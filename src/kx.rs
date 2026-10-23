//! TCP KeyExchange on 21116 (LEAPGATE.md §6.1, note 02 §6.2). Owned by the rendezvous module.
//!
//! The server half of the client's `key_exchange` (`rustdesk:src/common.rs`): the server offers a
//! signed ephemeral key in the first frame of every TCP connection; a client that wants the
//! stream encrypted answers with its own ephemeral key and a symmetric key sealed to ours.
//! Clients that do not want it skip the offer (`get_next_nonkeyexchange_msg`).

use hbb_common::{
    bail,
    protobuf::Message as _,
    rendezvous_proto::{KeyExchange, KxParams, RendezvousMessage},
    tcp::{Encrypt, KxTranscript, KX_PARAMS_DOMAIN, KX_VERSION_LATEST},
    ResultType,
};
use sodiumoxide::crypto::{box_, sign};

/// The ephemeral key pair offered on one connection, kept until the client answers.
pub(crate) struct Offer {
    /// As signed and sent: bit 255 set, which marks an offer with signed parameters.
    pk: [u8; box_::PUBLICKEYBYTES],
    sk: box_::SecretKey,
}

impl Offer {
    /// A version 1 offer signed with the server key; send the message as the connection's first frame.
    pub(crate) fn new(server_sk: &sign::SecretKey) -> ResultType<(Self, RendezvousMessage)> {
        let (pk, sk) = box_::gen_keypair();
        let mut pk = pk.0;
        // X25519 ignores bit 255, so clients from before version 1 use the key unchanged.
        pk[31] |= 0x80;
        let params = KxParams {
            pk: pk.to_vec().into(),
            version: KX_VERSION_LATEST,
            ..Default::default()
        };
        let mut payload = KX_PARAMS_DOMAIN.to_vec();
        payload.extend_from_slice(&params.write_to_bytes()?);
        let mut msg = RendezvousMessage::new();
        msg.set_key_exchange(KeyExchange {
            keys: vec![sign::sign(&pk, server_sk).into()],
            version: KX_VERSION_LATEST,
            signed_params: sign::sign(&payload, server_sk).into(),
            ..Default::default()
        });
        Ok((Self { pk, sk }, msg))
    }

    /// The client's answer (`keys` = its ephemeral public key and the sealed symmetric key):
    /// the cipher for both directions of the stream, with this side as the responder.
    pub(crate) fn accept(self, ex: &KeyExchange) -> ResultType<Encrypt> {
        if ex.keys.len() != 2 {
            bail!("Handshake failed: invalid key exchange message");
        }
        let key = Encrypt::decode(&ex.keys[1], &ex.keys[0], &self.sk)?;
        if ex.version == 0 {
            return Ok(Encrypt::new(key));
        }
        Encrypt::new_split(
            key,
            false,
            &KxTranscript {
                initiator_pk: &ex.keys[0],
                responder_pk: &self.pk,
                advertised: KX_VERSION_LATEST,
                picked: ex.version,
            },
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use hbb_common::{
        bytes::BytesMut,
        rendezvous_proto::rendezvous_message,
        tcp::kx_version_for,
    };
    use sodiumoxide::crypto::secretbox;

    /// What the client does with the offer (`key_exchange`): verify, pick a version, seal a key.
    /// Returns the client's answer and its cipher.
    pub(crate) fn client_answer(
        offer: &RendezvousMessage,
        server_pk: &sign::PublicKey,
        legacy: bool,
    ) -> (KeyExchange, Encrypt) {
        let Some(rendezvous_message::Union::KeyExchange(ex)) = &offer.union else {
            panic!("expected the server's key exchange");
        };
        assert_eq!(ex.keys.len(), 1);
        let their_pk = sign::verify(&ex.keys[0], server_pk).unwrap();
        let their_pk: [u8; 32] = their_pk.try_into().unwrap();
        let picked = if legacy {
            // Clients from before version 1 ignore the version and the signed parameters.
            0
        } else {
            assert!(their_pk[31] & 0x80 != 0);
            let signed = sign::verify(&ex.signed_params, server_pk).unwrap();
            let params =
                KxParams::parse_from_bytes(signed.strip_prefix(KX_PARAMS_DOMAIN).unwrap()).unwrap();
            assert_eq!(&params.pk[..], &their_pk[..]);
            assert_eq!(params.version, ex.version);
            kx_version_for(ex.version)
        };
        let (our_pk, our_sk) = box_::gen_keypair();
        let key = secretbox::gen_key();
        let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
        let sealed = box_::seal(&key.0, &nonce, &box_::PublicKey(their_pk), &our_sk);
        let enc = if picked == 0 {
            Encrypt::new(key)
        } else {
            Encrypt::new_split(
                key,
                true,
                &KxTranscript {
                    initiator_pk: &our_pk.0,
                    responder_pk: &their_pk,
                    advertised: ex.version,
                    picked,
                },
            )
            .unwrap()
        };
        let answer = KeyExchange {
            keys: vec![our_pk.0.to_vec().into(), sealed.into()],
            version: picked,
            ..Default::default()
        };
        (answer, enc)
    }

    #[test]
    fn both_versions_agree_in_both_directions() {
        let (server_pk, server_sk) = sign::gen_keypair();
        for legacy in [true, false] {
            let (offer, msg) = Offer::new(&server_sk).unwrap();
            let (answer, mut client) = client_answer(&msg, &server_pk, legacy);
            assert_eq!(answer.version, if legacy { 0 } else { 1 });
            let mut server = offer.accept(&answer).unwrap();
            for i in 0..3u8 {
                let mut up = BytesMut::from(&client.enc(&[i, 1, 2])[..]);
                server.dec(&mut up).unwrap();
                assert_eq!(&up[..], &[i, 1, 2]);
                let mut down = BytesMut::from(&server.enc(&[i, 3, 4])[..]);
                client.dec(&mut down).unwrap();
                assert_eq!(&down[..], &[i, 3, 4]);
            }
        }
    }

    #[test]
    fn version_1_keeps_the_directions_apart() {
        let (server_pk, server_sk) = sign::gen_keypair();
        let (offer, msg) = Offer::new(&server_sk).unwrap();
        let (answer, mut client) = client_answer(&msg, &server_pk, false);
        let mut server = offer.accept(&answer).unwrap();
        let mut up = BytesMut::from(&client.enc(b"ping")[..]);
        assert!(server.dec(&mut up).is_ok());
        // What the server sends (same counter value) does not open under its own receiving key.
        let mut reflected = BytesMut::from(&server.enc(b"ping")[..]);
        let mut server2 = server.clone();
        server2.2 = 0;
        assert!(server2.dec(&mut reflected).is_err());
    }

    #[test]
    fn rejects_a_malformed_answer() {
        let (server_pk, server_sk) = sign::gen_keypair();
        let (offer, msg) = Offer::new(&server_sk).unwrap();
        let (mut answer, _) = client_answer(&msg, &server_pk, false);
        answer.keys.truncate(1);
        assert!(offer.accept(&answer).is_err());
        // A sealed key that does not open with this offer's secret key.
        let (offer, _) = Offer::new(&server_sk).unwrap();
        let (answer, _) = client_answer(&msg, &server_pk, false);
        assert!(offer.accept(&answer).is_err());
    }
}
