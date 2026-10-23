-- 路由第二级：选中中继两段的延迟（毫秒，未乘权重）。实测还是估计看 route_reason：
-- rtt 两段都是实测，rtt_a / rtt_b 只有 A / B 段是实测，geo* 两段都是估计；没有值为 NULL。
alter table conn_attempt add column route_a_ms real;
alter table conn_attempt add column route_b_ms real;
