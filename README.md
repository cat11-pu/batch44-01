# GSB Bugfix Task
## 题面
水务公司的 LoRaWAN 抄表网最近出现重复入网，同一块表在网关上挂了两条会话。网关日志里 JoinRequest 的计数和实际入网数对不上。DevNonce 只放内存，网关重启后旧入网请求又能通过；JoinNonce 不按 JoinEUI 单调比较，回退的接受帧也生效；Join-Accept 的 MIC 用错根密钥，部分表永远入不了网；DevAddr 池重叠，两块表拿到同一个地址；未知 JoinEUI 被转到默认 Join Server，出现跨租户入网；RX1 和 RX2 的延迟漂移没补偿，接受帧总错过窗口；重复 JoinRequest 每次新建会话，计费翻倍；会话密钥没有按 LoRaWAN 版本派生，老表解密失败；CFList 信道计划和网关配置不一致也接受；入网前就下发 ADR 参数，终端直接失联；Rejoin-request 类型二没有处理，重入网被当新设备；根密钥轮换后旧表全部无法入网。lorawan_join_guard.py 的 LorawanJoinGuard 负责入网校验、地址分配和会话派生。重复 DevNonce 必须拒绝并记 JOIN_DEV_NONCE_REPLAY；同一 JoinEUI 的 JoinNonce 必须严格递增，否则报 JOIN_NONCE_ROLLBACK；MIC 校验失败必须静默丢弃并计数，记为 JOIN_MIC_INVALID，不能回错误帧。几万块水表靠这个网抄数，营业厅已经接到欠费误报。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：网络与通信安全
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
