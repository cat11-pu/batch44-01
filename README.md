# GSB Bugfix Task
## 题面
高校漫游联盟的 RADIUS 代理最近对账对不上，同一节课的计费记录出现两遍，部分外校用户还能反复认证。Proxy-State 在转发时被丢掉，回包找不到原代理，请求一直超时；带 EAP 的 Access-Request 不验 Message-Authenticator，伪造请求也能过；Request Authenticator 复用不拦，抓包重放可以反复认证；重传的计费请求每次都新建会话，时长直接翻倍；同一 NAS 的 Acct-Session-Id 冲突时直接合并，两个用户串账；Stop 比 Start 先到也照单全收，负时长写进账单；User-Password 隐藏时共享密钥长度算错，跨域认证全失败；两个代理互相转发，没有跳数上限，请求绕圈；响应来源地址不校验，任意主机都能冒充上游；Class 属性跨会话回显，租户信息串用；计费队列满时静默丢掉 Interim，账单一整天缺失；NAS-Identifier 与源地址不一致也采信。radius_proxy_ledger.py 的 RadiusProxyLedger 负责代理路由、认证校验和计费去重。Message-Authenticator 缺失或错误必须回 RADIUS_BAD_AUTHENTICATOR；同一 Acct-Session-Id 加 NAS 的重复请求只能记一次，重复计费按 RADIUS_DUP_ACCOUNTING 丢弃；Proxy-State 必须原样带回，丢失时报 RADIUS_PROXY_STATE_LOST。漫游结算是按月分成，账差一天都解释不清。

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
