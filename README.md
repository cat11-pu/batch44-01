# GSB Bugfix Task
## 题面
集团 TLS 网关做证书状态装订，客户端最近开始随机报证书已吊销，业务侧却查不到任何吊销记录。装订缓存过了 nextUpdate 仍继续下发，客户端拿到过期响应直接拒绝握手；未知序列号返回 good，而不是让客户端自己再去查；客户端带 nonce 的请求没有回显，严格校验的客户端全部失败；委托响应者证书缺少 OCSP 签名用途也照样采信；响应先解码再重编码，tbsResponseData 字节一变验签必挂；producedAt 在未来十分钟的响应也接受；thisUpdate 晚于 nextUpdate 的记录没有拒绝；上游不可达时回退到过期 CRL，还把 CRL 里的吊销当成有效；同一序列号在不同签发者下共用缓存，A 家的 good 盖住 B 家的 revoked；响应者地址是明文 HTTP，跳转还跟着走；并发刷新时半份 DER 被读走，客户端解析直接失败；装订响应挂到了链上另一张证书，主机名对不上。ocsp_staple_responder.py 的 OcspStapleResponder 负责缓存、刷新和装订绑定。吊销序列号只能返回 revoked 并记 OCSP_REVOKED，绝不能出现 good；响应超出 thisUpdate/nextUpdate 窗口必须停止装订并报 OCSP_STALE；委托证书必须能链到签发者且带 OCSPSigning 用途，否则按 OCSP_DELEGATE_INVALID 拒绝。网关每分钟几万次握手，运维只给了今晚一个窗口。

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
