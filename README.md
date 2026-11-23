# GSB Bugfix Task
## 题面
企业出口的加密 DNS 网关上线后，内网域名开始出现在公共解析器的日志里，安全队顺着出口流量找上门。运维在旁路抓包，发现一部分应答根本没有对应的问题段。GET 请求的 base64url 缺填充直接报错，客户端全部回退明文 DNS；POST 不校验 content-type，把任意字节都当 DNS 报文解析；上游响应只比对报文编号，不校验问题段，伪造应答能写进缓存；0x20 大小写随机化没有核对，缓存投毒可以绕过；CNAME 目标跳出应答区域也照样缓存；缓存键没带 DO、CD 和 ECS，安全客户拿到不签名结果；NXDOMAIN 用 SOA 最小 TTL 之外的时长；上游 TC 置位后不重试 TCP，截断答案直接返回；请求 URL 里带 upstream 参数，网关替任何主机转发；并发同名查询各自打上游，后完成的覆盖先完成；内网后缀没拦截，内部主机名被送到外部递归；EDNS 填充缺失，查询长度直接暴露域名长度。doh_resolver_guard.py 的 DohResolverGuard 负责请求解析、上游选择和缓存。问题段不匹配的应答必须丢弃并记 DOH_QUESTION_MISMATCH；内网后缀不得离开网关，命中即报 DOH_INTERNAL_LEAK；缓存键必须包含 DO、CD、ECS，过期数据不得以 DOH_CACHE_STALE 返回。加密 DNS 是今年等保整改的硬指标，明天上午要交流量证明。

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
