# GSB Bugfix Task
## 题面
资源服务器接入令牌自省后，离职员工的访问令牌在撤销一小时后还能调接口，安全运营追着问原因。授权服务器是集团统一维护的，我们只能改缓存层。自省结果缓存到令牌过期，撤销事件完全不失效；inactive 令牌在缓存里被当成 active 返回；缓存键只有令牌串，不区分租户和受众；未知令牌的负缓存让后来签发的同串令牌被拒；自省端点地址被重定向到外部主机，凭据跟着过去；本地可解析的 JWT 也全部打自省，流量翻十倍；撤销事件到达后缓存不删，窗口内继续放行；令牌 scope 变更后缓存还是旧权限；并发自省没有合并，一瞬间打崩授权服务器；响应里的 active 是字符串 false，被当成真值；缓存跨租户共享，A 的结论套到 B；自省请求走明文 HTTP 也接受。token_introspection_cache.py 的 TokenIntrospectionCache 负责缓存、撤销传播、负缓存策略和响应校验。已撤销令牌必须在传播时限内失效，超时按 INTROSPECT_REVOKED_STALE 告警并拒绝；active 必须是严格布尔值，字符串 false 按 INTROSPECT_BAD_RESPONSE 处理；缓存键必须包含租户、受众和令牌类型，冲突报 INTROSPECT_CACHE_COLLISION，并输出缓存命中与失效计数。风控要求撤销后十秒内生效，现在的实现差了两个数量级，缓存层也没有暴露失效原因。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：身份认证
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
