# GSB Bugfix Task
## 题面
集团用 SCIM 给 SaaS 同步账号，离职员工的权限过了两周还在，合规抽查直接点名。同步任务每天凌晨跑一次，失败只发一封没人看的邮件。PATCH 的 remove 操作对多值组属性不生效，人走了组还在；userName 过滤区分大小写，改个大小写就新建账号；分页 startIndex 从零算起，每页都漏掉第一个人；DELETE 返回成功但只是软删，令牌和会话都没撤；PUT 覆盖资源时把不可变的 id 一起换掉，后续更新全失败；组的 externalId 没解析，同步出重复组；批量接口部分失败仍回 200，失败项没人重试；ETag 不校验，两个管理员并发改，后写覆盖先写；SCIM 令牌跨租户共用，A 公司能写 B 公司用户；inactive 用户仍能通过上游 SSO 登录；改用户名被当成新用户，旧账号成了孤儿；扩展 schema 的未知 URN 被静默丢弃。scim_provision_guard.py 的 ScimProvisionGuard 负责资源同步、幂等和撤权。停用用户必须原子撤销会话、组关系和下游权限，残缺时记 SCIM_DEPROVISION_INCOMPLETE；同一租户重复 userName 必须回 409 并记 SCIM_DUPLICATE_USER；跨租户令牌必须拒绝并记 SCIM_TENANT_MISMATCH。审计清单里还挂着三个离职账号，HR 每天来问进度。

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
