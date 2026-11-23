# GSB Bugfix Task
## 题面
运营商自动化平台用 NETCONF 候选库批量下发基站配置，一次失败提交后设备锁死，值班只能上站重启。会话断开后候选库锁不释放，后续任务全部超时；confirmed-commit 的超时没有计时器，配置要么不回滚要么半夜回滚；persist-id 被另一个会话直接复用，提交到了错误设备；NACM 默认放行，只读账号能改路由策略；edit-config 的 merge 语义把旧节点留在树里，删掉的配置又活了；rollback-on-error 没实现，前一半接口起来后一半失败；设备能力集里没有 candidate 也照发，直接报未知操作；两个会话同时编辑候选库，后提交的把前一个覆盖；startup 库在 commit 前被覆盖，重启后配置丢失；重连后会话编号复用，拿到上一任留下的锁；订阅通知漏掉 commit 事件，网管以为已经生效；XML 前缀不同就匹配不到节点，删除操作静默失败。netconf_candidate_guard.py 的 NetconfCandidateGuard 负责锁、候选库事务和权限判定。任一编辑失败必须整笔回滚，半套配置按 NETCONF_PARTIAL_APPLY 拒绝；confirmed-commit 超时必须自动回滚并释放锁，否则报 NETCONF_CONFIRM_TIMEOUT；NACM 的 deny 必须压过 allow，未知子树默认拒绝并记 NETCONF_NACM_DENIED。核心网割接窗口只有四十分钟，不能再靠人盯着回滚。

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
