# GSB Bugfix Task
## 题面
城域骨干新增一台 ISIS 路由器后，L2 区域开始反复泛洪，部分网段时通时断。监控上 LSP 数量忽高忽低，网管告警被刷得没人看，区域边界两台核心路由器的 CPU 已经打到八成。LSP 序列号回绕后旧 LSP 反而胜出，路由表回到上一版；remaining lifetime 被写成最大值后不停重泛洪；校验和为零的 LSP 也装进 LSDB；overload 位置位后仍被当作可经过节点，流量继续往新设备引；ATT 位被错误带进 L2，边缘设备默认路由指向黑洞；伪节点 LSP 编号撞车，两台设备互相覆盖；认证 TLV 长度为零也接受，HMAC 根本没算；分片零丢失但分片一先到，半个 LSP 被安装；CSNP 范围和实际摘要对不上，已清除的 LSP 被复活；purge 的剩余寿命不递减，墓碑永远清不掉；同一 LSP ID 来自两个系统，后到的直接覆盖；泛洪未收敛就启动 SPF，算出环路。isis_lsp_guard.py 的 IsisLspGuard 负责 LSP 接收、泛洪、LSDB 维护和序列号比较。序列号不大于现有值的 LSP 必须丢弃并记 ISIS_LSP_STALE；purge 状态必须保留到寿命归零，期间不得重新生成，否则记 ISIS_PURGE_RESURRECT；认证失败必须整包丢弃并记 ISIS_AUTH_FAIL，不能只告警。骨干一抖，下面几百个基站一起掉，值班现在连登录都排队。

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
