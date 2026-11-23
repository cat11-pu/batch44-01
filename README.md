# GSB Bugfix Task
## 题面
视频站点边缘网关支持 HTTP/2 后，一次压测把后端线程池打空，监控显示大量流刚建就被重置。压测脚本每秒重置两万条流，后端连接池几分钟就见底。RST_STREAM 不计入并发流，攻击者可以无限建流再重置；HEADERS 之后立刻 RST，工作线程取消了但配额没释放；设置的 MAX_CONCURRENT_STREAMS 只发给客户端，自己不执行；过载时不发 GOAWAY，客户端继续在新连接上重试；CONTINUATION 空帧洪水把头部块一直挂起；优先级依赖成环，调度器原地打转；流编号复用不拒绝，旧流状态污染新流；PUSH_PROMISE 超过承诺上限也接受；SETTINGS_MAX_HEADER_LIST_SIZE 被忽略，超大头部吃内存；连接级窗口更新溢出后回绕，发送方直接卡死；没有按连接限制重置速率，单连接就能打满；h2c 升级绕过 TLS 策略，明文连接也能进后端。h2_reset_guard.py 的 H2ResetGuard 负责流生命周期、并发配额和过载保护。单连接重置速率超阈值必须关闭连接并回 ENHANCE_YOUR_CALM，记为 H2_RESET_FLOOD；正在重置的流必须继续占配额直到清理完成，超限报 H2_STREAM_LIMIT；CONTINUATION 超过头部块上限必须 RST_STREAM 并记 H2_HEADER_BLOCK_OVERSIZE。晚高峰马上到，网关组要求先顶住再谈根因。

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
