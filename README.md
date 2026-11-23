# GSB Bugfix Task
## 题面
写字楼无线换成 WPA3-SAE 后，会议室终端频繁掉线，安全测试还抓到了降级握手。物业已经把会议室 AP 列为重点保障，厂商远程支持还要等明天。SAE Commit 的标量和元素不验曲线点，非法点也进计算；抗泛洪令牌不强制，攻击者用 Commit 洪水把 AP 的 CPU 打满；H2E 和 hunting-and-pecking 混用，同一密码两边算不出密钥；配置禁用了十九号群，握手却仍接受；Confirm 没有绑定 Commit，反射攻击可以冒充双方；管理帧保护没有强制，伪造 deauth 就能踢人；过渡模式接受 WPA2-TKIP，降级后密钥强度骤降；重关联后重放计数器清零，旧帧又能通过；漫游时 PMK 派生用错 BSSID，切换必断；信标保护没校验，伪造信标把终端引到假 AP；SAE 密码标识被忽略，多密码场景全部失败；同一 MAC 的并发握手互相覆盖状态。wpa3_sae_guard.py 里的 Wpa3SaeGuard 承担 SAE 握手、PMF、过渡模式和降级策略。非法 SAE 元素必须回 SAE_INVALID_ELEMENT 且不消耗后续计算；管理帧保护必须强制，未保护的 deauth 直接丢弃并记 SAE_PMF_REQUIRED；关闭过渡模式后任何 WPA2 降级都按 SAE_DOWNGRADE_BLOCKED 拦截，并记录发起者 MAC。办公楼两千多人靠这套无线办公，明天早会前要恢复。

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
