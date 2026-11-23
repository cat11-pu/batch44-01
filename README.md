# GSB Bugfix Task
## 题面
园区 DHCP 中继换新版本后，宿舍区频繁拿到错误网关，部分终端一天掉线十几次。中继日志里只能看到转发计数，看不出是哪台服务器回的包。客户端自带的 Option 82 被原样转发，服务器按伪造的电路号分配地址；giaddr 直接取报文里的值，中继地址被客户端指定；任意服务器回的 OFFER 都转发，私接路由器也能给整层楼发地址；Option 82 没有回显，服务器无法按接入口做策略；DISCOVER 广播没有限速，一个坏网卡把中继 CPU 打满；跳数超过十六的报文继续转发，两个中继形成环；续租的单播包被送到旧 VLAN，租约到期后直接断网；Option 82 超过 255 字节被静默截断，端口信息丢失；NAK 用广播发给整个网段，无关终端也被踢下线；广播标志和 secs 字段组合异常时直接丢弃，正常开机拿不到地址；两台服务器同时应答，中继全转发，终端随机选一个；option overload 时 file 和 sname 字段解析错位。dhcp_relay_guard.py 的 DhcpRelayGuard 负责中继转发、选项处理和服务器信任。客户端带来的 Option 82 必须剥掉并重写，命中按 DHCP_RELAY_OPTION_SPOOF 丢弃；只接受配置内服务器的应答，来源不符报 DHCP_RELAY_UNTRUSTED_SERVER；跳数超过十六必须丢弃并记 DHCP_RELAY_LOOP。宿舍网一断，报修电话能把值班室打爆。

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
