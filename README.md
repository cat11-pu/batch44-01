# GSB Bugfix Task
## 题面
运维堡垒机收紧策略后，外包人员仍通过端口转发摸到了数据库网段，安全审计直接通报。堡垒机日志只记录了登录成功，转发通道一条都没留痕。配置关了 TCP 转发，Unix 域套接字转发仍然可用；代理转发套接字权限过宽，同机其他会话能直接借用；X11 转发不校验显示号，也没有 xauth 凭证；PermitOpen 写了通配主机，等于全部放开；ProxyJump 链路不校验目标，内网主机被逐跳穿透；streamlocal 转发绕过路径白名单；ForceCommand 对 sftp 子系统不生效，直接拿到 shell；AuthorizedKeysCommand 返回的选项没解析，限制全部失效；动态 SOCKS 转发在策略禁止时仍能建立；单用户转发连接数没有上限，端口被耗尽；认证未完成就允许打开 forwarded-tcpip 通道；主机密钥算法降级到 ssh-rsa 也接受。ssh_forward_guard.py 的 SshForwardGuard 负责通道审批、转发策略和会话隔离。不在白名单的转发请求必须在开通道前拒绝并记 SSH_FORWARD_DENIED；代理套接字必须按会话隔离且断开即删，泄漏报 SSH_AGENT_LEAK；sftp 和 exec 必须同样受 ForceCommand 约束，绕过按 SSH_FORCECOMMAND_BYPASS 拒绝。外包合同里写明只许看日志，现在连库都能连，必须今晚堵上。

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
