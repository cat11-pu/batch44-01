# GSB Bugfix Task
## 题面
Kubernetes 节点开放特权调试 Pod 后，一个挂载操作把宿主机的 /etc 换成了容器里的版本，节点直接失联。切换根目录前没有把共享传播改成私有，容器挂载冒到宿主；特权容器可以把新文件系统挂到 /etc 之上；解析 mountinfo 忽略可选字段，匹配到了错误的挂载点；绑定 /proc/self/fd 的链接绕过路径检查；递归绑定把宿主机所有挂载一起带进容器；重新挂载时丢掉 nosuid、nodev 和 noexec；检查与卸载之间路径被替换，卸载打到了别的目录；新挂载接口没有纳入系统调用过滤，绕过旧检查；idmapped 挂载绕过 uid 校验，容器里能写宿主文件；宿主机传播事件进入容器，容器里看到宿主的新挂载；覆盖挂载遮住安全代理的可执行文件；挂载命名空间文件描述符被子进程继承。mount_propagation_warden.py 的 MountPropagationWarden 负责挂载审批、传播隔离和保护路径。未列入白名单的 hostPath 必须带 nosuid、nodev、noexec 且传播为 private，否则报 MOUNT_UNSAFE_FLAGS；容器内任何挂载事件都不得传播到宿主，命中记 MOUNT_PROPAGATION_LEAK；覆盖受保护路径必须拒绝，错误码为 MOUNT_PROTECTED_PATH。这台节点承载在线业务，失联一分钟就是一片 502。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：系统安全
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
