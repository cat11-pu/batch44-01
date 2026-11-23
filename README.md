# GSB Bugfix Task
## 题面
容器运行时启用用户命名空间后，一个普通容器里的 root 读到了宿主机 root 拥有的文件。节点上同时跑着系统组件和租户容器，映射一错就是整机权限外溢。uid_map 允许重叠区间，两个容器映射到同一个宿主用户；写 gid_map 前没有关闭 setgroups，容器里的进程可以借此提权；映射条目超过页数限制，后半段被截断但返回成功；newuidmap 的 setuid 路径可被环境变量替换；idmapped 挂载把宿主 root 映射成容器 root；未映射的 uid 静默落到 overflow，文件属主变成 nobody；嵌套用户命名空间又映射回父命名空间的 root；策略禁止普通用户创建命名空间，内核开关却还开着；创建命名空间时保留了有效能力集；映射范围长度为零也接受，后续写入全失败；并发创建复用同一份映射，容器互相串身份；容器内新建的文件在宿主上归到了真实用户。userns_idmap_audit.py 的 UsernsIdmapAudit 负责映射校验、能力清理和挂载检查。重叠或不连续的 uid/gid 映射一律拒绝，错误码记为 USERNS_IDMAP_OVERLAP；容器 root 绝不能映射到宿主 uid 零，命中即报 USERNS_HOST_ROOT；gid_map 写入前必须确认 setgroups 已拒绝，否则按 USERNS_SETGROUPS 失败。多租户节点上跑着外部客户的镜像，这个洞不能再留到明天。

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
