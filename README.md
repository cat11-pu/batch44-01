# GSB Bugfix Task
## 题面
镜像构建服务用 overlayfs 做分层缓存后，一个低权限构建任务把带 setuid 的文件带进了运行环境。从下层复制上来的文件保留了 setuid 位；文件能力扩展属性原样复制，普通程序拿到网络管理能力；metacopy 模式下只复制元数据，权限改了但数据仍指向下层；白名单设备号不校验，whiteout 能遮住宿主机文件；redirect 扩展属性指向 upperdir 之外，读写落到宿主路径；上层和下层在同一文件系统时，硬链接直接指到下层文件；用户扩展属性模式允许非特权进程注入 redirect；设备节点也能复制上来，容器里出现宿主设备；O_DIRECT 写入绕过复制检查，下层文件被直接改；重命名下层目录后 redirect 产生别名，两处看到不同内容；多层 lower 同名路径合并顺序错，旧文件盖住新文件；挂载选项没有禁止执行和设备，逃逸后可以直接运行。overlayfs_copyup_policy.py 的 OverlayfsCopyupPolicy 负责复制检查、元数据清理和挂载策略。复制时必须剥掉 setuid、setgid 和文件能力，命中记 OVL_UNSAFE_METADATA；whiteout 和 redirect 目标越出 upperdir 必须拒绝，错误码为 OVL_REDIRECT_ESCAPE；设备节点和指向下层的硬链接一律拒绝，报 OVL_SPECIAL_FILE。构建集群每天出几千个镜像，谁也不想再回滚整批产物。

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
