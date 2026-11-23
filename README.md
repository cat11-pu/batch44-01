# GSB Bugfix Task
## 题面
配置管理平台统一推送 sudo 规则后，一个本应只读日志的账号拿到了 root shell。平台组复盘时发现规则文件是三个人分别维护的，合并顺序没人说得清。命令参数用了通配，vi 里执行 shell 直接提权；否定规则写在允许规则前面，最后匹配不生效；别名在定义前被引用，解析器直接跳过整条；User_Alias 带了 NOPASSWD，所有成员都免密；只限制了 runas 用户，runas 组却能切到 root；includedir 顺序不固定，重复用户规格合并结果每次不同；env_keep 放行 LD_PRELOAD，普通命令也能注入；SETENV 和 NOSETENV 标签继承错，环境变量泄漏；主机匹配用前缀，测试机规则覆盖生产；命令参数正则没有首尾锚定，多余参数也放行；Defaults 里一条 !authenticate 全局生效；单个文件语法错误导致整套规则按放行处理。sudoers_policy_parse.py 的 SudoersPolicyParse 负责别名展开、规则匹配和标签合并。规则必须按最后匹配生效，否定项优先，否则记 SUDO_RULE_ORDER；env_keep 不得放行 LD_PRELOAD、LD_LIBRARY_PATH、PYTHONPATH，命中记 SUDO_ENV_DANGEROUS；任何解析错误必须失败关闭，按 SUDO_PARSE_FATAL 拒绝全部提权。这台跳板机连着生产库，今晚必须把规则重新过一遍。

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
