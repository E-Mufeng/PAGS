# PAGS

PAGS 是面向 Codex 等本地编码代理的经验检索与候选采集组件。
此仓库公开可复用的核心源码，而不是个人经验库或整机部署备份。

## 包含什么

- Git 版本化的只读经验门禁与 ripgrep 检索。
- `search_experience` / `read_experience` MCP 接口。
- 原生会话/轮次绑定的候选采集与去重，候选保持 untrusted。
- 候选与已批准经验分离、跨项目共享单独审批。
- 可选的项目学习卡读取；用户没有实际回答时不标记掌握。

## 版本状态

这是现有本地实现的**首次公开源码快照**，不是声称今天新增了全部功能。
整体产品仍处于部分验收状态：全会话覆盖、恢复/迁移、成本收益及完整生命周期
尚未得到全面验证。公开副本只做源码语法、依赖文件完整性和隐私检查，
没有重新运行生产验收、历史导入或任何模型试验。

## 环境

- Windows；Python 3.11+、Node.js、Git、ripgrep（`rg`）可从 PATH 调用。
- `python -m pip install -r requirements.txt` 安装 Python 依赖。
- 固定的 myagentmemory 0.6.1 核心随 `vendor/` 提供，保留上游 MIT 许可证。
- 需要时用 `PAGS_NODE` / `PAGS_RG` 指定程序；`CODEX_HOME` 指定本机 Codex 数据目录。

## 本地初始化

```powershell
python examples/init_private_workspace.py
python source/pags_gate.py --vault knowledge --project-id example-project Git
python source/pags_mcp.py --auto-project
python projects/learning-console/learning_cli.py --input examples/cards.json --json
```

初始化只创建本仓内被忽略的空经验库和项目登记，不写全局 Codex 配置、Hook、PATH
或其他项目，也不调用模型。空库返回无命中是正常结果；没有附赠任何私人经验。
MCP 接入需由使用者在自己的客户端显式配置，命令启动不代表已经全局接入。

`PROJECTS.json` 用于登记本机路径，首次生成内容为空。经验与证据必须经过相应审查
再进入 approved 引用；路由目标列表本身不代表允许跨项目披露。
Stop 采集等能力是待用户显式接入的源码接口，不会因克隆仓库而自动启用。

## 公开范围与隐私

没有上传原始聊天、真实会话标识、个人经验/学习记录、知识库、数据库、运行配置、
日志、生产证据、备份、旧 Git 历史或可执行文件。示例是空白合成模板。
本机绝对路径仅在发布副本中改为环境变量或仓库相对位置，原项目保持不变。
自动检查不等于识别所有业务隐私；继续更新时仍需审阅公开差异。

## 许可证

原创部分采用 MIT；第三方部分见 `THIRD_PARTY_NOTICES.md` 和随附许可证。
