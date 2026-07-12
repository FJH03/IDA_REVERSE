# ida_reverse

AI 辅助逆向工程工作区 —— 通过 MCP 协议桥接 VS Code Copilot 与 IDA Pro，实现自然语言驱动的二进制分析。

## 项目结构

```
ida_reverse/
├── .vscode/mcp.json          # VS Code MCP 配置（headless idalib 模式）
├── tools/idc/makesig.idc     # IDC 脚本：自动生成函数字节签名
├── workbench/                # 分析工作目录（IDB / 二进制样本）
└── ida-pro-mcp/              # [子模块] IDA Pro MCP 桥接服务器
```

## 环境要求

| 组件 | 说明 |
|------|------|
| IDA Pro 9.3+ | 需包含 idalib（headless 分析库） |
| Python 3.12 | |
| [uv](https://astral.sh/uv) | Python 包管理器 |
| VS Code + Copilot | AI 助手（支持 MCP 协议） |

## 快速开始

```powershell
# 1. 克隆仓库（含子模块）
git clone --recurse-submodules <repo-url>
cd ida_reverse

# 2. 激活 idalib（只需一次，将 <IDA_DIR> 替换为你的 IDA 安装目录）
uv run "<IDA_DIR>\idalib\python\py-activate-idalib.py"

# 3. 重启 VS Code，MCP 自动生效
```

## 使用方式

配置完成后，在 VS Code 中直接与 Copilot 对话即可驱动 IDA 分析：

> "打开 workbench/target.exe，列出所有导出函数"
> "反编译 main 函数，分析它的核心逻辑"
> "搜索所有对 CreateFileW 的交叉引用"

## 工具

### makesig.idc

IDA Pro IDC 脚本，从函数起始地址自动生成唯一的字节签名（用于 FLIRT / 特征匹配）。

**使用方法**：在 IDA 中光标定位到目标函数，运行脚本即可输出两种格式的签名。

**示例输出**：
```
Signature for sub_401000:
55 8B EC ? ? ? ? 83 EC 08
\x55\x8B\xEC\x2A\x2A\x2A\x2A\x83\xEC\x08
```

## 相关项目

- [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) — IDA Pro MCP Server 上游

## 许可

本仓库中的工具遵循各自原作者的许可协议。详细信息见各文件头注释。
