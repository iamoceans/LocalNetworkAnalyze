# 局域网流量分析器 (Local Network Analyzer)

基于 Python 的桌面应用，用于分析、监控本地网络流量。支持实时抓包、协议解析、异常检测、局域网扫描与数据导出，并提供中英双语界面与现代化 GUI。

## 功能概览

| 功能 | 说明 |
|------|------|
| **实时流量监控** | 基于 Scapy 抓包，实时解析并展示网络数据包 |
| **协议解析** | 解析 HTTP、DNS、TCP、UDP 等协议 |
| **局域网扫描** | ARP 扫描、ICMP 扫描、端口扫描，发现网内设备与开放端口 |
| **异常检测** | 端口扫描检测、DDoS 检测、流量异常检测，并产生安全告警 |
| **流量分析** | 流量统计、带宽监控、连接跟踪、网站访问统计（Top 网站） |
| **数据导出** | 导出为 CSV、JSON 或 PCAP |
| **图形界面** | CustomTkinter 界面，仪表盘、抓包、扫描、分析、告警等面板 |
| **多语言** | 界面支持中文、英文（`--language zh` / `en`） |
| **主题** | 浅色 / 深色 / 跟随系统，支持 lavender_glass 等主题 |

## 环境要求

- **Python**：3.8 及以上
- **权限**：抓包需管理员/root 权限
- **Windows**：需安装 [Npcap](https://npcap.com/)（并勾选「WinPcap API 兼容模式」），详见 [INSTALL.md](INSTALL.md)

## 安装

1. **克隆仓库**：
```bash
git clone https://github.com/your-org/LocalNetworkAnalyze.git
cd LocalNetworkAnalyze
```

2. **创建虚拟环境（推荐）**：
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate
```

3. **安装依赖**：
```bash
pip install -r requirements.txt
```

主要依赖：`scapy`、`customtkinter`、`matplotlib`、`sqlalchemy`。

开发环境可额外安装：
```bash
pip install -r requirements-dev.txt
```

## 使用方式

### 启动图形界面（推荐）

```bash
# 方式一：启动脚本（Windows 可双击 start.bat，会自动检测 venv 并提示管理员权限）
python run.py

# 方式二：直接运行主模块
python -m src.main
```

**Windows**：若需抓包，请以管理员身份运行（右键「以管理员身份运行」）。  
**Linux/macOS**：可能需要 `sudo python -m src.main` 或 `sudo ./start.sh`。

### 常用命令行参数

```bash
# 指定网卡
python -m src.main --interface eth0

# 指定 BPF 过滤
python -m src.main --filter "tcp port 80"

# 指定数据库路径
python -m src.main --database /path/to/database.db

# 界面语言：中文 / 英文
python -m src.main --language zh
python -m src.main --language en

# 主题：light / dark / system
python -m src.main --theme dark

# 无界面模式（仅抓包，指定时长秒数）
python -m src.main --headless --interface eth0 --duration 60

# 仅执行扫描后退出
python -m src.main --scan arp --target 192.168.1.0/24
python -m src.main --scan icmp --target 192.168.1.0/24
python -m src.main --scan port --target 192.168.1.1 --ports 80,443,8080

# 调试日志
python -m src.main --debug

# 仅初始化数据库
python -m src.main --init-db
```

更多示例见运行时的 `python -m src.main --help`。

## 项目结构

```
LocalNetworkAnalyze/
├── src/
│   ├── core/           # 核心：配置、日志、异常、多语言
│   ├── capture/        # 抓包（Scapy 等）
│   ├── scan/           # 扫描：ARP / ICMP / 端口
│   ├── protocol/       # 协议解析：HTTP、DNS、TCP/UDP
│   ├── analysis/       # 分析：流量统计、带宽、连接跟踪、网站统计
│   ├── detection/      # 异常检测：端口扫描、DDoS、异常检测
│   ├── storage/        # 存储：数据库、导出 CSV/JSON
│   ├── gui/            # 图形界面与主题
│   └── utils/          # 工具与常量
├── tests/              # 单元测试与集成测试
├── data/               # 数据库、抓包与导出目录
├── logs/               # 应用日志
├── run.py              # 便捷启动入口
├── start.bat / start.sh # 一键启动脚本
├── INSTALL.md          # 安装与故障排除（含 Npcap）
└── QUICKSTART.md       # 快速上手
```

## 配置说明

- **配置文件**：可通过 `--config path/to/config.json` 加载 JSON 配置。
- **环境变量**（可选）：如 `LNA_INTERFACE`、`LNA_LOG_LEVEL`、`LNA_DB_PATH`、`LNA_THEME` 等，用于覆盖默认配置。

配置示例（节选）：

```json
{
  "capture": {
    "interface": "",
    "filter": "",
    "buffer_size": 1000
  },
  "gui": {
    "theme": "light",
    "language": "zh"
  },
  "log": {
    "level": "INFO",
    "path": "logs/app.log"
  }
}
```

## 界面面板说明

| 面板 | 作用 |
|------|------|
| **仪表盘** | 实时流量统计、带宽、协议分布、Top 连接/网站 |
| **抓包** | 选择网卡、BPF 过滤、开始/停止抓包、包列表 |
| **扫描** | 局域网发现（ARP/ICMP）、端口扫描 |
| **分析** | 查询、筛选、分析已抓取的流量 |
| **告警** | 查看与管理异常检测产生的安全告警 |

## 开发与测试

```bash
# 运行测试
pytest

# 带覆盖率
pytest --cov=src --cov-report=html

# 仅单元测试
pytest tests/unit/ -v
```

代码风格与质量可参考项目内约定（如 Black、Ruff、mypy 等）。

## 架构与设计

- **不可变配置**：配置使用 frozen dataclass
- **模块化**：抓包、分析、检测、存储、GUI 分层清晰
- **依赖注入**：组件通过构造函数注入依赖
- **仓储模式**：数据访问通过 Repository 抽象

## 安全与合规

- 抓包需要管理员/root 权限，仅在您拥有或获授权的网络上使用。
- 默认不存储敏感载荷，请遵守当地法律法规。

## 故障排除

| 现象 | 处理 |
|------|------|
| 抓包报错「权限不足」 | Windows：以管理员运行；Linux/macOS：使用 `sudo` |
| Npcap 相关错误（Windows） | 安装 Npcap 并勾选「WinPcap API 兼容模式」，详见 [INSTALL.md](INSTALL.md) |
| 找不到网卡 | 检查 `ipconfig`/`ip link`/`ifconfig`，在配置或界面中选择正确网卡 |
| CPU 占用高 | 适当减小抓包缓冲、使用 BPF 过滤、或关闭部分实时图表 |

更多问题可查看 `logs/app.log`，或使用 `--debug` 运行。

## 致谢与参考

- [Scapy](https://scapy.net/) — 数据包处理
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter) — 现代 GUI
- [Matplotlib](https://matplotlib.org/) — 图表展示
- [Npcap](https://npcap.com/) — Windows 抓包驱动

## 许可证

MIT License，详见 [LICENSE](LICENSE) 文件。

## 贡献

欢迎提交 Issue 与 Pull Request：Fork 后创建分支、补充测试、通过检查后提 PR 即可。
