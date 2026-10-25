# aimili-vpngate-plus

**面向 Linux VPS 的 VPNGate 节点管理与 HTTP / HTTPS / SOCKS5 代理网关（改动版）**

**简体中文** · [English](README_EN.md)

> **与原项目的关系与出处声明**：本项目基于 [OpenMili/aimili-vpngate](https://github.com/OpenMili/aimili-vpngate) 修改，保留原项目版权与许可证声明；新增功能（保留池、收藏分层、iplark 评分接入点、远程接入模式）为本项目的改动内容，与原项目无关。保留策略与切换上限的设计参考了 [MasterAlanLab/free-proxy](https://github.com/MasterAlanLab/free-proxy)。改动清单见 [IMPLEMENTATION_NOTES.md](IMPLEMENTATION_NOTES.md)。

| 项目 | 默认值或支持范围 |
| --- | --- |
| Web 管理后台 | TCP `8787` + 独立安全路径 + 账号密码 |
| 本机代理 | `127.0.0.1:7928`，支持 HTTP、HTTPS `CONNECT` 和 SOCKS5 |
| 源码部署 | x64、x86、ARM64、ARM32 Linux |
| 更新通道 | 本仓库 `main` 分支（`ml update` 从本仓库更新，不再指向上游） |

## 新增功能（第一阶段）

- **保留池 + 14 天宽限期**：节点从 VPNGate 列表消失后不再立即删除，进入观察期保留 14 天，期间继续探测；宽限期满先归档再删除。正在用的节点刷新时保留；拉取失败时不改写列表。
- **收藏豁免**：收藏节点永不因“消失”被删（与国家无关）；任何国家的节点都可收藏，方便以后切到该国时直接用。
- **收藏优先分层选择**：选择时先按目标国家/地区过滤，过滤出的集合内收藏在前、非收藏在后，池内按综合分排。综合分 = 0.3 × 延迟 + 0.3 × 可用性 + 0.4 × iplark 评分（第一阶段先接延迟与可用性，iplark 为真实接入点，第三阶段写评分后自动生效）。
- **IP 类型菜单**：全部 / 住宅 / 机房 / 未知。
- **面板新增**：保留池视图按钮、观察期标识、iplark 评分列（第一阶段显示“—”）、置灰的“查评分”按钮（第三阶段接入）；新增 `GET /api/retained`、`POST /api/favorite` 接口。
- **远程接入**：默认关闭；开启后唯一路径是 SSH 隧道 + IP 白名单，不直接开放代理端口。

后续阶段状态：iplark 查分（第三阶段）与隧道内延迟测量（第四阶段）尚未实现，仅留接入点与占位。

## 快速安装

使用 `root` 用户在受支持的 Linux VPS 上执行：

```
bash <(curl -Ls https://raw.githubusercontent.com/liulangdegezi/aimili-vpngate-plus/main/install.sh)
```

安装完成后，终端会显示 Web 后台完整地址、随机安全路径、登录账号和密码。输入 `ml` 可打开管理菜单。

无人值守安装可显式跳过首次参数询问，并自动生成安全路径和登录凭据：

```
AIMILIVPN_NONINTERACTIVE=1 bash <(curl -Ls https://raw.githubusercontent.com/liulangdegezi/aimili-vpngate-plus/main/install.sh)
```

安装前请在 VPS 控制面板启用 TUN/TAP，并确认 `/dev/net/tun` 存在。Web 默认使用 TCP `8787`，安全组建议只允许自己的 IP 访问。

## 完整安装

### 运行条件

- 操作系统：Ubuntu、Debian、Alpine、CentOS、RHEL、Rocky Linux、AlmaLinux、Fedora、Oracle Linux 或 Amazon Linux。
- 权限与组件：`root`、OpenVPN、iptables、策略路由和 TUN/TAP。
- Windows 与 macOS 可作为代理客户端，但不能直接运行完整网关；Docker Desktop 也不等同于具备宿主机 TUN 能力的 Linux VPS。

### 方式一：一键源码安装

```
bash <(curl -Ls https://raw.githubusercontent.com/liulangdegezi/aimili-vpngate-plus/main/install.sh)
```

安装器会部署到 `/opt/aimilivpn` 并注册系统服务。常用命令：

```
ml                 # 打开管理菜单
ml status          # 查看状态、Web 地址和账号
ml logs            # 查看实时日志
ml restart         # 重启服务
ml password        # 重设 Web 账号密码
ml update          # 从本仓库 main 分支更新
ml uninstall       # 卸载
```

需要先审查脚本时：

```
git clone --branch main --single-branch https://github.com/liulangdegezi/aimili-vpngate-plus.git
cd aimili-vpngate-plus
sudo bash install.sh
```

### Docker 方式

本改动版暂不发布 Docker 镜像，请使用源码安装。`compose.yaml` 里的镜像地址尚未发布，直接 `docker compose up` 会拉取失败。

## 连接与使用

### 1. 登录 Web 后台

源码安装完成后，使用终端输出的地址访问：

```
http://VPS_IP:8787/随机安全路径/
```

忘记地址时执行 `ml status`；需要重设账号密码时执行 `ml password`。

### 2. 获取并连接节点

1. 登录后台，等待首次节点加载完成，或点击“更新节点”。
2. 按国家筛选节点，并使用“测试”检查本机实测延迟与可用性。
3. 点击目标节点的“切换”；目标预检失败时，程序会尽量保留当前可用连接。
4. 根据需要选择智能自动、固定国家或固定 IP 模式。
5. 在状态区域确认 VPN 已连接，并核对当前出口 IP。

### 3. 在 VPS 本机使用代理

HTTP、HTTPS 网站代理和 SOCKS5 共用 `127.0.0.1:7928`。HTTPS 网站通过 HTTP 代理的 `CONNECT` 方法访问，代理地址仍填写 `http://127.0.0.1:7928`。

```
# HTTP / HTTPS
curl -x http://127.0.0.1:7928 https://api.ipify.org

# SOCKS5，并通过代理解析域名
curl --proxy socks5h://127.0.0.1:7928 https://api.ipify.org
```

### 4. 从电脑或其他设备连接

代理默认只监听 VPS 回环地址。本改动版的唯一远程路径是 SSH 隧道 + IP 白名单，不要直接暴露代理端口：

```
ssh -N \
  -L 8787:127.0.0.1:8787 \
  -L 7928:127.0.0.1:7928 \
  root@VPS_IP
```

隧道建立后：

- Web：`http://127.0.0.1:8787/随机安全路径/`
- HTTP / HTTPS 代理：`127.0.0.1:7928`
- SOCKS5 代理：`127.0.0.1:7928`，支持时选择远程 DNS 或 `socks5h`

`7928` 默认没有面向公网的用户认证。请勿在没有防火墙、来源 IP 限制或其他可靠访问控制的情况下将其直接开放到公网。

## 配置项（第一阶段）

| 配置 | 取值 |
| --- | --- |
| 观察期宽限期 | 14 天 |
| 失败阈值 | TCP 3 次·24 小时未见 / 非 TCP 5 次·72 小时未见 |
| 存活清理间隔 | 12 小时 |
| 切换候选上限 | 3 个 |
| 失败黑名单 | 30 分钟 |
| 防抖动冷却 | 2 小时（刚切走的节点 2 小时内不回切，手动切换不受限） |
| 保留池上限 | 500 条（归档文件上限 1000 条） |
| 评分权重 | 延迟 0.3 / 可用性 0.3 / iplark 0.4 |
| 评分复查间隔 | 8 小时（第三阶段） |

节点列表镜像备用来源仍使用上游 GitHub Pages 镜像（仅作节点列表备用来源），可保留或自建后替换。

## 新功能按钮说明

- 节点行星标：收藏 / 取消收藏（全局属性，任何国家节点都可收藏）。
- 工具栏“保留池”按钮：只显示观察期节点，与收藏视图互斥。
- 节点行“观察期”标识：该节点已从 VPNGate 列表消失，正在宽限期内。
- iplark 评分列：第一阶段显示“—”，第三阶段写评分后自动显示。
- “查评分”按钮：第一阶段置灰，第三阶段接入。
- 筛选菜单：国家/地区、IP 类型（含未知类型）、仅收藏。

## 使用范围与法律声明

下载、部署或使用本项目即表示您应自行确认用途符合所在地法律、VPS 所在地法律、网络服务商条款及 VPNGate 的相关规则。本项目仅用于合法的网络研究、教育、开发测试、隐私保护和经授权的网络访问，不得用于绕过依法实施的监管措施、未授权访问、攻击、扫描、垃圾信息、欺诈、侵权或其他违法活动。VPNGate 节点由第三方志愿者运营，本项目不拥有、不控制也不审核这些节点，无法保证其稳定性、速度、安全性、隐私政策或日志行为。请勿通过不可信节点传输账号密码、金融信息、商业机密等敏感数据。软件按“现状”提供，不对可用性、适销性、特定用途适用性或间接损失作出保证。如无法确认当地法律或服务商是否允许，请停止部署和使用。

## 许可证

GPL-3.0，见 [LICENSE](LICENSE)。原项目版权声明已保留。
