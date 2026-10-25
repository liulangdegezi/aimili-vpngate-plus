# 第一阶段实施笔记（保留池 + 收藏分层）

> 基于上游 OpenMili/aimili-vpngate（commit 2cd7dc5）修改，仅实现整合方案的第一阶段。
> 本文件随改动版仓库走，部署时一并发布（说明改动来源与范围）。

## 一、改动范围（只改 `vpngate_manager.py` 一个文件）

`git diff --stat`：`vpngate_manager.py +444 / -13`。其余文件（包括 `install.sh`、
`proxy_server.py`、`vpn_utils.py`）一律未动；未创建 GitHub 仓库，未推送任何代码，
远端仍指向上游。

## 二、改了什么（按方案对应关系）

### 1. 保留池（方案 §三）

- **刷新不再“消失即删”**（`maintain_valid_nodes` 合并段）：成功刷新后，不在新列表里
  的非活动节点不再被丢弃，改为进入 `observing` 状态；只有宽限期满（14 天）仍未
  出现时，才先归档再删除。正在用的活动节点刷新时保留（原有行为）；拉取失败时
  不改写列表（原有行为）。
- **观察期节点继续留在 `nodes.json` 里**，而不是移到独立文件——这样现有的周期探测
  循环会继续探测它们（“宽限期内继续探测”），无需另起一套探测逻辑。节点记录新增
  字段：`retention_status`（normal/observing）、`last_seen_at`（最后一次出现在快照
  的时间）、`source_present`（是否在最新快照中）、`consecutive_failures`（连续失败
  次数）、`last_success_at`、`iplark_score`（第三阶段接入点，见下）。
- **收藏豁免**：收藏节点永不因“消失”被删（与国家无关）；宽限期满的判断跳过收藏节点。
- **归档**：删除前写入 `retained_archive.json`（节点 id、国家、IP、端口、协议、
  IP 类型、连接配置、最后可见/最后成功时间、归档时间、删除原因），归档文件上限
  1000 条。四个删除路径全部先归档：宽限期满、保留池超限、节点列表 1000 条截断、
  存活清理。
- **容量控制**：观察期节点超过 500 条时，按最后可见时间最久先归档淘汰；活动 /
  收藏 / 正常节点不受该上限影响。
- **存活清理**（`sweep_retained_nodes`，每 12 小时最多跑一次，时间戳记在 state）：
  仅删除同时满足“失败次数 + 陈旧度”双门槛的观察期节点——TCP 节点失败 ≥3 次且
  24 小时未见，非 TCP 节点连续失败 ≥5 次且 72 小时未见；活动、收藏、黑名单、
  固定节点一律不参与。

### 2. 收藏（方案 §一.2、§三.3）

- **存储复用原项目现有字段**：原项目已有 `favorite_node_ids`（存放在 `ui_auth.json`）
  及 `/api/toggle_favorite` 接口和面板收藏星标、收藏视图——这是最自然的存储，
  因此没有另建 `favorites.json`，避免出现两个收藏数据源。
- **新增 `POST /api/favorite`**：与 `/api/toggle_favorite` 操作同一存储（开关语义），
  按方案命名，并额外返回 `is_favorite`；原有接口保持不动，面板现有收藏模式直接
  接在同一存储上，无需改接。
- 收藏是全局属性：任何国家的节点都可收藏，不受当前目标国家限制。

### 3. 选择（方案 §四.1、§四.2、§四.4）

- 新增 `rank_selection_candidates()`，供 `auto_switch_node()` 使用，过滤顺序为：
  目标国家/地区过滤（`force_country` 已配置时生效）→ 该国收藏池在前、该国
  非收藏池在后 → 池内按综合分排（综合分降序，延迟升序，VPNGate 分数降序兜底）。
- 新增 `composite_node_score()`：综合分 = 0.3 × 延迟分 + 0.3 × 可用性分 +
  0.4 × iplark 评分归一化。**第一阶段只接延迟与可用性**，iplark 维是真实接入点
  而非空壳：读取节点 `iplark_score`（百分制，None = 未知）；池内没有任何评分时
  该维取中性 0.5，不影响排序；第三阶段开始写评分后，未知节点按池内中位数填补，
  单次查分失败不会把好节点排到底。
- IP 类型菜单过滤：后端 `apply_routing_filters()` 与新选择函数均支持
  全部 / 住宅 / 机房 / **未知**（未知 = 尚未识别出 `ip_type` 的节点）；两处路由
  配置校验白名单已同步加入 `unknown`。
- 切换候选上限：`auto_switch_node()` 的递归重试上限改用 `SWITCH_CANDIDATE_LIMIT`
  常量（3 次，与原有行为一致，仅把硬编码改为常量）。
- 防抖动：`auto_switch_node()` 记录刚切走的节点，2 小时内不回切（除非它是唯一
  可用候选）；手动点击切换不受此限制（与方案“固定 IP 模式下仅允许手动”一致，
  手动路径本身也不走该函数）。

### 4. 面板（原设计基础上只加新功能）

- 工具栏新增“保留池”按钮（`toggleRetainedView()`），只显示观察期节点；与收藏
  视图互斥；按钮高亮状态由 `updateRetainedButtonUI()` 在 `render()` 中同步。
- 节点行：观察期节点在状态徽章旁显示“观察期”标识；新增 iplark 评分列（第一阶段
  显示“—”，第三阶段写评分后自动显示真实分数，无需再改前端）；操作区新增置灰的
  “查评分”按钮（第一阶段查分功能未实现，按钮 disabled 并注明第三阶段接入）。
- 筛选：工具栏 IP 类型下拉新增“未知类型 IP”；路由设置 IP 类型卡片新增“未知类型”；
  空态表格 colspan 由 7 改为 8（新增一列）。

### 5. 新增 API（沿用 `/api` 前缀与原有 secret 路径 + 登录鉴权，鉴权逻辑未动）

- `GET /api/retained`：返回观察期节点一览（id、国家、IP、端口、协议、IP 类型、
  延迟、探测状态、最后可见时间、连续失败次数、是否收藏）及归档条数。
- `POST /api/favorite`：收藏开关（见上）。

### 6. 配置项（带注释的常量，均可用环境变量覆盖，与原项目风格一致）

- `RETAINED_OBSERVING_GRACE_SECONDS`：14 天
- `RETAINED_TCP_FAILURE_THRESHOLD` / `RETAINED_TCP_STALE_SECONDS`：3 次 / 24 小时
- `RETAINED_NON_TCP_FAILURE_THRESHOLD` / `RETAINED_NON_TCP_STALE_SECONDS`：5 次 / 72 小时
- `RETAINED_LIVENESS_SWEEP_SECONDS`：12 小时
- `SWITCH_CANDIDATE_LIMIT`：3 个
- `SWITCH_BACK_COOLDOWN_SECONDS`：2 小时
- `RETAINED_POOL_MAX_NODES`：500 条
- 黑名单 30 分钟复用原有 `INVALID_BACKOFF_SECONDS`，未重复定义
- 评分权重：`SCORE_WEIGHT_LATENCY` 0.3 / `SCORE_WEIGHT_AVAILABILITY` 0.3 /
  `SCORE_WEIGHT_IPLARK` 0.4

## 三、明确不做的事（留给后续阶段与部署）

- 不接 iplark 评分查分（第三阶段）：只有评分字段与排序接入点，面板“查评分”按钮
  置灰，评分列显示“—”。
- 不做隧道内延迟测量（第四阶段）：延迟仍用原有隧道外实测。
- 不改代理绑定与远程接入：`proxy_server.py` 未动，代理继续只监听本机；远程只走
  SSH 隧道 + IP 白名单（文档层面，见发布流程文档）。
- 不改 `install.sh` 里的更新源地址（见部署 TODO 第 1 条）。
- 不创建 GitHub 仓库、不推送代码、不联系任何人。

## 四、验证结果

- `python3 -m py_compile vpngate_manager.py`：通过。
- 前端 JS 语法：从 `INDEX_HTML` 提取唯一 `<script>` 块，`node --check`：通过。
- 功能测试（临时脚本 `/tmp/phase1_test.py`，直接导入真实模块，以临时
  `VPNGATE_DATA_DIR` 隔离运行数据，全部通过）：
  - 综合分：低延迟可用节点 > 高延迟可用节点 > 不可用节点；iplark 接入点：有评分
    节点 0.66 > 未知节点（池内中位数 55 分）0.52 > 低分节点 0.38。
  - 选择排序：目标 GB 时收藏的 GB 节点排第一（即使延迟最差），其次按综合分；
    IP 类型“未知”菜单只留无类型节点；收藏模式只出收藏节点。
  - 存活清理：7 个构造节点中恰好删除 2 个（TCP 3 次失败 + 25 小时未见；
    UDP 5 次失败 + 80 小时未见）；收藏、活动、非观察期、未达失败数、未达陈旧度
    的节点全部保留；归档文件含被删节点的连接配置与删除原因。
- `git diff`：仅 `vpngate_manager.py` 一个文件改动（+444 / -13）；`install.sh`
  无 diff；远端未变，未执行过推送。
- grep 核查：刷新合并段已无“消失即删”路径——消失节点的全部出路是进入观察期、
  宽限期满归档删除、超限归档淘汰或存活清理归档删除（4 处 `archive_retained_node`
  调用点）；其余 `nodes.json` 写回点均为原有全量写回逻辑，不丢节点。

## 五、已知局限（部署前需实测）

- `maintain_valid_nodes` 合并段与 `/api/favorite`、`/api/retained` 处理函数未在
  真实服务上跑过（需要 VPS + TUN/OpenVPN + 真实 VPNGate 拉取），仅通过语法、
  单元测试与代码审查验证；部署后需在干净 VPS 上跑一轮刷新、收藏、切换验证。
- `toggleFavRouting()` 里的第二个 `updateFavPanelUI()` 调用点未同步加保留池按钮
  更新——因为该函数随后即调用 `load()` 重新渲染，而 `render()` 已是保留池按钮
  状态的唯一同步点，故无实际影响。
- 观察期节点的探测复用现有周期探测（探测所有非活动节点），未单独设探测频率；
  若观察期节点量大，探测轮次会变长，属可接受的第一阶段行为。

## 六、部署 TODO（部署时再改，勿提前改）

1. **`install.sh` 更新源**：目前仍指向上游（`ml update` 与安装脚本内的上游地址）；
   目标仓库名确定后，改为自己的仓库地址，并同步改 `vpngate_manager.py` 里的
   `GITHUB_REPOSITORY` 常量（影响更新检查与面板链接）。
2. **镜像地址**：`MIRROR_*_URL` 默认仍指向上游 GitHub Pages 镜像（仅作节点列表
   备用来源）；可保留，也可自建镜像后替换。
3. **LICENSE**：发布时不要直接照抄上游那个 22 行缩略文件当全文；附上 gnu.org 的
   GPL-3.0 全文，并保留原项目版权声明与出处（见发布流程文档 §四，已核实为
   GPL-3.0 意图）。
4. **README**：发布前补中英双语 README（含原项目出处声明与改动清单），并更新
   `VERSION` 与 Release Notes。
5. **.gitignore 已覆盖运行时数据**（`vpngate_data/` 含 `nodes.json`、`ui_auth.json`、
   `retained_archive.json`），首推前仍需人工确认无凭据文件混入。
6. **一键安装验证**：转公开后，在干净 VPS 上跑一键安装命令，确认面板可打开、
   `ml` 命令可用、刷新/收藏/切换流程正常，再对外分享。
