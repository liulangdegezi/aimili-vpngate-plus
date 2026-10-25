# aimili-vpngate-plus

**VPNGate node manager and HTTP / HTTPS / SOCKS5 proxy gateway for Linux VPS (modified version)**

[简体中文](README.md) · **English**

> **Relationship to the original project and attribution**: This project is a modified version of [OpenMili/aimili-vpngate](https://github.com/OpenMili/aimili-vpngate). Original copyright and license notices are retained; new features (retention pool, favorites-first selection, iplark scoring hook, remote access mode) are changes made by this project and are not affiliated with the original project. The retention and switch-limit design references [MasterAlanLab/free-proxy](https://github.com/MasterAlanLab/free-proxy). See [IMPLEMENTATION_NOTES.md](IMPLEMENTATION_NOTES.md) for the change list.

| Item | Default / supported range |
| --- | --- |
| Web admin panel | TCP `8787` + secret path + username/password |
| Local proxy | `127.0.0.1:7928`, HTTP, HTTPS `CONNECT` and SOCKS5 |
| Source deployment | x64, x86, ARM64, ARM32 Linux |
| Update channel | This repository's `main` branch (`ml update` pulls from this repo, not upstream) |

## New features (Phase 1)

- **Retention pool + 14-day grace period**: nodes that disappear from the VPNGate list are no longer deleted immediately; they enter an observing state for 14 days and keep being probed. After the grace period they are archived before deletion. The active node is preserved on refresh; a failed fetch does not rewrite the list.
- **Favorites exemption**: favorited nodes are never deleted for disappearing (regardless of country); any country's node can be favorited for future use.
- **Favorites-first tiered selection**: candidates are filtered by target country/region first, favorites within that set rank first, then non-favorites, each pool sorted by composite score. Composite score = 0.3 × latency + 0.3 × availability + 0.4 × iplark score (Phase 1 wires latency and availability; iplark is a real hook that takes effect once scores are written in Phase 3).
- **IP type menu**: all / residential / hosting / unknown.
- **Panel additions**: retained-pool view button, observing badge, iplark score column (shows "—" in Phase 1), greyed-out "Check score" button (Phase 3 hook); new `GET /api/retained` and `POST /api/favorite` endpoints.
- **Remote access**: off by default; when enabled, the only path is SSH tunnel + IP whitelist. The proxy port is never exposed directly.

Later phases (not yet implemented): iplark score fetching (Phase 3) and in-tunnel latency measurement (Phase 4) are hooks/placeholders only.

## Quick install

Run as `root` on a supported Linux VPS:

```
bash <(curl -Ls https://raw.githubusercontent.com/liulangdegezi/aimili-vpngate-plus/main/install.sh)
```

After installation, the terminal shows the web panel address, random secret path, and login credentials. Run `ml` to open the management menu.

Unattended install (skips first-run prompts, auto-generates secret path and credentials):

```
AIMILIVPN_NONINTERACTIVE=1 bash <(curl -Ls https://raw.githubusercontent.com/liulangdegezi/aimili-vpngate-plus/main/install.sh)
```

Before installing, enable TUN/TAP in the VPS control panel and confirm `/dev/net/tun` exists. The web panel defaults to TCP `8787`; restrict security-group access to your own IP.

## Full install

### Requirements

- OS: Ubuntu, Debian, Alpine, CentOS, RHEL, Rocky Linux, AlmaLinux, Fedora, Oracle Linux, or Amazon Linux.
- Permissions and components: `root`, OpenVPN, iptables, policy routing, TUN/TAP.
- Windows and macOS can act as proxy clients but cannot run the full gateway; Docker Desktop is not equivalent to a Linux VPS with host TUN capability.

### Option 1: One-click source install

```
bash <(curl -Ls https://raw.githubusercontent.com/liulangdegezi/aimili-vpngate-plus/main/install.sh)
```

The installer deploys to `/opt/aimilivpn` and registers a system service. Common commands:

```
ml                 # Open the management menu
ml status          # Show status, web address and account
ml logs            # Show live logs
ml restart         # Restart the service
ml password        # Reset the web account password
ml update          # Update from this repo's main branch
ml uninstall       # Uninstall
```

To review the script before installing:

```
git clone --branch main --single-branch https://github.com/liulangdegezi/aimili-vpngate-plus.git
cd aimili-vpngate-plus
sudo bash install.sh
```

### Docker

No Docker image is published for this modified version yet; please use the source install. The image address in `compose.yaml` is not published, so `docker compose up` will fail to pull.

## Usage

### 1. Log in to the web panel

After installation, visit the address printed by the installer:

```
http://VPS_IP:8787/<random-secret-path>/
```

Run `ml status` if you forget the address, `ml password` to reset credentials.

### 2. Fetch and connect nodes

1. Log in, wait for the first node load, or click "Update nodes".
2. Filter by country and use "Test" to check measured latency and availability.
3. Click "Switch" on the target node; if pre-check fails, the program tries to keep the current working connection.
4. Choose smart auto, fixed country, or fixed IP mode as needed.
5. Confirm the VPN is connected and check the current egress IP in the status area.

### 3. Use the proxy on the VPS

HTTP, HTTPS and SOCKS5 share `127.0.0.1:7928`. HTTPS goes through the HTTP proxy's `CONNECT` method; the proxy address is still `http://127.0.0.1:7928`.

```
# HTTP / HTTPS
curl -x http://127.0.0.1:7928 https://api.ipify.org

# SOCKS5 with remote DNS resolution
curl --proxy socks5h://127.0.0.1:7928 https://api.ipify.org
```

### 4. Connect from another computer or device

The proxy listens on loopback only by default. The only supported remote path is SSH tunnel + IP whitelist; do not expose the proxy port directly:

```
ssh -N \
  -L 8787:127.0.0.1:8787 \
  -L 7928:127.0.0.1:7928 \
  root@VPS_IP
```

After the tunnel is up:

- Web: `http://127.0.0.1:8787/<random-secret-path>/`
- HTTP / HTTPS proxy: `127.0.0.1:7928`
- SOCKS5 proxy: `127.0.0.1:7928`, use remote DNS or `socks5h` when supported

Port `7928` has no public-facing authentication by default. Never expose it to the internet without a firewall, source-IP restriction, or other reliable access control.

## Configuration (Phase 1)

| Setting | Value |
| --- | --- |
| Observing grace period | 14 days |
| Failure thresholds | TCP 3 failures + 24h unseen / non-TCP 5 consecutive failures + 72h unseen |
| Liveness sweep interval | 12 hours |
| Switch candidate limit | 3 |
| Failure blacklist | 30 minutes |
| Anti-flap cooldown | 2 hours (a node just switched away from is not switched back within 2h; manual switching is exempt) |
| Retention pool cap | 500 entries (archive file cap 1000 entries) |
| Score weights | latency 0.3 / availability 0.3 / iplark 0.4 |
| Score recheck interval | 8 hours (Phase 3) |

The node-list mirror fallback still uses the upstream GitHub Pages mirror (fallback source only); it can be kept or replaced with a self-hosted one.

## New panel buttons

- Star on a node row: favorite / unfavorite (global attribute; any country's node can be favorited).
- Toolbar "Retained pool" button: shows observing nodes only, mutually exclusive with the favorites view.
- "Observing" badge on a node row: the node has disappeared from the VPNGate list and is within its grace period.
- iplark score column: shows "—" in Phase 1, real scores automatically once Phase 3 writes them.
- "Check score" button: greyed out in Phase 1, wired in Phase 3.
- Filters: country/region, IP type (including unknown), favorites only.

## Scope and legal notice

By downloading, deploying, or using this project you confirm the use complies with local law, the law of the VPS location, network provider terms, and VPNGate rules. This project is for lawful network research, education, development testing, privacy protection, and authorized network access only, and must not be used to bypass lawfully implemented regulatory measures, gain unauthorized access, attack, scan, spam, defraud, infringe, or engage in other unlawful activity. VPNGate nodes are operated by third-party volunteers; this project does not own, control, or audit them and cannot guarantee their stability, speed, security, privacy policy, or logging behavior. Do not send account passwords, financial information, trade secrets, or other sensitive data through untrusted nodes. The software is provided "as is" without warranty of availability, merchantability, fitness for a particular purpose, or indirect loss. If you cannot confirm that local law or provider terms allow it, stop deploying and using it.

## License

GPL-3.0, see [LICENSE](LICENSE). Original copyright notices are retained.
