from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import proxy_server
import snapshot_utils

_import_data_dir = tempfile.TemporaryDirectory()
_original_data_dir = os.environ.get("VPNGATE_DATA_DIR")
os.environ["VPNGATE_DATA_DIR"] = _import_data_dir.name
try:
    import vpngate_manager as manager
finally:
    if _original_data_dir is None:
        os.environ.pop("VPNGATE_DATA_DIR", None)
    else:
        os.environ["VPNGATE_DATA_DIR"] = _original_data_dir


class FakeProcess:
    def __init__(self) -> None:
        self.running = True
        self.terminated = False

    def poll(self):
        return None if self.running else 0

    def terminate(self) -> None:
        self.terminated = True
        self.running = False

    def wait(self, timeout=None):
        self.running = False
        return 0

    def kill(self) -> None:
        self.running = False


def valid_snapshot_rows(rows: list[tuple[str, str, str]]) -> str:
    csv_rows = [
        "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64"
    ]
    for index, (ip, country_long, country_short) in enumerate(rows):
        config_text = (
            "client\n"
            "dev tun\n"
            "proto udp\n"
            f"remote {ip} 1194 udp\n"
            "resolv-retry infinite\n"
            "nobind\n"
            "<ca>\nCA\n</ca>\n"
            "<cert>\nCERT\n</cert>\n"
            "<key>\nKEY\n</key>\n"
        )
        config = base64.b64encode(config_text.encode("utf-8")).decode("ascii")
        csv_rows.append(
            f"vpn{index}.example,{ip},100,20,1000,{country_long},{country_short},1,{config}"
        )
    return "\n".join(csv_rows) + "\n"


def valid_snapshot(ip: str = "198.51.100.10") -> str:
    return valid_snapshot_rows([(ip, "Japan", "JP")])


class ManagerLogicTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.path_patches = [
            mock.patch.object(manager, "DATA_DIR", root),
            mock.patch.object(manager, "CONFIG_DIR", root / "configs"),
            mock.patch.object(manager, "NODES_FILE", root / "nodes.json"),
            mock.patch.object(manager, "STATE_FILE", root / "state.json"),
            mock.patch.object(manager, "AUTH_FILE", root / "auth.txt"),
            mock.patch.object(manager, "BLACKLIST_FILE", root / "blacklist.json"),
            mock.patch.object(manager, "API_CACHE_FILE", root / "api_snapshot.csv"),
            mock.patch.object(manager, "API_CACHE_META_FILE", root / "api_snapshot.meta.json"),
            mock.patch.object(manager, "BUNDLED_SNAPSHOT_FILE", root / "bundled_snapshot.csv"),
            mock.patch.object(manager.vpn_utils, "DATA_DIR", root),
            mock.patch.object(manager.vpn_utils, "IP_CACHE_FILE", root / "ip_cache.json"),
        ]
        for patcher in self.path_patches:
            patcher.start()
        manager.ensure_dirs()
        manager.active_openvpn_process = None
        manager.pending_openvpn_process = None
        manager.active_openvpn_node_id = ""
        manager.active_connection_cancel_event = None
        manager.is_connecting = False
        manager.consecutive_proxy_failures = 0
        manager.last_proxy_failure_node_id = ""
        manager.background_refill_thread = None
        manager.background_refill_cancel_event.clear()
        manager.active_sessions.clear()
        manager.full_sweep_running = False
        manager.full_sweep_cancel_requested = False

    def tearDown(self) -> None:
        if manager.connection_attempt_lock.locked():
            manager.connection_attempt_lock.release()
        manager.background_refill_cancel_event.set()
        manager.background_refill_thread = None
        for patcher in reversed(self.path_patches):
            patcher.stop()
        self.temp_dir.cleanup()

    def write_nodes(self, count: int) -> list[dict]:
        nodes = []
        for index in range(count):
            node_id = f"node-{index}"
            nodes.append(
                {
                    "id": node_id,
                    "ip": f"192.0.2.{index + 1}",
                    "remote_host": f"192.0.2.{index + 1}",
                    "remote_port": 1194,
                    "ping": index + 1,
                    "score": 1000 - index,
                    "config_text": "client\nremote 192.0.2.1 1194 udp\n",
                    "config_file": str(manager.CONFIG_DIR / f"{node_id}.ovpn"),
                    "probe_status": "not_checked",
                    "probed_at": 0,
                    "active": False,
                }
            )
        manager.write_json(manager.NODES_FILE, nodes)
        return nodes

    def test_node_probe_stops_after_target_batch(self) -> None:
        nodes = self.write_nodes(12)
        calls = []

        def fake_openvpn(config_file, **kwargs):
            calls.append(config_file)
            return True, "ready", None

        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(manager.vpn_utils, "enrich_ip_info"),
            mock.patch.object(manager, "run_openvpn_until_ready", side_effect=fake_openvpn),
            mock.patch.object(manager, "NODE_PROBE_WORKERS", 5),
        ):
            results = manager.test_multiple_nodes(
                [node["id"] for node in nodes],
                target_available=3,
            )

        self.assertEqual(5, len(calls))
        self.assertEqual(5, len(results))
        stored = manager.read_nodes()
        self.assertEqual(5, sum(node.get("probe_status") == "available" for node in stored))
        self.assertEqual(7, sum(node.get("probe_status") == "not_checked" for node in stored))

    def test_ip_classification_separates_proxy_use_from_network_type(self) -> None:
        residential, residential_reason = manager.vpn_utils.classify_ip_type(
            {
                "isp": "Sony Network Communications Inc.",
                "org": "Sony Network Communications Inc.",
                "proxy": True,
                "hosting": False,
                "mobile": False,
            }
        )
        softether, softether_reason = manager.vpn_utils.classify_ip_type(
            {
                "isp": "SoftEther",
                "org": "SoftEther Corporation",
                "proxy": True,
                "hosting": False,
                "mobile": False,
            }
        )
        hosting, hosting_reason = manager.vpn_utils.classify_ip_type(
            {"proxy": True, "hosting": True, "mobile": False}
        )
        mobile, mobile_reason = manager.vpn_utils.classify_ip_type(
            {"proxy": False, "hosting": False, "mobile": True}
        )
        unknown, unknown_reason = manager.vpn_utils.classify_ip_type(
            {"proxy": True, "hosting": False, "mobile": False}
        )

        self.assertEqual(("residential", "consumer_or_unclassified_network"), (residential, residential_reason))
        self.assertEqual(("hosting", "proxy_provider_datacenter"), (softether, softether_reason))
        self.assertEqual(("hosting", "hosting_flag"), (hosting, hosting_reason))
        self.assertEqual(("mobile", "mobile_flag"), (mobile, mobile_reason))
        self.assertEqual(("unknown", "missing_provider_data"), (unknown, unknown_reason))
        self.assertEqual("low", manager.vpn_utils.classification_confidence(unknown_reason))

    def test_ip_enrichment_reclassifies_legacy_cache_and_keeps_proxy_quality(self) -> None:
        ip = "118.240.250.95"
        manager.vpn_utils.IP_CACHE_FILE.write_text(
            json.dumps(
                {
                    ip: {
                        "ip_type": "hosting",
                        "quality": "proxy",
                        "cached_at": 9999999999,
                        "classification_version": 1,
                    }
                }
            ),
            encoding="utf-8",
        )
        api_result = [
            {
                "status": "success",
                "query": ip,
                "country": "Japan",
                "regionName": "Tokyo",
                "city": "Tokyo",
                "isp": "Sony Network Communications Inc.",
                "org": "Sony Network Communications Inc.",
                "as": "AS2527 Sony Network Communications Inc.",
                "asname": "Sony Network Communications Inc.",
                "proxy": True,
                "hosting": False,
                "mobile": False,
            }
        ]
        response = mock.MagicMock()
        response.read.return_value = json.dumps(api_result).encode("utf-8")
        response.__enter__.return_value = response
        node = {"id": "sony", "ip": ip}

        with mock.patch.object(manager.vpn_utils.urllib.request, "urlopen", return_value=response) as urlopen_mock:
            manager.vpn_utils.enrich_ip_info([node])

        self.assertEqual("residential", node["ip_type"])
        self.assertEqual("proxy", node["quality"])
        self.assertTrue(node["is_proxy"])
        self.assertFalse(node["is_hosting"])
        urlopen_mock.assert_called_once()
        cache = json.loads(manager.vpn_utils.IP_CACHE_FILE.read_text(encoding="utf-8"))
        self.assertEqual(manager.vpn_utils.IP_CLASSIFICATION_VERSION, cache[ip]["classification_version"])

    def test_ambiguous_datacenter_uses_secondary_source_and_geo_country(self) -> None:
        ip = "219.100.37.98"
        primary_payload = [{
            "status": "success",
            "query": ip,
            "country": "Japan",
            "countryCode": "JP",
            "regionName": "Tokyo",
            "city": "Chiyoda",
            "isp": "SoftEther",
            "org": "SoftEther Corporation",
            "as": "AS36599 SoftEther",
            "asname": "SOFTETHER",
            "proxy": True,
            "hosting": False,
            "mobile": False,
        }]
        primary = mock.MagicMock()
        primary.read.return_value = json.dumps(primary_payload).encode("utf-8")
        primary.__enter__.return_value = primary
        secondary = mock.MagicMock()
        secondary.read.return_value = json.dumps({"is_datacenter": True, "is_vpn": True}).encode("utf-8")
        secondary.__enter__.return_value = secondary
        node = {"id": "softether", "ip": ip}

        with mock.patch.object(
            manager.vpn_utils.urllib.request,
            "urlopen",
            side_effect=[primary, secondary],
        ):
            manager.vpn_utils.enrich_ip_info([node])

        self.assertEqual("hosting", node["ip_type"])
        self.assertEqual("high", node["ip_type_confidence"])
        self.assertEqual("datacenter", node["quality"])
        self.assertTrue(node["is_hosting"])
        self.assertEqual(["ip-api.com", "ipapi.is"], node["ip_type_sources"])
        self.assertEqual("JP", node["geo_country_short"])

    def test_unverified_datacenter_conflict_becomes_unknown(self) -> None:
        ip = "203.0.113.10"
        primary_payload = [{
            "status": "success",
            "query": ip,
            "country": "Japan",
            "countryCode": "JP",
            "regionName": "Tokyo",
            "city": "Tokyo",
            "isp": "Example VPS",
            "org": "Example VPS Hosting",
            "as": "AS64500 Example",
            "asname": "EXAMPLE",
            "proxy": True,
            "hosting": False,
            "mobile": False,
        }]
        primary = mock.MagicMock()
        primary.read.return_value = json.dumps(primary_payload).encode("utf-8")
        primary.__enter__.return_value = primary
        node = {"id": "ambiguous", "ip": ip}

        with mock.patch.object(
            manager.vpn_utils.urllib.request,
            "urlopen",
            side_effect=[primary, TimeoutError("secondary unavailable")],
        ):
            manager.vpn_utils.enrich_ip_info([node])

        self.assertEqual("unknown", node["ip_type"])
        self.assertEqual("low", node["ip_type_confidence"])
        strict = manager.apply_routing_filters([node], {"routing_mode": "auto", "routing_ip_type": "residential"})
        self.assertEqual([], strict)

    def test_missing_provider_data_uses_secondary_source_or_stays_unknown(self) -> None:
        ip = "203.0.113.11"
        primary_payload = [{
            "status": "success",
            "query": ip,
            "country": "Japan",
            "countryCode": "JP",
            "regionName": "Tokyo",
            "city": "Tokyo",
            "isp": "",
            "org": "",
            "as": "",
            "asname": "",
            "proxy": True,
            "hosting": False,
            "mobile": False,
        }]
        primary = mock.MagicMock()
        primary.read.return_value = json.dumps(primary_payload).encode("utf-8")
        primary.__enter__.return_value = primary
        node = {"id": "missing-provider", "ip": ip}

        with mock.patch.object(
            manager.vpn_utils.urllib.request,
            "urlopen",
            side_effect=[primary, TimeoutError("secondary unavailable")],
        ):
            manager.vpn_utils.enrich_ip_info([node])

        self.assertEqual("unknown", node["ip_type"])
        self.assertEqual("provider_data_unverified", node["ip_type_reason"])
        self.assertEqual("low", node["ip_type_confidence"])
        strict = manager.apply_routing_filters(
            [node],
            {"routing_mode": "auto", "routing_ip_type": "residential"},
        )
        self.assertEqual([], strict)

    def test_strict_residential_filter_requires_medium_or_high_confidence(self) -> None:
        nodes = [
            {"id": "low", "ip_type": "residential", "ip_type_confidence": "low"},
            {"id": "medium", "ip_type": "residential", "ip_type_confidence": "medium"},
            {"id": "mobile", "ip_type": "mobile", "ip_type_confidence": "high"},
            {"id": "hosting", "ip_type": "hosting", "ip_type_confidence": "high"},
        ]

        strict = manager.apply_routing_filters(
            nodes,
            {"routing_mode": "auto", "routing_ip_type": "residential"},
        )

        self.assertEqual(["medium", "mobile"], [node["id"] for node in strict])

    def test_background_ip_enrichment_merges_metadata_without_replacing_status(self) -> None:
        nodes = self.write_nodes(2)
        nodes[0]["probe_status"] = "available"
        manager.write_json(manager.NODES_FILE, nodes)

        def fake_enrich(items):
            for item in items:
                item["ip_type"] = "residential"
                item["quality"] = "proxy"
                item["owner"] = "Consumer ISP"
                item["is_proxy"] = True

        with mock.patch.object(manager.vpn_utils, "enrich_ip_info", side_effect=fake_enrich):
            changed = manager.enrich_stored_nodes()

        stored = manager.read_nodes()
        self.assertGreater(changed, 0)
        self.assertEqual("available", next(node for node in stored if node["id"] == "node-0")["probe_status"])
        self.assertTrue(all(node["ip_type"] == "residential" for node in stored))

    def test_source_deadline_still_tries_official_http(self) -> None:
        csv_text = valid_snapshot()

        def fake_fetch(url, verify_ssl=True, deadline_seconds=None):
            if url == manager.API_HTTPS_URL:
                raise manager.SourceDeadlineExceeded("slow official source")
            if url == manager.API_HTTP_URL:
                return csv_text
            raise AssertionError(f"unexpected source: {url}")

        with (
            mock.patch.object(manager, "fetch_api_text_with_deadline", side_effect=fake_fetch) as fetch_mock,
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual(1, len(nodes))
        self.assertEqual(
            [manager.API_HTTPS_URL, manager.API_HTTP_URL],
            [call.args[0] for call in fetch_mock.call_args_list],
        )

    def test_probe_failure_preserves_existing_ip_metadata(self) -> None:
        nodes = self.write_nodes(1)
        nodes[0].update(
            {
                "owner": "Existing ISP",
                "location": "日本 东京",
                "ip_type": "residential",
                "ip_type_confidence": "medium",
            }
        )
        manager.write_json(manager.NODES_FILE, nodes)

        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=0),
            mock.patch.object(manager, "run_openvpn_until_ready", return_value=(False, "offline", None)),
        ):
            manager.test_multiple_nodes([nodes[0]["id"]])

        stored = manager.read_nodes()[0]
        self.assertEqual("unavailable", stored["probe_status"])
        self.assertEqual("Existing ISP", stored["owner"])
        self.assertEqual("日本 东京", stored["location"])
        self.assertEqual("residential", stored["ip_type"])
        self.assertEqual("medium", stored["ip_type_confidence"])

    def test_country_matching_accepts_iso_and_legacy_name(self) -> None:
        node = {"country": "日本", "country_short": "JP"}
        self.assertTrue(manager.country_matches(node["country"], "JP", node["country_short"]))
        self.assertTrue(manager.country_matches(node["country"], "日本", node["country_short"]))
        self.assertFalse(manager.country_matches(node["country"], "KR", node["country_short"]))
        self.assertEqual("JP", manager.normalize_routing_country("日本", [node]))

    def test_web_and_proxy_ports_must_be_distinct(self) -> None:
        self.assertTrue(manager.ports_conflict(8787, "8787"))
        self.assertFalse(manager.ports_conflict(8787, 7928))

    def test_ui_connection_requires_tunnel_and_proxy_readiness(self) -> None:
        manager.active_openvpn_node_id = "node-1"
        manager.active_openvpn_process = FakeProcess()
        base_state = {"is_connecting": False, "tunnel_ready": True, "proxy_ready": False, "proxy_ok": False}
        self.assertFalse(manager.connection_ready_for_ui(base_state))
        ready_state = {**base_state, "proxy_ready": True, "proxy_ok": True}
        self.assertTrue(manager.connection_ready_for_ui(ready_state))

    def test_manual_disconnect_state_clears_all_readiness_flags(self) -> None:
        nodes = self.write_nodes(1)
        nodes[0]["active"] = True
        manager.write_json(manager.NODES_FILE, nodes)
        manager.set_state(
            is_connecting=True,
            tunnel_ready=True,
            proxy_ready=True,
            proxy_ok=True,
            proxy_ip="198.51.100.20",
        )

        with mock.patch.object(manager, "stop_active_openvpn") as stop_mock:
            manager.clear_active_connection_state("手动断开连接")

        stop_mock.assert_called_once_with()
        state = manager.get_state()
        self.assertFalse(state["is_connecting"])
        self.assertFalse(state["tunnel_ready"])
        self.assertFalse(state["proxy_ready"])
        self.assertFalse(state["proxy_ok"])
        self.assertEqual("-", state["proxy_ip"])
        self.assertFalse(any(node.get("active") for node in manager.read_nodes()))

    def test_ui_auth_json_is_written_private(self) -> None:
        auth_file = manager.DATA_DIR / "ui_auth.json"
        manager.write_json(auth_file, {"username": "test", "password": "secret"})
        if os.name != "nt":
            self.assertEqual(0o600, stat.S_IMODE(auth_file.stat().st_mode))

    def test_source_deadline_limits_total_fetch_time(self) -> None:
        def slow_fetch(url, verify_ssl=True):
            threading.Event().wait(0.1)
            return valid_snapshot()

        with mock.patch.object(manager, "fetch_api_text", side_effect=slow_fetch):
            started = manager.time.monotonic()
            with self.assertRaises(manager.SourceDeadlineExceeded):
                manager.fetch_api_text_with_deadline(
                    manager.API_HTTPS_URL,
                    deadline_seconds=0.01,
                )

        self.assertLess(manager.time.monotonic() - started, 0.08)

    def test_node_probe_stops_after_systemic_openvpn_failure(self) -> None:
        nodes = self.write_nodes(12)

        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(False, "[ERR_OVPN_TUN_NOT_AVAILABLE] missing TUN", None),
            ) as openvpn_mock,
            mock.patch.object(manager, "NODE_PROBE_WORKERS", 5),
            mock.patch.object(manager, "log_to_json"),
        ):
            results = manager.test_multiple_nodes(
                [node["id"] for node in nodes],
                target_available=3,
            )

        self.assertEqual(5, openvpn_mock.call_count)
        self.assertEqual(5, len(results))
        stored = manager.read_nodes()
        self.assertEqual(5, sum(node.get("probe_status") == "unavailable" for node in stored))
        self.assertEqual(7, sum(node.get("probe_status") == "not_checked" for node in stored))

    def test_maintenance_does_not_start_second_batch_after_systemic_failure(self) -> None:
        candidates = self.write_nodes(12)

        with (
            mock.patch.object(manager, "fetch_candidates", return_value=candidates),
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(False, "[ERR_OVPN_CMD_NOT_FOUND] openvpn missing", None),
            ) as openvpn_mock,
            mock.patch.object(manager, "NODE_PROBE_WORKERS", 5),
            mock.patch.object(manager, "log_to_json"),
        ):
            result = manager.maintain_valid_nodes()

        self.assertEqual(5, openvpn_mock.call_count)
        self.assertIn("Tested 5", result)

    def test_cancel_pending_connection_stops_handshake_process(self) -> None:
        process = FakeProcess()
        event = threading.Event()
        manager.pending_openvpn_process = process
        manager.active_connection_cancel_event = event
        manager.is_connecting = True
        previous_epoch = manager.connection_epoch

        manager.cancel_pending_connection_attempt()

        self.assertTrue(event.is_set())
        self.assertTrue(process.terminated)
        self.assertIsNone(manager.pending_openvpn_process)
        self.assertFalse(manager.is_connecting)
        self.assertEqual(previous_epoch + 1, manager.connection_epoch)

    def test_proxy_failures_reset_when_node_changes(self) -> None:
        self.assertEqual(1, manager.record_proxy_failure("node-a"))
        self.assertEqual(2, manager.record_proxy_failure("node-a"))
        self.assertEqual(1, manager.record_proxy_failure("node-b"))
        manager.reset_proxy_failure_counter("node-b")
        self.assertEqual(1, manager.record_proxy_failure("node-b"))

    def test_failed_switch_preflight_keeps_current_connection(self) -> None:
        nodes = self.write_nodes(2)
        nodes[0]["active"] = True
        manager.write_json(manager.NODES_FILE, nodes)
        current_process = FakeProcess()
        manager.active_openvpn_process = current_process
        manager.active_openvpn_node_id = nodes[0]["id"]

        with (
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(False, "preflight failed", None),
            ),
            mock.patch.object(manager, "log_to_json"),
        ):
            with self.assertRaisesRegex(RuntimeError, "已保留当前连接"):
                manager.connect_node(nodes[1]["id"])

        self.assertIs(manager.active_openvpn_process, current_process)
        self.assertEqual(nodes[0]["id"], manager.active_openvpn_node_id)
        self.assertTrue(current_process.running)
        stored = {node["id"]: node for node in manager.read_nodes()}
        self.assertEqual("unavailable", stored[nodes[1]["id"]]["probe_status"])

    def test_proxy_failure_does_not_report_connection_success(self) -> None:
        nodes = self.write_nodes(1)
        process = FakeProcess()

        with (
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                return_value=(True, "ready", process),
            ),
            mock.patch.object(manager, "setup_policy_routing", return_value=False),
            mock.patch.object(manager, "cleanup_policy_routing"),
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(manager, "check_proxy_health", return_value={"ok": False, "error": "no route"}),
            mock.patch.object(manager, "log_to_json"),
        ):
            with self.assertRaisesRegex(RuntimeError, "代理出口不可用"):
                manager.connect_node(nodes[0]["id"])

        self.assertFalse(process.running)
        self.assertIsNone(manager.active_openvpn_process)
        self.assertEqual("", manager.active_openvpn_node_id)
        stored = manager.read_nodes()
        self.assertEqual("unavailable", stored[0]["probe_status"])

    def test_manual_failure_recovery_prefers_previous_node(self) -> None:
        with (
            mock.patch.object(manager, "active_openvpn_running", return_value=False),
            mock.patch.object(manager, "connect_node", return_value="connected") as connect_mock,
            mock.patch.object(manager, "log_to_json"),
            mock.patch.object(manager, "auto_switch_node") as auto_switch_mock,
        ):
            manager.recover_after_manual_connect_failure("old-node")

        connect_mock.assert_called_once_with("old-node")
        auto_switch_mock.assert_not_called()

    def test_auto_switch_exhaustion_schedules_background_refill(self) -> None:
        with (
            mock.patch.object(manager, "schedule_background_refill", return_value=True) as schedule_mock,
            mock.patch.object(manager, "log_to_json") as log_mock,
        ):
            manager.auto_switch_node(attempt=3)

        schedule_mock.assert_called_once_with()
        log_mock.assert_called_once_with("INFO", "Main", "连续自动切换失败，已启动唯一后台节点补齐任务")

    def test_physical_interface_detection_is_cached(self) -> None:
        original_cache = manager.vpn_utils.physical_interface_cache
        manager.vpn_utils.physical_interface_cache = (None, 0.0)
        try:
            with mock.patch.object(
                manager.vpn_utils,
                "_detect_physical_interface",
                return_value="eth0",
            ) as detect_mock:
                self.assertEqual("eth0", manager.vpn_utils.get_physical_interface())
                self.assertEqual("eth0", manager.vpn_utils.get_physical_interface())
            detect_mock.assert_called_once_with()
        finally:
            manager.vpn_utils.physical_interface_cache = original_cache

    def test_forced_refresh_keeps_healthy_active_connection(self) -> None:
        process = FakeProcess()
        manager.active_openvpn_process = process
        manager.active_openvpn_node_id = "active-node"

        with (
            mock.patch.object(manager, "fetch_candidates", return_value=[]),
            mock.patch.object(manager, "stop_active_openvpn") as stop_mock,
            mock.patch.object(manager, "log_to_json"),
        ):
            result = manager.maintain_valid_nodes(force=True)

        self.assertEqual("没有拉取到新节点", result)
        self.assertTrue(process.running)
        stop_mock.assert_not_called()

    def test_fetch_timeout_skips_insecure_https_retry(self) -> None:
        csv_text = valid_snapshot()

        def fake_fetch(url, verify_ssl):
            if url.startswith("https://"):
                raise TimeoutError("timed out")
            return csv_text

        with (
            mock.patch.object(manager, "fetch_api_text", side_effect=fake_fetch) as fetch_mock,
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "set_state"),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual(1, len(nodes))
        self.assertEqual(
            [mock.call(manager.API_HTTPS_URL, True), mock.call(manager.API_HTTP_URL, True)],
            fetch_mock.call_args_list,
        )

    def test_discovery_countries_are_normalized_and_persisted(self) -> None:
        countries = manager.persist_discovery_countries(["jp", "US", "JP", "bad", ""])

        self.assertEqual(["JP", "US"], countries)
        self.assertEqual(["JP", "US"], manager.load_ui_config()["discovery_countries"])
        self.assertEqual(["JP", "US"], manager.get_state()["discovery_countries"])

    def test_fetch_filters_country_after_source_is_accepted(self) -> None:
        csv_text = valid_snapshot_rows(
            [
                ("198.51.100.60", "Japan", "JP"),
                ("198.51.100.61", "United States", "US"),
            ]
        )
        manager.persist_discovery_countries(["JP"])

        with (
            mock.patch.object(manager, "fetch_api_text", return_value=csv_text) as fetch_mock,
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual(["JP"], [node["country_short"] for node in nodes])
        fetch_mock.assert_called_once_with(manager.API_HTTPS_URL, True)
        self.assertEqual(csv_text, manager.API_CACHE_FILE.read_text(encoding="utf-8"))
        self.assertIn("成功获取 2 个", manager.get_state()["last_fetch_message"])
        self.assertIn("保留 1 个", manager.get_state()["last_fetch_message"])

    def test_empty_country_result_does_not_fall_through_to_next_source(self) -> None:
        csv_text = valid_snapshot_rows(
            [
                ("198.51.100.70", "Japan", "JP"),
                ("198.51.100.71", "United States", "US"),
            ]
        )
        manager.persist_discovery_countries(["DE"])

        with (
            mock.patch.object(manager, "fetch_api_text", return_value=csv_text) as fetch_mock,
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual([], nodes)
        fetch_mock.assert_called_once_with(manager.API_HTTPS_URL, True)
        state = manager.get_state()
        self.assertEqual("ok", state["last_fetch_status"])
        self.assertEqual("official_https", state["last_fetch_source"])
        self.assertIn("保留 0 个", state["last_fetch_message"])

    def test_node_table_contains_latency_country_panel_and_test_action(self) -> None:
        self.assertIn('<th style="width: 125px;">延迟</th>', manager.INDEX_HTML)
        self.assertIn('colspan="8"', manager.INDEX_HTML)
        self.assertIn('class="country-option-input"', manager.INDEX_HTML)
        self.assertIn('${testBtn}', manager.INDEX_HTML)

    def test_web_dashboard_has_browser_freeze_safeguards(self) -> None:
        self.assertNotIn("backdrop-filter", manager.LOGIN_HTML)
        self.assertNotIn("backdrop-filter", manager.INDEX_HTML)
        self.assertNotIn("background-attachment: fixed", manager.INDEX_HTML)
        self.assertIn("@media (prefers-reduced-motion: reduce)", manager.LOGIN_HTML)
        self.assertIn("@media (prefers-reduced-motion: reduce)", manager.INDEX_HTML)
        self.assertIn("const pageSize = 50;", manager.INDEX_HTML)
        self.assertIn('id="pagination_container"', manager.INDEX_HTML)
        self.assertIn('paginationContainer.style.display = totalPages > 1 ? "flex" : "none";', manager.INDEX_HTML)
        self.assertIn("const MAX_RENDERED_LOG_LINES = 300;", manager.INDEX_HTML)
        self.assertIn("nodesRequestPromise", manager.INDEX_HTML)
        self.assertIn("backgroundPollInFlight", manager.INDEX_HTML)
        self.assertIn('let lastNodesSnapshotSignature = "";', manager.INDEX_HTML)
        self.assertIn("if (signature === lastNodesSnapshotSignature) return false;", manager.INDEX_HTML)
        self.assertIn('typeof document.hidden !== "boolean" || !document.hidden', manager.INDEX_HTML)
        self.assertEqual(500, manager.WEB_LOG_MAX_ENTRIES)

    def test_web_dashboard_has_cross_browser_interaction_safeguards(self) -> None:
        self.assertNotIn("fonts.googleapis.com", manager.LOGIN_HTML)
        self.assertNotIn("fonts.googleapis.com", manager.INDEX_HTML)
        self.assertIn('const pwd = document.getElementById("password").value;', manager.LOGIN_HTML)
        self.assertIn('const password = $("cred_password").value;', manager.INDEX_HTML)
        self.assertIn("function fetchWithTimeout", manager.LOGIN_HTML)
        self.assertIn("function fetchWithTimeout", manager.INDEX_HTML)
        self.assertNotIn("await fetch(", manager.INDEX_HTML)
        self.assertIn('role="dialog" aria-modal="true"', manager.INDEX_HTML)
        self.assertIn('aria-label="关闭网页安全设置"', manager.INDEX_HTML)
        self.assertIn('class="option-card active" data-value="auto" aria-pressed="true"', manager.INDEX_HTML)
        self.assertIn('class="vps-recommend-tab"', manager.INDEX_HTML)
        self.assertIn('position: static;', manager.INDEX_HTML)
        self.assertIn('-webkit-overflow-scrolling: touch;', manager.INDEX_HTML)
        self.assertIn('formatUrlHost(window.location.hostname)', manager.INDEX_HTML)
        self.assertNotIn('id="status" class="status" style="display: none;"', manager.INDEX_HTML)
        self.assertIn('${esc(localProxy)}', manager.INDEX_HTML)
        self.assertIn('${esc(statusMessage)}', manager.INDEX_HTML)

    def test_dashboard_javascript_is_valid(self) -> None:
        if not shutil.which("node"):
            self.skipTest("Node.js is not installed; JavaScript syntax check skipped")
        scripts = re.findall(r"<script>(.*?)</script>", manager.INDEX_HTML, re.DOTALL)
        self.assertTrue(scripts)
        with tempfile.NamedTemporaryFile("w", suffix=".js", encoding="utf-8", delete=False) as handle:
            handle.write("\n".join(scripts))
            script_path = handle.name
        try:
            result = subprocess.run(
                ["node", "--check", script_path],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
        finally:
            Path(script_path).unlink(missing_ok=True)

    def test_random_password_uses_cryptographic_randomness(self) -> None:
        with mock.patch.object(manager.secrets, "choice", side_effect=list("aA0aA0aA0aA0")) as choice:
            password = manager.generate_random_password()

        self.assertEqual("aA0aA0aA0aA0", password)
        self.assertEqual(12, choice.call_count)

    def test_expired_sessions_are_removed(self) -> None:
        manager.active_sessions.update({"expired": 99.0, "active": 101.0})

        removed = manager.purge_expired_sessions(now=100.0)

        self.assertEqual(1, removed)
        self.assertEqual({"active": 101.0}, manager.active_sessions)

    def test_web_log_reader_only_returns_recent_valid_entries(self) -> None:
        log_file = manager.DATA_DIR / "logs" / "current.json"
        log_file.parent.mkdir(parents=True)
        with log_file.open("w", encoding="utf-8") as f:
            for index in range(520):
                f.write(json.dumps({"index": index}) + "\n")
            f.write("not-json\n")

        entries = manager.read_recent_log_entries(log_file)

        self.assertEqual(500, len(entries))
        self.assertEqual(20, entries[0]["index"])
        self.assertEqual(519, entries[-1]["index"])

    def test_web_update_controls_only_expose_stable_main_channel(self) -> None:
        self.assertEqual("1.2.2", manager.APP_VERSION)
        self.assertEqual("V1.2.2 正式版", manager.APP_VERSION_LABEL)
        self.assertIn("检测更新", manager.INDEX_HTML)
        self.assertIn("/api/check_update", manager.INDEX_HTML)
        self.assertIn("/tree/main", manager.INDEX_HTML)
        self.assertNotIn("/releases/latest", manager.INDEX_HTML)
        self.assertNotIn('id="latest_release_link"', manager.INDEX_HTML)
        self.assertNotIn("下载最新正式版", manager.INDEX_HTML)
        self.assertNotIn("releaseLink", manager.INDEX_HTML)
        self.assertNotIn("/tree/bate", manager.INDEX_HTML)
        self.assertNotIn(">测试版<", manager.INDEX_HTML)
        self.assertIn('id="deployment_mode_label"', manager.INDEX_HTML)

    def test_installer_updates_only_from_main(self) -> None:
        install_text = (manager.ROOT_DIR / "install.sh").read_text(encoding="utf-8")

        self.assertIn('DEPLOY_BRANCH="main"', install_text)
        self.assertIn('branch = "main"', install_text)
        self.assertNotIn("CURRENT_BRANCH", install_text)
        self.assertNotIn("origin/master", install_text)
        self.assertNotIn("bate", install_text.lower())

    def test_installer_uses_secure_credentials_and_current_version(self) -> None:
        install_text = (manager.ROOT_DIR / "install.sh").read_text(encoding="utf-8")

        self.assertNotIn("random.choices", install_text)
        self.assertIn("secrets.choice", install_text)
        self.assertIn('get_app_version()', install_text)
        self.assertNotIn("管理终端 v2.0", install_text)
        self.assertIn("5-90 秒", install_text)
        self.assertIn('new_pwd = input("请输入新管理密码 (不能为空): ")', install_text)
        self.assertIn('state["active_openvpn_node_id"] = ""', install_text)
        self.assertIn("ip link show dev tun0", install_text)
        self.assertIn("pidof openvpn", install_text)
        self.assertIn('chmod 600 "$AUTH_FILE"', install_text)
        self.assertIn("AIMILIVPN_NONINTERACTIVE", install_text)
        self.assertIn('["ip", "rule", "del", "table", "100"]', install_text)
        self.assertIn('/etc/sysctl.d/99-aimilivpn.conf', install_text)
        self.assertNotIn('http://[::1]:${PROXY_PORT}', install_text)

    def test_openvpn_command_requires_server_certificate_usage(self) -> None:
        with mock.patch.object(manager, "get_openvpn_version", return_value=2.5):
            command = manager.openvpn_command("node.ovpn", route_nopull=True)
        index = command.index("--remote-cert-tls")
        self.assertEqual("server", command[index + 1])

    def test_release_workflow_uses_full_patch_version(self) -> None:
        workflow_text = (manager.ROOT_DIR / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

        self.assertIn("default: v2.1.5", workflow_text)
        self.assertIn("AimiliVPN V$(tr -d '\\r\\n' < VERSION) 正式版", workflow_text)
        self.assertNotIn("cut -d. -f1,2 VERSION", workflow_text)

    def test_latest_release_check_ignores_non_version_name_text(self) -> None:
        release = {
            "tag_name": "v2.2.0",
            "name": "AimiliVPN V2.2 正式版",
            "published_at": "2026-09-01T00:00:00Z",
            "draft": False,
            "prerelease": False,
        }
        with mock.patch.object(manager, "fetch_api_text", return_value=json.dumps(release)) as fetch_mock:
            result = manager.check_latest_release()

        self.assertTrue(result["ok"])
        self.assertTrue(result["update_available"])
        self.assertEqual("2.2.0", result["latest_version"])
        self.assertEqual("v2.2.0", result["latest_tag"])
        self.assertEqual(
            "https://github.com/liulangdegezi/aimili-vpngate-plus/releases/tag/v2.2.0",
            result["release_url"],
        )
        fetch_mock.assert_called_once_with(manager.GITHUB_LATEST_RELEASE_API, True)

    def test_latest_release_check_reports_current_formal_version(self) -> None:
        release = {
            "tag_name": "v1.2.2",
            "name": "AimiliVPN V1.2.2 正式版",
            "draft": False,
            "prerelease": False,
        }
        with mock.patch.object(manager, "fetch_api_text", return_value=json.dumps(release)):
            result = manager.check_latest_release()

        self.assertFalse(result["update_available"])
        self.assertEqual("V1.2.2 正式版", result["current_version_label"])

    def test_latest_release_check_no_release_returns_current_without_error(self) -> None:
        import io
        import urllib.error

        error = urllib.error.HTTPError(
            "https://api.github.com/repos/x/releases/latest",
            404,
            "Not Found",
            {},
            io.BytesIO(b""),
        )
        with mock.patch.object(manager, "fetch_api_text", side_effect=error):
            result = manager.check_latest_release()

        self.assertTrue(result["ok"])
        self.assertTrue(result["no_release"])
        self.assertFalse(result["update_available"])
        self.assertEqual("1.2.2", result["current_version"])

    def test_full_sweep_order_fixed_ip_first(self) -> None:
        nodes = [
            {"id": "other", "latency_ms": 10, "ping": 10},
            {"id": "fixed", "latency_ms": 500, "ping": 500},
            {"id": "other2", "latency_ms": 20, "ping": 20},
        ]
        ui_cfg = {"routing_mode": "fixed_ip", "fixed_node_id": "fixed"}
        ordered = manager.full_sweep_order(nodes, ui_cfg)
        self.assertEqual(["fixed", "other", "other2"], [n["id"] for n in ordered])

    def test_full_sweep_order_fixed_region_first(self) -> None:
        nodes = [
            {"id": "us", "country": "United States", "country_short": "US", "latency_ms": 500, "ping": 500},
            {"id": "de", "country": "Germany", "country_short": "DE", "latency_ms": 10, "ping": 10},
            {"id": "jp", "country": "Japan", "country_short": "JP", "latency_ms": 20, "ping": 20},
        ]
        ui_cfg = {"routing_mode": "fixed_region", "force_country": "US"}
        ordered = manager.full_sweep_order(nodes, ui_cfg)
        self.assertEqual(["us", "de", "jp"], [n["id"] for n in ordered])

    def test_full_sweep_order_favorites_first(self) -> None:
        nodes = [
            {"id": "fav", "latency_ms": 500, "ping": 500},
            {"id": "plain", "latency_ms": 10, "ping": 10},
        ]
        ui_cfg = {"routing_mode": "favorites", "favorite_node_ids": ["fav"]}
        ordered = manager.full_sweep_order(nodes, ui_cfg)
        self.assertEqual(["fav", "plain"], [n["id"] for n in ordered])

    def test_full_sweep_order_others_by_latency_unknown_last(self) -> None:
        nodes = [
            {"id": "medium", "latency_ms": 200, "ping": 10},
            {"id": "unknown", "latency_ms": 0, "ping": 0},
            {"id": "fast", "latency_ms": 50, "ping": 999},
            {"id": "ping_only", "latency_ms": 0, "ping": 300},
        ]
        ordered = manager.full_sweep_order(nodes, {"routing_mode": "auto"})
        self.assertEqual(["fast", "medium", "ping_only", "unknown"], [n["id"] for n in ordered])

    def test_full_sweep_calls_test_multiple_without_early_stop_and_excludes_active(self) -> None:
        nodes = [
            {"id": "active", "ip": "192.0.2.1", "remote_host": "192.0.2.1", "latency_ms": 5, "ping": 5, "active": True},
            {"id": "slow", "ip": "192.0.2.2", "remote_host": "192.0.2.2", "latency_ms": 300, "ping": 300},
            {"id": "quick", "ip": "192.0.2.3", "remote_host": "192.0.2.3", "latency_ms": 10, "ping": 10},
        ]
        manager.write_json(manager.NODES_FILE, nodes)
        captured = {}
        def fake_test_multiple(ids, target_available=None, stop_requested=None):
            captured["ids"] = list(ids)
            captured["target_available"] = target_available
            captured["stop_requested"] = stop_requested
            return [
                {"id": "quick", "probe_status": "available"},
                {"id": "slow", "probe_status": "unavailable"},
            ]
        with (
            mock.patch.object(manager, "load_ui_config", return_value={"routing_mode": "auto"}),
            mock.patch.object(manager, "test_multiple_nodes", side_effect=fake_test_multiple),
            mock.patch.object(manager, "set_state"),
        ):
            result = manager.run_full_sweep()
        self.assertEqual(["quick", "slow"], captured["ids"])
        self.assertIsNone(captured["target_available"])
        self.assertIsNotNone(captured["stop_requested"])
        self.assertFalse(manager.full_sweep_running)
        self.assertEqual(2, result["tested"])
        self.assertEqual(1, result["available"])
        self.assertEqual(1, result["unavailable"])
        self.assertFalse(result["interrupted"])
        stop = captured["stop_requested"]
        self.assertFalse(stop())
        manager.full_sweep_cancel_requested = True
        try:
            self.assertTrue(stop())
        finally:
            manager.full_sweep_cancel_requested = False

    def test_test_multiple_nodes_stops_between_batches_on_connect_request(self) -> None:
        nodes = self.write_nodes(12)
        calls = []
        def fake_openvpn(config_file, **kwargs):
            calls.append(config_file)
            return True, "ready", None
        state = {"n": 0}
        def stop_requested():
            state["n"] += 1
            return state["n"] >= 2
        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(manager.vpn_utils, "enrich_ip_info"),
            mock.patch.object(manager, "run_openvpn_until_ready", side_effect=fake_openvpn),
            mock.patch.object(manager, "NODE_PROBE_WORKERS", 5),
        ):
            results = manager.test_multiple_nodes(
                [node["id"] for node in nodes],
                target_available=None,
                stop_requested=stop_requested,
            )
        self.assertEqual(5, len(calls))
        self.assertEqual(5, len(results))
        stored = manager.read_nodes()
        self.assertEqual(5, sum(node.get("probe_status") == "available" for node in stored))
        self.assertEqual(7, sum(node.get("probe_status") == "not_checked" for node in stored))

    def test_latest_release_check_reports_source_update_command(self) -> None:
        release = {"tag_name": "v2.2.0", "draft": False, "prerelease": False}
        with (
            mock.patch.object(manager, "fetch_api_text", return_value=json.dumps(release)),
            mock.patch.object(manager, "DEPLOYMENT_MODE", "source"),
            mock.patch.object(manager, "DEPLOYMENT_MODE_LABEL", "Python 源码"),
            mock.patch.object(manager, "UPDATE_COMMAND", "ml update"),
        ):
            result = manager.check_latest_release()

        self.assertEqual("source", result["deployment_mode"])
        self.assertEqual("ml update", result["update_command"])

    def test_latest_release_check_reports_docker_update_command(self) -> None:
        release = {"tag_name": "v2.2.0", "draft": False, "prerelease": False}
        with (
            mock.patch.object(manager, "fetch_api_text", return_value=json.dumps(release)),
            mock.patch.object(manager, "DEPLOYMENT_MODE", "docker"),
            mock.patch.object(manager, "DEPLOYMENT_MODE_LABEL", "Docker 容器"),
            mock.patch.object(
                manager,
                "UPDATE_COMMAND",
                "docker compose pull && docker compose up -d",
            ),
        ):
            result = manager.check_latest_release()

        self.assertEqual("docker", result["deployment_mode"])
        self.assertEqual(
            "docker compose pull && docker compose up -d",
            result["update_command"],
        )

    def test_fetch_uses_github_mirror_after_official_sources(self) -> None:
        csv_text = valid_snapshot()

        def fake_fetch(url, verify_ssl):
            if url == manager.MIRROR_HTTPS_URL:
                return csv_text
            raise TimeoutError("blocked")

        with (
            mock.patch.object(manager, "fetch_api_text", side_effect=fake_fetch) as fetch_mock,
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
            mock.patch.object(manager, "read_mirror_freshness", return_value=(0.0, "")),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual(1, len(nodes))
        self.assertEqual(
            [manager.API_HTTPS_URL, manager.API_HTTP_URL, manager.MIRROR_HTTPS_URL],
            [call.args[0] for call in fetch_mock.call_args_list],
        )
        self.assertEqual(csv_text, manager.API_CACHE_FILE.read_text(encoding="utf-8"))
        self.assertEqual("github_pages_https", manager.get_state()["last_fetch_source"])

    def test_http_source_does_not_replace_trusted_cache(self) -> None:
        cached_text = valid_snapshot("198.51.100.20")
        http_text = valid_snapshot("198.51.100.21")
        manager.API_CACHE_FILE.write_text(cached_text, encoding="utf-8")

        def fake_fetch(url, verify_ssl):
            if url == manager.API_HTTP_URL:
                return http_text
            raise TimeoutError("TLS unavailable")

        with (
            mock.patch.object(manager, "fetch_api_text", side_effect=fake_fetch),
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual("198.51.100.21", nodes[0]["ip"])
        self.assertEqual(cached_text, manager.API_CACHE_FILE.read_text(encoding="utf-8"))

    def test_fetch_falls_back_to_local_cache(self) -> None:
        cached_text = valid_snapshot("198.51.100.30")
        manager.API_CACHE_FILE.write_text(cached_text, encoding="utf-8")

        with (
            mock.patch.object(manager, "fetch_api_text", side_effect=TimeoutError("all blocked")),
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual("198.51.100.30", nodes[0]["ip"])
        self.assertEqual("local_cache", manager.get_state()["last_fetch_source"])

    def test_bundled_snapshot_seeds_local_cache(self) -> None:
        bundled_text = valid_snapshot("198.51.100.40")
        manager.BUNDLED_SNAPSHOT_FILE.write_text(bundled_text, encoding="utf-8")

        with (
            mock.patch.object(manager, "fetch_api_text", side_effect=TimeoutError("all blocked")),
            mock.patch.object(manager, "load_blacklist", return_value={}),
            mock.patch.object(manager, "log_to_json"),
        ):
            nodes = manager.fetch_candidates()

        self.assertEqual("198.51.100.40", nodes[0]["ip"])
        self.assertEqual(bundled_text, manager.API_CACHE_FILE.read_text(encoding="utf-8"))
        self.assertEqual("bundled_initial", manager.get_state()["last_fetch_source"])

    def test_snapshot_rejects_executable_openvpn_directive(self) -> None:
        unsafe_config = (
            "client\ndev tun\nproto udp\nremote 198.51.100.50 1194 udp\n"
            "script-security 2\nup /tmp/payload\n"
            "<ca>\nCA\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\n"
        )
        encoded = base64.b64encode(unsafe_config.encode("utf-8")).decode("ascii")
        csv_text = (
            "#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,OpenVPN_ConfigData_Base64\n"
            f"vpn.example,198.51.100.50,100,20,1000,Japan,JP,1,{encoded}\n"
        )

        with self.assertRaisesRegex(ValueError, "no valid nodes"):
            snapshot_utils.parse_and_validate_snapshot(csv_text)


class ProxyServerConcurrencyTests(unittest.TestCase):
    def test_socks5_rejects_client_without_no_auth_method(self) -> None:
        class Client:
            def __init__(self):
                self.incoming = bytearray(b"\x01\x02")
                self.sent = bytearray()
                self.closed = False

            def recv(self, size):
                chunk = self.incoming[:size]
                del self.incoming[:size]
                return bytes(chunk)

            def sendall(self, data):
                self.sent.extend(data)

            def close(self):
                self.closed = True

        client = Client()
        with mock.patch.object(proxy_server, "proxy_auth_enabled", return_value=False):
            proxy_server.socks5_client(client, b"\x05")

        self.assertEqual(b"\x05\xff", bytes(client.sent))
        self.assertTrue(client.closed)

    def test_each_proxy_worker_keeps_its_accepted_socket(self) -> None:
        class Client:
            def __init__(self, name):
                self.name = name

            def close(self):
                pass

        class FakeServer:
            def __init__(self):
                self.items = [(Client("first"), ("first", 1)), (Client("second"), ("second", 2))]

            def setsockopt(self, *args):
                pass

            def bind(self, *args):
                pass

            def listen(self, *args):
                pass

            def accept(self):
                if self.items:
                    return self.items.pop(0)
                raise KeyboardInterrupt()

        class DeferredThread:
            targets = []

            def __init__(self, target, daemon=True):
                self.target = target
                self.targets.append(target)

            def start(self):
                pass

        seen = []
        semaphore = mock.Mock()
        semaphore.acquire.return_value = True
        with (
            mock.patch.object(proxy_server.socket, "socket", return_value=FakeServer()),
            mock.patch.object(proxy_server.threading, "Thread", DeferredThread),
            mock.patch.object(
                proxy_server,
                "proxy_client",
                side_effect=lambda client, address: seen.append((client.name, address[0])),
            ),
            mock.patch.object(proxy_server, "proxy_connection_sem", semaphore),
        ):
            with self.assertRaises(KeyboardInterrupt):
                proxy_server.start_proxy_server("127.0.0.1", 7928)
            for target in DeferredThread.targets:
                target()

        self.assertEqual([("first", "first"), ("second", "second")], seen)


if __name__ == "__main__":
    unittest.main()


class CodeUpdateTests(unittest.TestCase):
    """Panel one-click code update. All worker tests use fake
    command runners, so no real git checkout, install, or restart ever runs
    under test; the fake install dir is a temp dir, never the repo."""

    def setUp(self) -> None:
        self._saved_is_connecting = manager.is_connecting
        self._saved_full_sweep = manager.full_sweep_running
        self._saved_data_dir = manager.DATA_DIR
        self._saved_deployment = manager.DEPLOYMENT_MODE
        self._tmp = tempfile.TemporaryDirectory()
        manager.DATA_DIR = Path(self._tmp.name)
        manager.is_connecting = False
        manager.full_sweep_running = False

    def tearDown(self) -> None:
        manager.is_connecting = self._saved_is_connecting
        manager.full_sweep_running = self._saved_full_sweep
        manager.DATA_DIR = self._saved_data_dir
        manager.DEPLOYMENT_MODE = self._saved_deployment
        if manager.maintenance_lock.locked():
            manager.maintenance_lock.release()
        self._tmp.cleanup()

    def _make_install_dir(self, version: str = "1.1.0") -> Path:
        install_dir = Path(self._tmp.name) / "install"
        install_dir.mkdir(parents=True, exist_ok=True)
        (install_dir / ".git").mkdir(exist_ok=True)
        (install_dir / "VERSION").write_text(version + "\n", encoding="utf-8")
        return install_dir

    def _fake_result(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

    def test_score_button_tooltip_simplified_and_update_button_present(self) -> None:
        html = manager.INDEX_HTML
        self.assertIn('id="code_update_btn"', html)
        self.assertIn("startCodeUpdate", html)
        self.assertIn("一键更新", html)
        self.assertIn("/api/update_code", html)
        self.assertIn("/api/update_status", html)
        self.assertIn('title="暂未启用"', html)
        self.assertNotIn("评分功能为第三阶段，暂未启用", html)
        self.assertIn("最长约 90 秒", html)
        self.assertIn("出口 IP 可能变化", html)
        self.assertIn("请用终端 ml update 重试", html)
        self.assertIn("600000", html)
        self.assertIn("aimili_code_update_done", html)

    def test_update_worker_never_touches_scoring_gate(self) -> None:
        source = (manager.ROOT_DIR / "vpngate_manager.py").read_text(encoding="utf-8")
        self.assertIn("/api/update_code", source)
        self.assertIn("/api/update_status", source)
        self.assertNotIn("check_score", source)
        self.assertNotIn("iplark_qualified", source)
        self.assertNotIn("fetch_iplark_score", source)
        start = source.index("def run_code_update_worker")
        end = source.index("def spawn_code_updater")
        self.assertNotIn("iplark", source[start:end])

    def test_code_update_status_and_busy_reasons(self) -> None:
        status = manager.read_code_update_status()
        self.assertEqual("idle", status["result"])
        manager.write_code_update_status(
            "running", "fetch", "正在拉取 main 分支…", "1.1.0", ""
        )
        self.assertIn("进行中", manager.code_update_busy_reason() or "")
        manager.write_code_update_status("idle", "", "", "1.1.0", "")
        self.assertIsNone(manager.code_update_busy_reason())
        manager.maintenance_lock.acquire()
        try:
            self.assertIn("维护", manager.code_update_busy_reason() or "")
        finally:
            manager.maintenance_lock.release()
        manager.is_connecting = True
        try:
            self.assertIn("连接", manager.code_update_busy_reason() or "")
        finally:
            manager.is_connecting = False
        manager.full_sweep_running = True
        try:
            self.assertIn("全量检测", manager.code_update_busy_reason() or "")
        finally:
            manager.full_sweep_running = False

    def test_code_update_worker_already_latest_stops_without_reinstall(self) -> None:
        install_dir = self._make_install_dir("1.1.0")
        calls: list = []

        def fake(cmd, cwd, timeout, env=None):
            calls.append(list(cmd))
            if cmd[:2] == ["git", "rev-parse"]:
                return self._fake_result(0, "aaa111\n")
            return self._fake_result(0)

        result = manager.run_code_update_worker(
            install_dir=install_dir, runner=fake, panel_healthy=lambda h, p, t: True
        )
        self.assertTrue(result)
        status = manager.read_code_update_status()
        self.assertEqual("success", status["result"])
        self.assertIn("已是最新", status["message"])
        self.assertNotIn(["git", "checkout", "-B", "main", "origin/main"], calls)
        self.assertNotIn(["bash", "install.sh"], calls)

    def test_code_update_worker_temp_check_failure_keeps_old_code(self) -> None:
        install_dir = self._make_install_dir("1.1.0")
        calls: list = []

        def fake(cmd, cwd, timeout, env=None):
            calls.append(list(cmd))
            if cmd[:2] == ["git", "rev-parse"] and cmd[2] == "HEAD":
                return self._fake_result(0, "aaa111\n")
            if cmd[:2] == ["git", "rev-parse"]:
                return self._fake_result(0, "bbb222\n")
            if cmd[:3] == ["git", "worktree", "add"]:
                tmp_path = Path(cmd[4])
                tmp_path.mkdir(parents=True, exist_ok=True)
                (tmp_path / "vpngate_manager.py").write_text("def broken(:\n", encoding="utf-8")
                return self._fake_result(0)
            return self._fake_result(0)

        result = manager.run_code_update_worker(
            install_dir=install_dir, runner=fake, panel_healthy=lambda h, p, t: True
        )
        self.assertFalse(result)
        status = manager.read_code_update_status()
        self.assertEqual("failed", status["result"])
        self.assertEqual("check", status["stage"])
        self.assertNotIn(["git", "checkout", "-B", "main", "origin/main"], calls)
        self.assertNotIn(["bash", "install.sh"], calls)

    def test_code_update_worker_post_checkout_failure_rolls_back(self) -> None:
        install_dir = self._make_install_dir("1.1.0")
        calls: list = []
        install_calls = []

        def fake(cmd, cwd, timeout, env=None):
            calls.append(list(cmd))
            if cmd[:2] == ["git", "rev-parse"] and cmd[2] == "HEAD":
                return self._fake_result(0, "aaa111\n")
            if cmd[:2] == ["git", "rev-parse"]:
                return self._fake_result(0, "bbb222\n")
            if cmd[:3] == ["git", "worktree", "add"]:
                tmp_path = Path(cmd[4])
                tmp_path.mkdir(parents=True, exist_ok=True)
                (tmp_path / "vpngate_manager.py").write_text("x = 1\n", encoding="utf-8")
                (tmp_path / "install.sh").write_text("#!/bin/bash\n", encoding="utf-8")
                return self._fake_result(0)
            if cmd == ["bash", "install.sh"]:
                install_calls.append(list(cmd))
                # First install fails (post-checkout failure); the rollback
                # reinstall succeeds.
                return self._fake_result(1 if len(install_calls) == 1 else 0, "", "install boom")
            return self._fake_result(0)

        result = manager.run_code_update_worker(
            install_dir=install_dir, runner=fake, panel_healthy=lambda h, p, t: True
        )
        self.assertFalse(result)
        status = manager.read_code_update_status()
        self.assertEqual("failed", status["result"])
        self.assertIn("已回滚", status["error"])
        self.assertEqual(2, len(install_calls))
        self.assertIn(["git", "checkout", "-B", "main", "aaa111"], calls)

    def test_code_update_worker_docker_branch_uses_compose(self) -> None:
        install_dir = self._make_install_dir("1.1.0")
        calls: list = []

        def fake(cmd, cwd, timeout, env=None):
            calls.append(list(cmd))
            return self._fake_result(0)

        with mock.patch.object(manager, "DEPLOYMENT_MODE", "docker"):
            result = manager.run_code_update_worker(
                install_dir=install_dir, runner=fake, panel_healthy=lambda h, p, t: True
            )
        self.assertTrue(result)
        self.assertIn(["docker", "compose", "pull"], calls)
        self.assertIn(["docker", "compose", "up", "-d"], calls)
        self.assertNotIn(["git", "checkout", "-B", "main", "origin/main"], calls)

    def test_spawn_code_updater_prefers_systemd_scope_and_falls_back(self) -> None:
        with (
            mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)) as run_mock,
            mock.patch("subprocess.Popen") as popen_mock,
        ):
            self.assertTrue(manager.spawn_code_updater())
            run_mock.assert_called_once()
            popen_mock.assert_not_called()
        with (
            mock.patch("subprocess.run", side_effect=FileNotFoundError("no systemd-run")),
            mock.patch("subprocess.Popen") as popen_mock,
        ):
            self.assertTrue(manager.spawn_code_updater())
            popen_mock.assert_called_once()
            _, kwargs = popen_mock.call_args
            self.assertTrue(kwargs.get("start_new_session"))

    def test_version_sync_1_2_2(self) -> None:
        self.assertEqual("1.2.2", manager.APP_VERSION)
        self.assertEqual("V1.2.2 正式版", manager.APP_VERSION_LABEL)
        self.assertIn("V1.2.2 正式版", manager.INDEX_HTML)
        install_text = (manager.ROOT_DIR / "install.sh").read_text(encoding="utf-8")
        self.assertIn('"1.2.2"', install_text)
        self.assertNotIn('"1.2.1"', install_text)
        compose_text = (manager.ROOT_DIR / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn(":1.2.2", compose_text)
        self.assertNotIn("1.2.1", compose_text)
        version_text = (manager.ROOT_DIR / "VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual("1.2.2", version_text)
        changelog = (manager.ROOT_DIR / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## V1.2.2", changelog)
        self.assertIn("## V1.2.1（2026-10-26，已发布正式版 v1.2.1）", changelog)
        self.assertIn("## V1.2.0（2026-10-26，已发布正式版 v1.2.0）", changelog)
        self.assertIn("## V1.1.0（2026-10-26，已发布正式版 v1.1.0）", changelog)


class RetentionEligibilityTests(unittest.TestCase):
    """Retained-pool selection filter (1.2.1).

    retention_eligible answers only "does this disappeared node match the
    current proxy-settings selection". It deliberately does NOT exempt
    favorites: the refresh merge exempts favorites before calling it, so a
    favorited node of a non-matching country still answers False here and
    is kept only by the merge's earlier favorite branch.
    """

    def test_fixed_region_matches_by_country_name(self) -> None:
        node = {"id": "uk1", "country": "United Kingdom", "country_short": "GB"}
        cfg = {"routing_mode": "fixed_region", "force_country": "United Kingdom"}
        self.assertTrue(manager.retention_eligible(node, cfg))

    def test_fixed_region_matches_by_country_short_code(self) -> None:
        node = {"id": "uk1", "country": "United Kingdom", "country_short": "GB"}
        cfg = {"routing_mode": "fixed_region", "force_country": "GB"}
        self.assertTrue(manager.retention_eligible(node, cfg))

    def test_fixed_region_non_matching_is_ineligible(self) -> None:
        node = {"id": "de1", "country": "Germany", "country_short": "DE"}
        cfg = {"routing_mode": "fixed_region", "force_country": "United Kingdom"}
        self.assertFalse(manager.retention_eligible(node, cfg))

    def test_fixed_region_empty_country_retains_all(self) -> None:
        node = {"id": "de1", "country": "Germany", "country_short": "DE"}
        cfg = {"routing_mode": "fixed_region", "force_country": ""}
        self.assertTrue(manager.retention_eligible(node, cfg))

    def test_fixed_ip_only_the_fixed_node_is_eligible(self) -> None:
        cfg = {"routing_mode": "fixed_ip", "fixed_node_id": "fixed1"}
        self.assertTrue(manager.retention_eligible({"id": "fixed1"}, cfg))
        self.assertFalse(manager.retention_eligible({"id": "other1"}, cfg))

    def test_fixed_ip_empty_id_retains_all(self) -> None:
        cfg = {"routing_mode": "fixed_ip", "fixed_node_id": ""}
        self.assertTrue(manager.retention_eligible({"id": "anything"}, cfg))

    def test_auto_mode_retains_all(self) -> None:
        # Auto means "no country restriction": unlike full_sweep_priority
        # (which returns False for every node in auto mode), retention
        # eligibility must not delete everything in auto mode.
        node = {"id": "de1", "country": "Germany", "country_short": "DE"}
        self.assertTrue(manager.retention_eligible(node, {"routing_mode": "auto"}))
        self.assertTrue(manager.retention_eligible(node, {}))

    def test_favorites_mode_retains_non_favorites(self) -> None:
        node = {"id": "plain1", "country": "Germany", "country_short": "DE"}
        cfg = {"routing_mode": "favorites", "favorite_node_ids": ["fav1"]}
        self.assertTrue(manager.retention_eligible(node, cfg))

    def test_eligibility_ignores_favorite_status_by_design(self) -> None:
        # A favorited node of a non-matching country answers False here;
        # the merge keeps it only because its favorite branch runs first.
        node = {"id": "fav1", "country": "France", "country_short": "FR"}
        cfg = {
            "routing_mode": "fixed_region",
            "force_country": "United Kingdom",
            "favorite_node_ids": ["fav1"],
        }
        self.assertFalse(manager.retention_eligible(node, cfg))

    def test_already_observing_non_matching_node_is_ineligible(self) -> None:
        # Q3: eligibility is evaluated on every refresh, so an observing
        # node that stops matching after a selection change is purged on
        # the next refresh instead of waiting out its grace period.
        node = {
            "id": "old1",
            "country": "Germany",
            "country_short": "DE",
            "retention_status": "observing",
        }
        cfg = {"routing_mode": "fixed_region", "force_country": "United Kingdom"}
        self.assertFalse(manager.retention_eligible(node, cfg))


class DetectionGatingTests(unittest.TestCase):
    """1.2.2 detection frequency (A): trigger + candidate-hash gating.

    The full-sweep priority order itself is untouched by this batch
    (full_sweep_order / full_sweep_priority); these tests prove the
    gating decision and that a skip keeps previous probe results.
    """

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.path_patches = [
            mock.patch.object(manager, "DATA_DIR", root),
            mock.patch.object(manager, "CONFIG_DIR", root / "configs"),
            mock.patch.object(manager, "NODES_FILE", root / "nodes.json"),
            mock.patch.object(manager, "STATE_FILE", root / "state.json"),
            mock.patch.object(manager, "AUTH_FILE", root / "auth.txt"),
            mock.patch.object(manager, "BLACKLIST_FILE", root / "blacklist.json"),
            mock.patch.object(manager, "API_CACHE_FILE", root / "api_snapshot.csv"),
            mock.patch.object(manager, "API_CACHE_META_FILE", root / "api_snapshot.meta.json"),
            mock.patch.object(manager, "BUNDLED_SNAPSHOT_FILE", root / "bundled_snapshot.csv"),
        ]
        for patcher in self.path_patches:
            patcher.start()
        manager.ensure_dirs()
        self._saved_restart_first = manager._first_maintain_after_startup
        manager.active_openvpn_process = None
        manager.active_openvpn_node_id = ""
        manager.is_connecting = False
        manager.full_sweep_running = False
        manager.full_sweep_cancel_requested = False

    def tearDown(self) -> None:
        manager._first_maintain_after_startup = self._saved_restart_first
        for patcher in reversed(self.path_patches):
            patcher.stop()
        self.temp_dir.cleanup()

    def _write_candidates(self, ids: list[str]) -> list[dict]:
        nodes = []
        for index, node_id in enumerate(ids):
            nodes.append(
                {
                    "id": node_id,
                    "ip": f"192.0.2.{index + 1}",
                    "country": "United Kingdom",
                    "country_short": "GB",
                    "ping": index + 1,
                    "score": 100,
                    "config_text": "client\nremote 192.0.2.1 1194 udp\n",
                    "config_file": str(manager.CONFIG_DIR / f"{node_id}.ovpn"),
                    "probe_status": "not_checked",
                    "probed_at": 0,
                    "active": False,
                }
            )
        manager.write_json(manager.NODES_FILE, nodes)
        return nodes

    def _run_maintain(self, candidates, trigger, restart_first):
        manager._first_maintain_after_startup = restart_first
        sweep_mock = mock.Mock(
            return_value={
                "skipped": False,
                "tested": 2,
                "available": 1,
                "unavailable": 1,
            }
        )
        with (
            mock.patch.object(manager, "fetch_candidates", return_value=candidates),
            mock.patch.object(manager, "active_openvpn_running", return_value=True),
            mock.patch.object(manager, "test_multiple_nodes", return_value=[]),
            mock.patch.object(manager, "sweep_retained_nodes", return_value=0),
            mock.patch.object(manager, "run_full_sweep", sweep_mock),
            mock.patch.object(manager, "log_to_json") as log_mock,
        ):
            message = manager.maintain_valid_nodes(force=False, trigger=trigger)
        return message, sweep_mock, log_mock

    def test_decision_manual_always_sweeps(self) -> None:
        self.assertTrue(manager.should_run_full_sweep("manual", False, False)[0])
        self.assertTrue(manager.should_run_full_sweep("manual", True, False)[0])

    def test_decision_check_always_sweeps(self) -> None:
        self.assertTrue(manager.should_run_full_sweep("check", False, False)[0])

    def test_decision_refill_never_sweeps(self) -> None:
        self.assertFalse(manager.should_run_full_sweep("refill", True, True)[0])
        self.assertFalse(manager.should_run_full_sweep("refill", False, False)[0])

    def test_decision_auto_sweeps_only_on_change_or_restart_first(self) -> None:
        self.assertTrue(manager.should_run_full_sweep("auto", True, False)[0])
        self.assertTrue(manager.should_run_full_sweep("auto", False, True)[0])
        self.assertTrue(manager.should_run_full_sweep("auto", True, True)[0])
        self.assertFalse(manager.should_run_full_sweep("auto", False, False)[0])
        # Unknown triggers are treated as auto, never as manual.
        self.assertFalse(manager.should_run_full_sweep("bogus", False, False)[0])
        self.assertTrue(manager.should_run_full_sweep("bogus", True, False)[0])

    def test_candidate_hash_ignores_fetch_order(self) -> None:
        nodes_a = [{"id": "b"}, {"id": "a"}]
        nodes_b = [{"id": "a"}, {"id": "b"}]
        self.assertEqual(
            manager._candidate_list_hash(nodes_a),
            manager._candidate_list_hash(nodes_b),
        )
        nodes_c = [{"id": "a"}, {"id": "c"}]
        self.assertNotEqual(
            manager._candidate_list_hash(nodes_a),
            manager._candidate_list_hash(nodes_c),
        )

    def test_auto_unchanged_list_skips_sweep_and_keeps_results(self) -> None:
        candidates = self._write_candidates(["node-a", "node-b"])
        message, sweep_mock, _ = self._run_maintain(candidates, "auto", True)
        self.assertEqual(1, sweep_mock.call_count)
        # Mark previous probe results, then run again with the same list.
        stored = manager.read_nodes()
        for node in stored:
            node["probe_status"] = "available"
        manager.write_json(manager.NODES_FILE, stored)
        message, sweep_mock, log_mock = self._run_maintain(candidates, "auto", False)
        sweep_mock.assert_not_called()
        self.assertIn("已跳过", message)
        self.assertIn("节点列表未变化", message)
        self.assertIn("已跳过", manager.get_state().get("last_check_message", ""))
        self.assertTrue(
            any("已跳过" in str(call) for call in log_mock.call_args_list)
        )
        stored = manager.read_nodes()
        self.assertTrue(all(n["probe_status"] == "available" for n in stored))

    def test_auto_changed_list_sweeps(self) -> None:
        candidates_a = self._write_candidates(["node-a", "node-b"])
        self._run_maintain(candidates_a, "auto", True)
        candidates_b = self._write_candidates(["node-a", "node-c"])
        _, sweep_mock, _ = self._run_maintain(candidates_b, "auto", False)
        self.assertEqual(1, sweep_mock.call_count)

    def test_manual_unchanged_list_still_sweeps(self) -> None:
        candidates = self._write_candidates(["node-a", "node-b"])
        self._run_maintain(candidates, "auto", True)
        _, sweep_mock, _ = self._run_maintain(candidates, "manual", False)
        self.assertEqual(1, sweep_mock.call_count)

    def test_refill_changed_list_never_sweeps(self) -> None:
        candidates_a = self._write_candidates(["node-a", "node-b"])
        self._run_maintain(candidates_a, "auto", True)
        candidates_b = self._write_candidates(["node-a", "node-c"])
        message, sweep_mock, _ = self._run_maintain(candidates_b, "refill", False)
        sweep_mock.assert_not_called()
        self.assertIn("已跳过", message)
        self.assertIn("后台补齐", message)

    def test_restart_first_unchanged_list_sweeps(self) -> None:
        candidates = self._write_candidates(["node-a", "node-b"])
        self._run_maintain(candidates, "auto", True)
        _, sweep_mock, _ = self._run_maintain(candidates, "auto", True)
        self.assertEqual(1, sweep_mock.call_count)

    def test_refill_does_not_consume_restart_first_flag(self) -> None:
        candidates = self._write_candidates(["node-a", "node-b"])
        message, sweep_mock, _ = self._run_maintain(candidates, "refill", True)
        sweep_mock.assert_not_called()
        self.assertTrue(manager._first_maintain_after_startup)
        _, sweep_mock, _ = self._run_maintain(candidates, "auto", True)
        self.assertEqual(1, sweep_mock.call_count)

    def test_sweep_priority_order_unchanged_by_gating(self) -> None:
        nodes = [
            {"id": "slow-other", "latency_ms": 500, "ping": 500},
            {"id": "gb-node", "latency_ms": 300, "ping": 300, "country": "United Kingdom", "country_short": "GB"},
            {"id": "fast-other", "latency_ms": 10, "ping": 10},
        ]
        ui_cfg = {"routing_mode": "fixed_region", "force_country": "United Kingdom"}
        ordered = [n["id"] for n in manager.full_sweep_order(nodes, ui_cfg)]
        self.assertEqual(["gb-node", "fast-other", "slow-other"], ordered)
        # Gating decisions do not mutate the node list or its order.
        for trigger in ("manual", "auto", "refill", "check"):
            manager.should_run_full_sweep(trigger, False, False)
        self.assertEqual(
            ["gb-node", "fast-other", "slow-other"],
            [n["id"] for n in manager.full_sweep_order(nodes, ui_cfg)],
        )


class CodeUpdateLastAttemptTests(unittest.TestCase):
    """1.2.2 one-click diagnostics: rejected attempts and last attempt.

    The status/last-attempt files are pointed at a per-test temp dir so
    these tests never touch the import-time temp dir shared by other
    test classes, and a rejected attempt can never overwrite a running
    status file (the two files are distinct paths).
    """

    def setUp(self) -> None:
        self._saved_is_connecting = manager.is_connecting
        self._saved_full_sweep = manager.full_sweep_running
        self._saved_data_dir = manager.DATA_DIR
        self._saved_status_file = manager.CODE_UPDATE_STATUS_FILE
        self._saved_last_attempt_file = manager.CODE_UPDATE_LAST_ATTEMPT_FILE
        self._tmp = tempfile.TemporaryDirectory()
        manager.DATA_DIR = Path(self._tmp.name)
        manager.CODE_UPDATE_STATUS_FILE = Path(self._tmp.name) / "code_update_status.json"
        manager.CODE_UPDATE_LAST_ATTEMPT_FILE = Path(self._tmp.name) / "code_update_last_attempt.json"
        manager.is_connecting = False
        manager.full_sweep_running = False

    def tearDown(self) -> None:
        manager.is_connecting = self._saved_is_connecting
        manager.full_sweep_running = self._saved_full_sweep
        manager.DATA_DIR = self._saved_data_dir
        manager.CODE_UPDATE_STATUS_FILE = self._saved_status_file
        manager.CODE_UPDATE_LAST_ATTEMPT_FILE = self._saved_last_attempt_file
        if manager.maintenance_lock.locked():
            manager.maintenance_lock.release()
        self._tmp.cleanup()

    def _log_text(self) -> str:
        logs_dir = Path(self._tmp.name) / "logs"
        if not logs_dir.exists():
            return ""
        text = ""
        for log_file in logs_dir.glob("*.json"):
            text += log_file.read_text(encoding="utf-8")
        return text

    def test_rejected_attempt_writes_log_and_last_attempt(self) -> None:
        reason = "已有面板更新正在进行中，请稍后查看更新状态"
        manager.record_code_update_rejected(reason, "1.2.2")
        last = manager.read_code_update_last_attempt()
        self.assertIsNotNone(last)
        self.assertEqual("not_started", last["result"])
        self.assertEqual(reason, last["reason"])
        self.assertFalse(manager.CODE_UPDATE_STATUS_FILE.exists())
        log_text = self._log_text()
        self.assertIn("CodeUpdate", log_text)
        self.assertIn(reason, log_text)

    def test_rejected_attempt_never_overwrites_running_status(self) -> None:
        manager.write_code_update_status(
            "running", "fetch", "正在拉取 main 分支…", "1.2.2", ""
        )
        manager.record_code_update_rejected("节点维护任务正在运行，请稍后再试更新", "1.2.2")
        status = manager.read_code_update_status()
        self.assertEqual("running", status["result"])
        self.assertEqual("fetch", status["stage"])
        self.assertEqual(
            "节点维护任务正在运行，请稍后再试更新",
            status["last_attempt"]["reason"],
        )

    def test_spawn_failure_logs_method_and_detail(self) -> None:
        manager.record_code_update_spawn_failure(
            "none", "systemd-run：返回码 1；setsid：权限不足", "1.2.2"
        )
        status = manager.read_code_update_status()
        self.assertEqual("failed", status["result"])
        self.assertEqual("无法启动更新器进程", status["error"])
        self.assertTrue(status["needs_terminal"])
        log_text = self._log_text()
        self.assertIn("CodeUpdate", log_text)
        self.assertIn("systemd-run", log_text)
        self.assertIn("setsid", log_text)

    def test_successful_start_clears_last_attempt(self) -> None:
        manager.record_code_update_rejected("请先在确认框中确认更新", "1.2.2")
        self.assertIsNotNone(manager.read_code_update_last_attempt())
        manager.clear_code_update_last_attempt()
        self.assertIsNone(manager.read_code_update_last_attempt())

    def test_spawn_detailed_reports_method(self) -> None:
        with (
            mock.patch.object(
                manager.subprocess, "run",
                return_value=mock.Mock(returncode=0),
            ),
            mock.patch.object(manager.subprocess, "Popen") as popen_mock,
        ):
            ok, method, detail = manager.spawn_code_updater_detailed()
        self.assertTrue(ok)
        self.assertEqual("systemd-run", method)
        self.assertEqual("", detail)
        popen_mock.assert_not_called()

        with (
            mock.patch.object(
                manager.subprocess, "run",
                return_value=mock.Mock(returncode=1),
            ),
            mock.patch.object(manager.subprocess, "Popen") as popen_mock,
        ):
            ok, method, detail = manager.spawn_code_updater_detailed()
        self.assertTrue(ok)
        self.assertEqual("setsid", method)
        popen_mock.assert_called_once()

        with (
            mock.patch.object(
                manager.subprocess, "run", side_effect=OSError("no systemd-run")
            ),
            mock.patch.object(
                manager.subprocess, "Popen", side_effect=OSError("no permission")
            ),
        ):
            ok, method, detail = manager.spawn_code_updater_detailed()
        self.assertFalse(ok)
        self.assertEqual("none", method)
        self.assertIn("systemd-run", detail)
        self.assertIn("setsid", detail)

    def test_frontend_poll_timeout_cancel_restore_markers(self) -> None:
        html = manager.INDEX_HTML
        self.assertIn("600000", html)
        self.assertIn("查看更新状态", html)
        self.assertIn("aimili_code_update_cancelled", html)
        self.assertIn("restoreCodeUpdateStatus", html)
        self.assertIn("上次已取消更新", html)
        self.assertNotIn("120000", html)
        self.assertNotIn("正在刷新页面以确认新版本", html)

class CodeUpdateWriteFailureTests(unittest.TestCase):
    """1.2.2 write-failure observability: a failed code-update write is
    never silent again. Status/log/last-attempt files are repointed to
    a per-test temp dir, and write_json is only ever faked to raise
    OSError (never to silently succeed), so no test touches real data."""

    def setUp(self) -> None:
        self._saved_data_dir = manager.DATA_DIR
        self._saved_status_file = manager.CODE_UPDATE_STATUS_FILE
        self._saved_log_file = manager.CODE_UPDATE_LOG_FILE
        self._saved_last_attempt_file = manager.CODE_UPDATE_LAST_ATTEMPT_FILE
        self._saved_deployment = manager.DEPLOYMENT_MODE
        self._tmp = tempfile.TemporaryDirectory()
        manager.DATA_DIR = Path(self._tmp.name)
        manager.CODE_UPDATE_STATUS_FILE = Path(self._tmp.name) / "code_update_status.json"
        manager.CODE_UPDATE_LOG_FILE = Path(self._tmp.name) / "code_update.log"
        manager.CODE_UPDATE_LAST_ATTEMPT_FILE = Path(self._tmp.name) / "code_update_last_attempt.json"
        manager.DEPLOYMENT_MODE = "source"

    def tearDown(self) -> None:
        manager.DATA_DIR = self._saved_data_dir
        manager.CODE_UPDATE_STATUS_FILE = self._saved_status_file
        manager.CODE_UPDATE_LOG_FILE = self._saved_log_file
        manager.CODE_UPDATE_LAST_ATTEMPT_FILE = self._saved_last_attempt_file
        manager.DEPLOYMENT_MODE = self._saved_deployment
        self._tmp.cleanup()

    def _log_text(self) -> str:
        logs_dir = Path(self._tmp.name) / "logs"
        if not logs_dir.exists():
            return ""
        text = ""
        for log_file in logs_dir.glob("*.json"):
            text += log_file.read_text(encoding="utf-8")
        return text

    def _make_install_dir(self, version: str = "1.1.0") -> Path:
        install_dir = Path(self._tmp.name) / "install"
        install_dir.mkdir(parents=True, exist_ok=True)
        (install_dir / ".git").mkdir(exist_ok=True)
        (install_dir / "VERSION").write_text(version + "\n", encoding="utf-8")
        return install_dir

    def _fake_result(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

    def test_append_log_returns_bool_and_reports_failure_to_stderr(self) -> None:
        self.assertTrue(manager._code_update_append_log("hello"))
        self.assertIn("hello", manager.CODE_UPDATE_LOG_FILE.read_text(encoding="utf-8"))
        with contextlib.redirect_stderr(io.StringIO()) as err:
            with mock.patch("builtins.open", side_effect=OSError("read-only (test)")):
                self.assertFalse(manager._code_update_append_log("lost"))
        self.assertIn("code_update.log", err.getvalue())
        self.assertIn("read-only (test)", err.getvalue())

    def test_status_write_reports_failure_and_keeps_entry_shape(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()) as err:
            with mock.patch.object(
                manager, "write_json", side_effect=OSError("disk full (test)")
            ):
                entry = manager.write_code_update_status(
                    "running", "fetch", "正在拉取 main 分支…", "1.2.2", ""
                )
        self.assertFalse(entry["status_ok"])
        self.assertTrue(entry["log_ok"])
        self.assertFalse(entry["write_ok"])
        self.assertEqual("running", entry["result"])
        self.assertEqual("fetch", entry["stage"])
        self.assertIn("code_update_status.json", err.getvalue())
        self.assertIn("disk full (test)", err.getvalue())
        self.assertIn("写入更新状态失败", self._log_text())

    def test_status_write_success_flags_and_file_content_unchanged(self) -> None:
        entry = manager.write_code_update_status(
            "running", "fetch", "正在拉取 main 分支…", "1.2.2", ""
        )
        self.assertTrue(entry["status_ok"])
        self.assertTrue(entry["log_ok"])
        self.assertTrue(entry["write_ok"])
        status = manager.read_code_update_status()
        self.assertEqual("running", status["result"])
        self.assertEqual("fetch", status["stage"])

    def test_last_attempt_write_reports_failure_to_stderr(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()) as err:
            with mock.patch.object(
                manager, "write_json", side_effect=OSError("disk full (test)")
            ):
                entry = manager.write_code_update_last_attempt(
                    "not_started", "测试原因", "1.2.2"
                )
        self.assertFalse(entry["write_ok"])
        self.assertIn("code_update_last_attempt.json", err.getvalue())
        self.assertIn("disk full (test)", err.getvalue())
        self.assertTrue(
            manager.write_code_update_last_attempt("not_started", "测试原因", "1.2.2")["write_ok"]
        )

    def test_clear_last_attempt_missing_is_ok_and_failure_reports(self) -> None:
        self.assertTrue(manager.clear_code_update_last_attempt())
        manager.write_code_update_last_attempt("not_started", "测试原因", "1.2.2")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            with mock.patch.object(
                Path, "unlink", side_effect=OSError("perm (test)")
            ):
                self.assertFalse(manager.clear_code_update_last_attempt())
        self.assertIn("code_update_last_attempt.json", err.getvalue())
        self.assertIn("perm (test)", err.getvalue())

    def test_start_refuses_to_spawn_when_initial_status_write_fails(self) -> None:
        with mock.patch.object(
            manager,
            "write_code_update_status",
            return_value={"status_ok": False, "log_ok": False, "write_ok": False},
        ):
            spawn_mock = mock.Mock()
            with mock.patch.object(manager, "spawn_code_updater_detailed", spawn_mock):
                started, error = manager.start_code_update_updater("1.2.2")
        self.assertFalse(started)
        self.assertIn("无法写入更新状态文件", error)
        spawn_mock.assert_not_called()
        last = manager.read_code_update_last_attempt()
        self.assertIsNotNone(last)
        self.assertEqual("not_started", last["result"])
        self.assertIn("无法写入更新状态文件", last["reason"])

    def test_start_success_and_spawn_failure_paths_unchanged(self) -> None:
        manager.record_code_update_rejected("请先在确认框中确认更新", "1.2.2")
        with mock.patch.object(
            manager, "spawn_code_updater_detailed", return_value=(True, "systemd-run", "")
        ):
            started, error = manager.start_code_update_updater("1.2.2")
        self.assertTrue(started)
        self.assertEqual("", error)
        self.assertIsNone(manager.read_code_update_last_attempt())
        status = manager.read_code_update_status()
        self.assertEqual("running", status["result"])
        self.assertEqual("starting", status["stage"])
        with mock.patch.object(
            manager, "spawn_code_updater_detailed", return_value=(False, "none", "boom")
        ):
            started, error = manager.start_code_update_updater("1.2.2")
        self.assertFalse(started)
        self.assertEqual("无法启动更新器进程", error)
        status = manager.read_code_update_status()
        self.assertEqual("failed", status["result"])
        self.assertEqual("无法启动更新器进程", status["error"])

    def test_worker_pre_overwrite_status_write_failure_aborts(self) -> None:
        install_dir = self._make_install_dir("1.1.0")
        calls: list = []
        original_write_json = manager.write_json
        state = {"status_calls": 0}

        def failing_write_json(path, data):
            if Path(path) == manager.CODE_UPDATE_STATUS_FILE:
                state["status_calls"] += 1
                if state["status_calls"] == 1:
                    raise OSError("disk full (test)")
            return original_write_json(path, data)

        def fake(cmd, cwd, timeout, env=None):
            calls.append(list(cmd))
            return self._fake_result(0)

        with contextlib.redirect_stderr(io.StringIO()) as err:
            with mock.patch.object(manager, "write_json", side_effect=failing_write_json):
                result = manager.run_code_update_worker(
                    install_dir=install_dir, runner=fake, panel_healthy=lambda h, p, t: True
                )
        self.assertFalse(result)
        self.assertEqual([], calls)
        status = manager.read_code_update_status()
        self.assertEqual("failed", status["result"])
        self.assertEqual("fetch", status["stage"])
        self.assertIn("无法写入更新状态文件", status["error"])
        self.assertIn("code_update_status.json", err.getvalue())
        self.assertIn("disk full (test)", err.getvalue())
        self.assertIn("写入更新状态失败", self._log_text())

    def test_worker_post_overwrite_status_write_failure_rolls_back(self) -> None:
        install_dir = self._make_install_dir("1.1.0")
        calls: list = []
        original_write_json = manager.write_json
        state = {"status_calls": 0}

        def failing_write_json(path, data):
            if Path(path) == manager.CODE_UPDATE_STATUS_FILE:
                state["status_calls"] += 1
                if state["status_calls"] == 4:
                    raise OSError("disk full (test)")
            return original_write_json(path, data)

        def fake(cmd, cwd, timeout, env=None):
            calls.append(list(cmd))
            if cmd[:2] == ["git", "rev-parse"] and cmd[2] == "HEAD":
                return self._fake_result(0, "aaa111\n")
            if cmd[:2] == ["git", "rev-parse"]:
                return self._fake_result(0, "bbb222\n")
            if cmd[:3] == ["git", "worktree", "add"]:
                tmp_path = Path(cmd[4])
                tmp_path.mkdir(parents=True, exist_ok=True)
                (tmp_path / "vpngate_manager.py").write_text("x = 1\n", encoding="utf-8")
                return self._fake_result(0)
            return self._fake_result(0)

        with contextlib.redirect_stderr(io.StringIO()) as err:
            with mock.patch.object(manager, "write_json", side_effect=failing_write_json):
                result = manager.run_code_update_worker(
                    install_dir=install_dir, runner=fake, panel_healthy=lambda h, p, t: True
                )
        self.assertFalse(result)
        # Status writes: 1 fetch, 2 check, 3 checkout, 4 install (failed),
        # then the rollback path records the failed status.
        self.assertEqual(5, state["status_calls"])
        self.assertIn(["git", "checkout", "-B", "main", "aaa111"], calls)
        self.assertIn(["git", "reset", "--hard", "aaa111"], calls)
        self.assertEqual(1, calls.count(["bash", "install.sh"]))
        status = manager.read_code_update_status()
        self.assertEqual("failed", status["result"])
        self.assertEqual("install", status["stage"])
        self.assertIn("无法写入更新状态文件", status["error"])
        self.assertIn("已回滚", status["error"])
        self.assertIn("code_update_status.json", err.getvalue())
        self.assertIn("已回滚", self._log_text())
