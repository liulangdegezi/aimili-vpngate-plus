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
import urllib.request
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
        self.assertEqual("1.2.7", manager.APP_VERSION)
        self.assertEqual("V1.2.7 正式版", manager.APP_VERSION_LABEL)
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
            "tag_name": "v1.2.4",
            "name": "AimiliVPN V1.2.4 正式版",
            "draft": False,
            "prerelease": False,
        }
        with mock.patch.object(manager, "fetch_api_text", return_value=json.dumps(release)):
            result = manager.check_latest_release()

        self.assertFalse(result["update_available"])
        self.assertEqual("V1.2.7 正式版", result["current_version_label"])

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
        self.assertEqual("1.2.7", result["current_version"])

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
        # 1.2.5 stage 4 supersedes the 1.2.0 deferred-scoring state:
        # the 查评分 button is live now, so the "暂未启用" tooltip is
        # gone and the row wires to the FFraud check endpoint instead.
        self.assertNotIn('title="暂未启用"', html)
        self.assertNotIn("评分功能为第三阶段，暂未启用", html)
        self.assertIn("/api/check_score", html)
        self.assertIn("checkNodeScore", html)
        self.assertIn("最长约 90 秒", html)
        self.assertIn("出口 IP 可能变化", html)
        self.assertIn("请用终端 ml update 重试", html)
        self.assertIn("600000", html)
        self.assertIn("aimili_code_update_done", html)

    def test_update_worker_never_touches_scoring_gate(self) -> None:
        source = (manager.ROOT_DIR / "vpngate_manager.py").read_text(encoding="utf-8")
        self.assertIn("/api/update_code", source)
        self.assertIn("/api/update_status", source)
        self.assertNotIn("iplark_qualified", source)
        self.assertNotIn("fetch_iplark_score", source)
        start = source.index("def run_code_update_worker")
        end = source.index("def spawn_code_updater")
        self.assertNotIn("iplark", source[start:end])
        # 1.2.5 stage 4 added a manual /api/check_score endpoint, but
        # the update worker itself must never touch the scoring path.
        self.assertNotIn("check_score", source[start:end])
        self.assertNotIn("risk_display", source[start:end])
        self.assertNotIn("ffraud", source[start:end].lower())

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
        # 1.2.7 revision (plan §三.1): "already latest" used to be a
        # sha-only verdict -- this fake originally answered every
        # non-git command with an empty success, i.e. NO process
        # signal at all, and the worker still reported success. That
        # is precisely the 1.2.6 false-success shape, so the old
        # assertion set cannot stand: the verdict is now two-
        # conditioned (sha equal AND the running process provably
        # serving the on-disk code). This test therefore supplies a
        # consistent process signal (systemd reports the service
        # started just now, after the VERSION file was written) and
        # keeps the original assertions verbatim: success, "已是最新",
        # no checkout, no install. The stale and unprovable shapes
        # are covered by Plus127Stage3UpdaterTests.
        install_dir = self._make_install_dir("1.1.0")
        calls: list = []

        def fake(cmd, cwd, timeout, env=None):
            calls.append(list(cmd))
            if cmd[:2] == ["systemctl", "show"]:
                mono_us = int(manager.time.monotonic() * 1_000_000)
                return self._fake_result(
                    0,
                    "MainPID=4242\n"
                    "ActiveEnterTimestamp=Mon 2026-11-03 10:00:00 UTC\n"
                    f"ExecMainStartTimestampMonotonic={mono_us}\n",
                )
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

    def test_version_sync_1_2_7(self) -> None:
        self.assertEqual("1.2.7", manager.APP_VERSION)
        self.assertEqual("V1.2.7 正式版", manager.APP_VERSION_LABEL)
        self.assertIn("V1.2.7 正式版", manager.INDEX_HTML)
        install_text = (manager.ROOT_DIR / "install.sh").read_text(encoding="utf-8")
        self.assertIn('"1.2.7"', install_text)
        self.assertNotIn('"1.2.2"', install_text)
        compose_text = (manager.ROOT_DIR / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn(":1.2.7", compose_text)
        self.assertNotIn("1.2.2", compose_text)
        version_text = (manager.ROOT_DIR / "VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual("1.2.7", version_text)
        changelog = (manager.ROOT_DIR / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## V1.2.7（2026-11-06，已发布正式版 v1.2.7）", changelog)
        self.assertIn("## V1.2.6（2026-11-05，已发布正式版 v1.2.6）", changelog)
        self.assertIn("## V1.2.5（2026-11-05，已发布正式版 v1.2.5）", changelog)
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


class SlimmingAndRetainedVisibilityTests(unittest.TestCase):
    """Regression tests for the 1.2.4 memory slimming + display switch."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.root = root
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
            mock.patch.object(manager, "RETAINED_ARCHIVE_FILE", root / "retained_archive.json"),
            mock.patch.object(manager.vpn_utils, "DATA_DIR", root),
            mock.patch.object(manager.vpn_utils, "IP_CACHE_FILE", root / "ip_cache.json"),
        ]
        for patcher in self.path_patches:
            patcher.start()
        manager.ensure_dirs()
        manager.active_openvpn_process = None
        manager.active_openvpn_node_id = ""
        manager.is_connecting = False
        manager.active_sessions.clear()

    def tearDown(self) -> None:
        manager.active_sessions.clear()
        for patcher in reversed(self.path_patches):
            patcher.stop()
        self.temp_dir.cleanup()

    @staticmethod
    def _archive_node(index: int) -> dict:
        return {
            "id": f"archive-node-{index}",
            "country": "Japan",
            "country_short": "JP",
            "ip": f"192.0.2.{index + 1}",
            "remote_host": f"192.0.2.{index + 1}",
            "remote_port": 1194,
            "proto": "udp",
            "ip_type": "residential",
            "config_text": f"client\nremote 192.0.2.{index + 1} 1194 udp\n",
            "config_file": f"/tmp/archive-node-{index}.ovpn",
            "last_seen_at": 1000 + index,
            "last_success_at": 900 + index,
        }

    def test_batch_archive_matches_repeated_single_archive_and_cap(self) -> None:
        initial = [
            {
                "id": f"existing-{index}",
                "country": "Japan",
                "config_text": "existing-config",
                "archived_at": 1,
                "reason": "existing",
            }
            for index in range(999)
        ]
        entries = [(self._archive_node(index), f"reason-{index}") for index in range(3)]

        single_path = self.root / "archive_single.json"
        batch_path = self.root / "archive_batch.json"
        with mock.patch.object(manager.time, "time", return_value=1234567890.0):
            with mock.patch.object(manager, "RETAINED_ARCHIVE_FILE", single_path):
                manager.write_json(single_path, initial)
                for node, reason in entries:
                    manager.archive_retained_node(node, reason)
            with mock.patch.object(manager, "RETAINED_ARCHIVE_FILE", batch_path):
                manager.write_json(batch_path, initial)
                archived = manager.archive_retained_nodes(entries)

        self.assertEqual(3, archived)
        self.assertEqual(single_path.read_bytes(), batch_path.read_bytes())
        batch_records = json.loads(batch_path.read_text(encoding="utf-8"))
        self.assertEqual(1000, len(batch_records))
        self.assertEqual("existing-2", batch_records[0]["id"])
        self.assertEqual(
            [f"archive-node-{index}" for index in range(3)],
            [record["id"] for record in batch_records[-3:]],
        )

    def test_write_json_streams_same_bytes_as_pretty_dumps(self) -> None:
        payload = {
            "name": "日本ノード",
            "items": [{"id": 1, "enabled": True}, {"id": 2, "note": None}],
            "empty": [],
        }
        target = self.root / "payload.json"

        manager.write_json(target, payload)

        self.assertEqual(
            json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"),
            target.read_bytes(),
        )
        self.assertEqual(payload, json.loads(target.read_text(encoding="utf-8")))

    def test_parsed_snapshot_config_is_reused_by_rows_to_candidates(self) -> None:
        rows = manager.parse_vpngate_rows(valid_snapshot())

        with (
            mock.patch.object(
                manager,
                "decode_config",
                side_effect=AssertionError("config was decoded a second time"),
            ),
            mock.patch.object(
                manager.snapshot_utils,
                "validate_openvpn_config",
                side_effect=AssertionError("config was validated a second time"),
            ),
        ):
            candidates = manager.rows_to_candidates(rows, {})

        self.assertEqual(1, len(candidates))
        # 1.2.6 stage 1 rewrite: candidate records no longer embed the
        # config (the old assertion read candidates[0]["config_text"]).
        # The reused parsed config must instead be retrievable verbatim
        # from the config store under the candidate's id.
        self.assertNotIn("config_text", candidates[0])
        self.assertIn(
            "remote 198.51.100.10 1194",
            manager.get_node_config(candidates[0]["id"]),
        )
        self.assertEqual(rows, [dict(row) for row in rows])

    def test_cache_api_snapshot_accepts_preparsed_rows_without_reparsing(self) -> None:
        text = valid_snapshot()
        rows = manager.parse_vpngate_rows(text)

        with mock.patch.object(
            manager.snapshot_utils,
            "parse_and_validate_snapshot",
            side_effect=AssertionError("snapshot was parsed a third time"),
        ):
            manager.cache_api_snapshot(text, "test-source", rows)

        meta = json.loads(manager.API_CACHE_META_FILE.read_text(encoding="utf-8"))
        self.assertEqual(text.encode("utf-8"), manager.API_CACHE_FILE.read_bytes())
        self.assertEqual("test-source", meta["source"])
        self.assertEqual(1, meta["row_count"])
        self.assertEqual(len(text.encode("utf-8")), meta["byte_count"])

    def test_retained_visibility_defaults_on_persists_and_filters_http_nodes(self) -> None:
        nodes = [
            {
                "id": "latest-node",
                "ip": "192.0.2.10",
                "remote_host": "192.0.2.10",
                "remote_port": 1194,
                "retention_status": "normal",
                "source_present": 1,
                "probe_status": "not_checked",
                "config_text": "latest-config",
                "config_file": str(manager.CONFIG_DIR / "latest-node.ovpn"),
                "active": False,
            },
            {
                "id": "retained-node",
                "ip": "192.0.2.11",
                "remote_host": "192.0.2.11",
                "remote_port": 1194,
                "retention_status": "observing",
                "source_present": 0,
                "probe_status": "not_checked",
                "config_text": "retained-config",
                "config_file": str(manager.CONFIG_DIR / "retained-node.ovpn"),
                "active": False,
            },
        ]
        manager.write_json(manager.NODES_FILE, nodes)
        self.assertTrue(manager.load_ui_config()["show_retained_pool_ips"])
        self.assertTrue(manager.get_state()["show_retained_pool_ips"])

        manager.active_sessions["slimming-test-token"] = manager.time.time() + 60
        server = manager.DualStackHTTPServer(("127.0.0.1", 0), manager.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}/EJsW2EeBo9lY"

        def request(path: str, payload: dict | None = None) -> tuple[int, dict]:
            data = None
            headers = {"Cookie": "session=slimming-test-token"}
            if payload is not None:
                data = json.dumps(payload).encode("utf-8")
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request(
                base_url + path,
                data=data,
                headers=headers,
                method="POST" if payload is not None else "GET",
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))

        try:
            status, default_payload = request("/api/nodes")
            self.assertEqual(200, status)
            self.assertTrue(default_payload["show_retained_pool_ips"])
            self.assertEqual(
                {"latest-node", "retained-node"},
                {node["id"] for node in default_payload["nodes"]},
            )

            status, off_payload = request(
                "/api/update_retained_pool_visibility",
                {"show_retained_pool_ips": False},
            )
            self.assertEqual(200, status)
            self.assertFalse(off_payload["show_retained_pool_ips"])
            self.assertFalse(manager.load_ui_config()["show_retained_pool_ips"])

            status, filtered_payload = request("/api/nodes")
            self.assertEqual(200, status)
            self.assertFalse(filtered_payload["show_retained_pool_ips"])
            self.assertFalse(filtered_payload["state"]["show_retained_pool_ips"])
            self.assertEqual(
                ["latest-node"],
                [node["id"] for node in filtered_payload["nodes"]],
            )

            status, retained_payload = request("/api/retained")
            self.assertEqual(200, status)
            self.assertEqual(
                ["retained-node"],
                [node["id"] for node in retained_payload["retained"]],
            )

            status, on_payload = request(
                "/api/update_retained_pool_visibility",
                {"show_retained_pool_ips": True},
            )
            self.assertEqual(200, status)
            self.assertTrue(on_payload["show_retained_pool_ips"])
            status, restored_payload = request("/api/nodes")
            self.assertEqual(200, status)
            self.assertEqual(
                {"latest-node", "retained-node"},
                {node["id"] for node in restored_payload["nodes"]},
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


class Plus124ScopedSweepAndPersistenceTests(unittest.TestCase):
    """1.2.4: connection-country-scoped full sweep + post-switch
    re-sweep, batched probe persistence, allocator trim helper, and
    the /api/retained archive-count cache."""

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
            mock.patch.object(manager, "RETAINED_ARCHIVE_FILE", root / "retained_archive.json"),
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
        manager._switch_watch_last_id = ""
        manager.clear_switch_sweep_pending()
        manager._retained_count_cache["key"] = None
        manager._retained_count_cache["count"] = 0

    def tearDown(self) -> None:
        manager._first_maintain_after_startup = self._saved_restart_first
        manager.active_openvpn_node_id = ""
        manager._switch_watch_last_id = ""
        manager.clear_switch_sweep_pending()
        manager._retained_count_cache["key"] = None
        manager._retained_count_cache["count"] = 0
        for patcher in reversed(self.path_patches):
            patcher.stop()
        self.temp_dir.cleanup()

    def _node(self, node_id: str, country_short: str, **extra) -> dict:
        node = {
            "id": node_id,
            "ip": "192.0.2.1",
            "remote_host": "192.0.2.1",
            "remote_port": 1194,
            "country": country_short,
            "country_short": country_short,
            "ping": 10,
            "latency_ms": 10,
            "config_text": "client\nremote 192.0.2.1 1194 udp\n",
            "config_file": str(manager.CONFIG_DIR / f"{node_id}.ovpn"),
            "probe_status": "not_checked",
            "probed_at": 0,
            "consecutive_failures": 0,
            "active": False,
        }
        node.update(extra)
        return node

    # -- Scope 1: sweep scoping -------------------------------------

    def test_sweep_only_tests_connection_country(self) -> None:
        nodes = [
            self._node("jp-active", "JP", active=True),
            self._node("jp-1", "JP"),
            self._node("jp-2", "JP"),
            self._node("us-1", "US"),
            self._node("kr-1", "KR"),
        ]
        manager.write_json(manager.NODES_FILE, nodes)
        manager.active_openvpn_node_id = "jp-active"
        captured = {}

        def fake_test_multiple(ids, target_available=None, stop_requested=None):
            captured["ids"] = list(ids)
            return [
                {"id": "jp-1", "probe_status": "available"},
                {"id": "jp-2", "probe_status": "unavailable"},
            ]

        with (
            mock.patch.object(manager, "load_ui_config", return_value={"routing_mode": "auto"}),
            mock.patch.object(manager, "test_multiple_nodes", side_effect=fake_test_multiple),
        ):
            result = manager.run_full_sweep()
        self.assertEqual({"jp-1", "jp-2"}, set(captured["ids"]))
        self.assertEqual(2, result["tested"])
        self.assertEqual(1, result["available"])
        self.assertEqual(1, result["unavailable"])
        self.assertIn("全量检测完成（JP）", manager.get_state().get("last_check_message", ""))

    def test_sweep_skips_without_connection(self) -> None:
        manager.write_json(
            manager.NODES_FILE,
            [self._node("jp-1", "JP"), self._node("us-1", "US")],
        )
        with mock.patch.object(manager, "test_multiple_nodes") as test_mock:
            result = manager.run_full_sweep()
        test_mock.assert_not_called()
        self.assertTrue(result["skipped"])
        self.assertEqual("no_connection", result["skip_reason"])
        self.assertEqual(
            "无当前连接，跳过全量检测",
            manager.get_state().get("last_check_message", ""),
        )

    def test_sweep_scoped_country_with_only_active_node(self) -> None:
        manager.write_json(
            manager.NODES_FILE,
            [self._node("jp-active", "JP", active=True), self._node("us-1", "US")],
        )
        manager.active_openvpn_node_id = "jp-active"
        with mock.patch.object(manager, "test_multiple_nodes") as test_mock:
            result = manager.run_full_sweep()
        test_mock.assert_not_called()
        self.assertFalse(result["skipped"])
        self.assertEqual(0, result["tested"])

    # -- Scope 1: switch observation / gating ------------------------

    def test_switch_pending_lifecycle_and_gating(self) -> None:
        manager.write_json(
            manager.NODES_FILE,
            [
                self._node("jp-a", "JP", active=True),
                self._node("jp-b", "JP"),
                self._node("us-a", "US"),
            ],
        )
        manager.active_openvpn_node_id = "jp-a"
        self.assertEqual("JP", manager.pending_switch_sweep_country())
        # Same-country switch coalesces to one pending entry (new id).
        manager.active_openvpn_node_id = "jp-b"
        self.assertEqual("JP", manager.pending_switch_sweep_country())
        self.assertEqual(("jp-b", "JP"), manager._switch_sweep_pending)
        # A later switch replaces the pending country.
        manager.active_openvpn_node_id = "us-a"
        self.assertEqual("US", manager.pending_switch_sweep_country())
        # Gating: the switch reason fires for auto, refill vetoes it.
        self.assertEqual(
            (True, "连接切换后补检（US）"),
            manager.should_run_full_sweep("auto", False, False, switch_country="US"),
        )
        self.assertFalse(
            manager.should_run_full_sweep("refill", True, True, switch_country="US")[0]
        )
        # Late re-evaluation upgrades an auto skip, never a refill.
        self.assertEqual(
            (True, "连接切换后补检（US）"),
            manager._late_switch_sweep("auto", False, "节点列表未变化"),
        )
        self.assertEqual(
            (False, "节点列表未变化"),
            manager._late_switch_sweep("refill", False, "节点列表未变化"),
        )
        # Consumption clears the marker; no new switch -> nothing pending.
        manager.clear_switch_sweep_pending()
        self.assertEqual("", manager.pending_switch_sweep_country())

    def test_scoped_hash_ignores_other_country_list_changes(self) -> None:
        def cand(node_id: str, country_short: str) -> dict:
            return self._node(node_id, country_short)

        active = self._node("gb-active", "GB", active=True)
        manager.write_json(
            manager.NODES_FILE,
            [active, cand("gb-a", "GB"), cand("gb-b", "GB"), cand("us-x", "US")],
        )
        manager.active_openvpn_node_id = "gb-active"

        def run_maintain(candidates, restart_first):
            manager._first_maintain_after_startup = restart_first
            sweep_mock = mock.Mock(
                return_value={"skipped": False, "tested": 2, "available": 1, "unavailable": 1}
            )
            with (
                mock.patch.object(manager, "fetch_candidates", return_value=candidates),
                mock.patch.object(manager, "active_openvpn_running", return_value=True),
                mock.patch.object(manager, "test_multiple_nodes", return_value=[]),
                mock.patch.object(manager, "sweep_retained_nodes", return_value=0),
                mock.patch.object(manager, "run_full_sweep", sweep_mock),
                mock.patch.object(manager, "log_to_json"),
            ):
                message = manager.maintain_valid_nodes(force=False, trigger="auto")
            return message, sweep_mock

        # Round 1 (restart-first): sweeps and stores the GB-scoped hash.
        _, sweep_mock = run_maintain(
            [cand("gb-a", "GB"), cand("gb-b", "GB"), cand("us-x", "US")], True
        )
        self.assertEqual(1, sweep_mock.call_count)
        # Round 2: only the US part of the list changed -> no sweep.
        message, sweep_mock = run_maintain(
            [cand("gb-a", "GB"), cand("gb-b", "GB"), cand("us-y", "US")], False
        )
        sweep_mock.assert_not_called()
        self.assertIn("已跳过", message)
        # Round 3: the GB part changed -> sweep again.
        _, sweep_mock = run_maintain(
            [cand("gb-a", "GB"), cand("gb-c", "GB"), cand("us-y", "US")], False
        )
        self.assertEqual(1, sweep_mock.call_count)

    # -- Scope 4: archive-count cache --------------------------------

    def test_retained_archive_count_cache_hit_and_invalidation(self) -> None:
        archive_path = manager.RETAINED_ARCHIVE_FILE
        manager.write_json(archive_path, [{"id": "a"}, {"id": "b"}, {"id": "c"}])
        self.assertEqual(3, manager.retained_archive_count())
        # Cache hit: a second call must not re-read the file at all.
        with mock.patch.object(
            manager, "read_json", side_effect=AssertionError("cache miss re-read")
        ):
            self.assertEqual(3, manager.retained_archive_count())
        # File changed (append one record) -> key changes -> recount.
        manager.write_json(archive_path, [{"id": "a"}, {"id": "b"}, {"id": "c"}, {"id": "d"}])
        self.assertEqual(4, manager.retained_archive_count())
        # Missing file -> 0, matching the previous read_json default.
        archive_path.unlink()
        self.assertEqual(0, manager.retained_archive_count())

    # -- Scope 3: batched probe persistence --------------------------

    def _write_probe_nodes(self, count: int, failures: int = 0) -> list[dict]:
        nodes = []
        for index in range(count):
            nodes.append(
                self._node(
                    f"node-{index}",
                    "JP",
                    consecutive_failures=failures,
                    note=f"orig-{index}",
                )
            )
        manager.write_json(manager.NODES_FILE, nodes)
        return nodes

    def test_probe_batch_flush_merges_concurrent_changes(self) -> None:
        nodes = self._write_probe_nodes(6, failures=4)
        calls = {"n": 0}

        def fake_openvpn(config_file, **kwargs):
            calls["n"] += 1
            if calls["n"] == 3:
                # A concurrent writer (e.g. the panel) edits non-probe
                # fields of two rows directly on disk mid-batch.
                raw = json.loads(manager.NODES_FILE.read_text(encoding="utf-8"))
                for row in raw:
                    if row["id"] == "node-0":
                        row["note"] = "changed-during-batch"
                    if row["id"] == "node-1":
                        row["owner"] = "concurrent-writer"
                manager.NODES_FILE.write_text(
                    json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8"
                )
            return True, "ready", None

        write_calls = {"nodes": 0}
        real_write_json = manager.write_json

        def counting_write_json(path, data):
            if Path(path) == manager.NODES_FILE:
                write_calls["nodes"] += 1
            return real_write_json(path, data)

        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(manager.vpn_utils, "enrich_ip_info"),
            mock.patch.object(manager, "run_openvpn_until_ready", side_effect=fake_openvpn),
            mock.patch.object(manager, "write_json", side_effect=counting_write_json),
            mock.patch.object(manager, "NODE_PROBE_WORKERS", 5),
        ):
            results = manager.test_multiple_nodes([n["id"] for n in nodes])
        self.assertEqual(6, len(results))
        stored = {n["id"]: n for n in manager.read_nodes()}
        for index in range(6):
            self.assertEqual("available", stored[f"node-{index}"]["probe_status"])
            # Success zeroes the failure counter exactly once.
            self.assertEqual(0, stored[f"node-{index}"]["consecutive_failures"])
            self.assertGreater(stored[f"node-{index}"].get("last_success_at", 0), 0)
        # Concurrent non-probe edits survived every flush.
        self.assertEqual("changed-during-batch", stored["node-0"]["note"])
        self.assertEqual("concurrent-writer", stored["node-1"]["owner"])
        self.assertEqual("orig-2", stored["node-2"]["note"])
        # Batched persistence: a handful of table writes, not one per
        # marker plus one per result (which would be 2 + 6 + 1 = 9).
        self.assertLessEqual(write_calls["nodes"], 3)

    def test_probe_batch_interrupt_flushes_and_counts_failures_once(self) -> None:
        nodes = self._write_probe_nodes(12, failures=2)

        def fake_openvpn(config_file, **kwargs):
            return False, "Connection reset by peer", None

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
                [n["id"] for n in nodes],
                target_available=None,
                stop_requested=stop_requested,
            )
        # Only the first batch ran; its results were still flushed on
        # the interrupt exit path.
        self.assertEqual(5, len(results))
        stored = {n["id"]: n for n in manager.read_nodes()}
        tested = [n for n in stored.values() if n["probe_status"] == "unavailable"]
        untested = [n for n in stored.values() if n["probe_status"] == "not_checked"]
        self.assertEqual(5, len(tested))
        self.assertEqual(7, len(untested))
        for node in tested:
            # 2 + exactly one increment -- the exit flush and the final
            # merge flush must not double-count.
            self.assertEqual(3, node["consecutive_failures"])

    # -- Scope 2: allocator helper -----------------------------------

    def test_malloc_trim_helper_callable(self) -> None:
        result = manager.malloc_trim()
        self.assertIsInstance(result, bool)
        # Second call (cached handle / unavailable latch) also safe.
        self.assertIsInstance(manager.malloc_trim(), bool)


class Plus125PoolSwitchAndUpdaterTests(unittest.TestCase):
    """1.2.5 stages 1+2: retained-pool mechanism switch (persist-first
    purge, favorite exemption, vanish gate, liveness-sweep skip) and
    one-click update verification (process baseline/freshness,
    main-vs-Release consistency, install-output tracing, verified
    installer restart). Worker tests inject fake runners/checks, so
    no real git, install, systemctl, or network is touched."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.root = root
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
            mock.patch.object(manager, "RETAINED_ARCHIVE_FILE", root / "retained_archive.json"),
            mock.patch.object(manager, "CODE_UPDATE_STATUS_FILE", root / "code_update_status.json"),
            mock.patch.object(manager, "CODE_UPDATE_LOG_FILE", root / "code_update.log"),
            mock.patch.object(manager, "CODE_UPDATE_LAST_ATTEMPT_FILE", root / "code_update_last_attempt.json"),
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
        manager._retained_count_cache["key"] = None
        manager._retained_count_cache["count"] = 0
        manager.active_sessions.clear()

    def tearDown(self) -> None:
        manager._first_maintain_after_startup = self._saved_restart_first
        manager.active_openvpn_node_id = ""
        manager._retained_count_cache["key"] = None
        manager._retained_count_cache["count"] = 0
        manager.active_sessions.clear()
        for patcher in reversed(self.path_patches):
            patcher.stop()
        self.temp_dir.cleanup()

    # -- helpers -----------------------------------------------------

    def _pool_node(self, node_id: str, status: str = "normal", active: bool = False) -> dict:
        return {
            "id": node_id,
            "ip": "192.0.2.1",
            "remote_host": "192.0.2.1",
            "remote_port": 1194,
            "country": "Japan",
            "country_short": "JP",
            "ping": 10,
            "latency_ms": 10,
            "config_text": "client\nremote 192.0.2.1 1194 udp\n",
            "config_file": str(manager.CONFIG_DIR / f"{node_id}.ovpn"),
            "probe_status": "not_checked",
            "probed_at": 0,
            "consecutive_failures": 0,
            "retention_status": status,
            "source_present": 0 if status == "observing" else 1,
            "active": active,
            "last_seen_at": manager.time.time(),
        }

    def _set_favorites(self, ids: list) -> None:
        cfg = manager.load_ui_config()
        cfg["favorite_node_ids"] = list(ids)
        manager.write_json(manager.DATA_DIR / "ui_auth.json", cfg)

    def _run_maintain(self, candidates):
        manager._first_maintain_after_startup = True
        retained_sweep = mock.Mock(return_value=0)
        sweep_mock = mock.Mock(
            return_value={"skipped": False, "tested": 0, "available": 0, "unavailable": 0}
        )
        with (
            mock.patch.object(manager, "fetch_candidates", return_value=candidates),
            mock.patch.object(manager, "active_openvpn_running", return_value=True),
            mock.patch.object(manager, "test_multiple_nodes", return_value=[]),
            mock.patch.object(manager, "sweep_retained_nodes", retained_sweep),
            mock.patch.object(manager, "run_full_sweep", sweep_mock),
            mock.patch.object(manager, "log_to_json"),
        ):
            message = manager.maintain_valid_nodes(force=False, trigger="auto")
        return message, retained_sweep

    def _fake_result(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

    def _make_update_install_dir(self, version: str = "1.2.4") -> Path:
        install_dir = self.root / "install"
        install_dir.mkdir(parents=True, exist_ok=True)
        (install_dir / ".git").mkdir(exist_ok=True)
        (install_dir / "VERSION").write_text(version + "\n", encoding="utf-8")
        return install_dir

    def _update_fake(self, pid_mode: str, worktree_version: str | None):
        """Fake updater runner. pid_mode: "change" (install swaps the
        MainPID), "same" (install leaves the old process running --
        the 1.2.4 false success), "no-systemd" (systemctl unusable)."""
        state = {"pid": 111, "ts": "Mon 2026-11-03 10:00:00 UTC", "installs": 0}
        calls: list = []

        def fake(cmd, cwd, timeout, env=None):
            calls.append(list(cmd))
            if cmd[:2] == ["systemctl", "show"]:
                if pid_mode == "no-systemd":
                    return self._fake_result(1, "", "System has not been booted with systemd")
                return self._fake_result(
                    0, f"MainPID={state['pid']}\nActiveEnterTimestamp={state['ts']}\n"
                )
            if cmd[:2] == ["git", "rev-parse"] and cmd[2] == "HEAD":
                return self._fake_result(0, "aaa111\n")
            if cmd[:2] == ["git", "rev-parse"]:
                return self._fake_result(0, "bbb222\n")
            if cmd[:3] == ["git", "worktree", "add"]:
                tmp_path = Path(cmd[4])
                tmp_path.mkdir(parents=True, exist_ok=True)
                (tmp_path / "vpngate_manager.py").write_text("x = 1\n", encoding="utf-8")
                (tmp_path / "install.sh").write_text("#!/bin/bash\n", encoding="utf-8")
                if worktree_version:
                    (tmp_path / "VERSION").write_text(
                        worktree_version + "\n", encoding="utf-8"
                    )
                return self._fake_result(0)
            if cmd == ["bash", "install.sh"]:
                state["installs"] += 1
                if state["installs"] == 1 and pid_mode == "change":
                    state["pid"] = 222
                    state["ts"] = "Mon 2026-11-03 10:05:00 UTC"
                return self._fake_result(0, "install output line\n", "")
            return self._fake_result(0)

        return fake, calls, state

    # -- Stage 1: retained-pool mechanism switch ---------------------

    def test_pool_switch_defaults_on_and_persists(self) -> None:
        # Fresh config: default ON (no behavior change for old users).
        self.assertTrue(manager.load_ui_config()["retained_pool_enabled"])
        self.assertTrue(manager.get_state()["retained_pool_enabled"])
        # Legacy ui_auth.json without the key: loads as ON and the key
        # is backfilled into the file.
        auth_path = manager.DATA_DIR / "ui_auth.json"
        manager.write_json(
            auth_path,
            {"username": "legacy-user", "password": "legacy-pass", "secret_path": "EJsW2EeBo9lY"},
        )
        self.assertTrue(manager.load_ui_config()["retained_pool_enabled"])
        self.assertIn(
            "retained_pool_enabled",
            json.loads(auth_path.read_text(encoding="utf-8")),
        )
        # Persistence round-trip through the persist helper + state.
        self.assertFalse(manager.persist_retained_pool_enabled(False))
        self.assertFalse(manager.load_ui_config()["retained_pool_enabled"])
        self.assertFalse(manager.get_state()["retained_pool_enabled"])
        self.assertTrue(manager.persist_retained_pool_enabled(True))
        self.assertTrue(manager.load_ui_config()["retained_pool_enabled"])
        with self.assertRaises(ValueError):
            manager.persist_retained_pool_enabled("yes")

    def test_pool_disable_purges_observing_keeps_favorites_and_active(self) -> None:
        observing_ids = [f"obs-{i}" for i in range(30)]
        favorite_ids = [f"fav-obs-{i}" for i in range(3)]
        nodes = [self._pool_node(nid, status="observing") for nid in observing_ids]
        nodes += [self._pool_node(nid, status="observing") for nid in favorite_ids]
        nodes.append(self._pool_node("active-1", status="normal", active=True))
        nodes.append(self._pool_node("normal-1"))
        nodes.append(self._pool_node("normal-2"))
        manager.write_json(manager.NODES_FILE, nodes)
        self._set_favorites(favorite_ids)

        outcome = manager.disable_retained_pool()

        self.assertEqual({"archived": 30, "kept_favorites": 3}, outcome)
        # The flag is persisted OFF as part of the same action.
        self.assertFalse(manager.load_ui_config()["retained_pool_enabled"])
        stored = {n["id"]: n for n in manager.read_nodes()}
        for nid in observing_ids:
            self.assertNotIn(nid, stored)
        for nid in favorite_ids:
            self.assertIn(nid, stored)
            self.assertEqual("normal", stored[nid]["retention_status"])
        self.assertIn("active-1", stored)
        self.assertIn("normal-1", stored)
        self.assertIn("normal-2", stored)
        archive = manager.read_json(manager.RETAINED_ARCHIVE_FILE, [])
        self.assertEqual(30, len(archive))
        self.assertEqual(set(observing_ids), {r["id"] for r in archive})
        self.assertTrue(all(r["reason"] == "retained-pool-disabled" for r in archive))
        self.assertEqual(30, manager.retained_archive_count())

    def test_pool_off_vanish_archives_immediately_and_skips_liveness_sweep(self) -> None:
        table = [
            self._pool_node("keep-1"),
            self._pool_node("gone-1"),
            self._pool_node("fav-1", status="observing"),
        ]
        manager.write_json(manager.NODES_FILE, table)
        self._set_favorites(["fav-1"])
        manager.persist_retained_pool_enabled(False)

        _, retained_sweep = self._run_maintain([self._pool_node("keep-1")])

        stored = {n["id"]: n for n in manager.read_nodes()}
        self.assertIn("keep-1", stored)
        self.assertNotIn("gone-1", stored)
        # Favorite exemption is identical with the pool OFF.
        self.assertIn("fav-1", stored)
        self.assertEqual("normal", stored["fav-1"]["retention_status"])
        archive = manager.read_json(manager.RETAINED_ARCHIVE_FILE, [])
        self.assertEqual(1, len(archive))
        self.assertEqual("gone-1", archive[0]["id"])
        self.assertEqual("retained-pool-disabled-vanish", archive[0]["reason"])
        # The 12h liveness sweep does not run at all while OFF.
        retained_sweep.assert_not_called()

    def test_pool_on_vanish_still_observes_and_sweeps(self) -> None:
        table = [
            self._pool_node("keep-1"),
            self._pool_node("gone-1"),
            self._pool_node("fav-1", status="observing"),
        ]
        manager.write_json(manager.NODES_FILE, table)
        self._set_favorites(["fav-1"])
        self.assertTrue(manager.load_ui_config()["retained_pool_enabled"])

        _, retained_sweep = self._run_maintain([self._pool_node("keep-1")])

        stored = {n["id"]: n for n in manager.read_nodes()}
        self.assertEqual("observing", stored["gone-1"]["retention_status"])
        self.assertEqual([], manager.read_json(manager.RETAINED_ARCHIVE_FILE, []))
        retained_sweep.assert_called()

    def test_pool_reopen_does_not_restore_archived(self) -> None:
        manager.write_json(
            manager.NODES_FILE,
            [self._pool_node("keep-1"), self._pool_node("gone-2")],
        )
        manager.persist_retained_pool_enabled(False)
        self._run_maintain([self._pool_node("keep-1")])
        self.assertEqual(
            ["gone-2"],
            [r["id"] for r in manager.read_json(manager.RETAINED_ARCHIVE_FILE, [])],
        )
        # Reopen: flag only; the archived node stays archived, and a
        # node disappearing afterwards observes under the normal rules.
        manager.persist_retained_pool_enabled(True)
        manager.write_json(
            manager.NODES_FILE,
            [self._pool_node("keep-1"), self._pool_node("gone-3")],
        )
        self._run_maintain([self._pool_node("keep-1")])
        stored = {n["id"]: n for n in manager.read_nodes()}
        self.assertNotIn("gone-2", stored)
        self.assertEqual("observing", stored["gone-3"]["retention_status"])
        self.assertEqual(
            ["gone-2"],
            [r["id"] for r in manager.read_json(manager.RETAINED_ARCHIVE_FILE, [])],
        )

    def test_pool_switch_http_endpoint(self) -> None:
        favorite_ids = ["fav-obs-0"]
        nodes = [
            self._pool_node("obs-a", status="observing"),
            self._pool_node("obs-b", status="observing"),
            self._pool_node("fav-obs-0", status="observing"),
            self._pool_node("normal-1"),
        ]
        manager.write_json(manager.NODES_FILE, nodes)
        self._set_favorites(favorite_ids)

        manager.active_sessions["plus125-test-token"] = manager.time.time() + 60
        server = manager.DualStackHTTPServer(("127.0.0.1", 0), manager.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}/EJsW2EeBo9lY"

        def request(path: str, payload: dict | None = None) -> tuple[int, dict]:
            data = None
            headers = {"Cookie": "session=plus125-test-token"}
            if payload is not None:
                data = json.dumps(payload).encode("utf-8")
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request(
                base_url + path,
                data=data,
                headers=headers,
                method="POST" if payload is not None else "GET",
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    return response.status, json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read().decode("utf-8"))

        try:
            status, off_payload = request(
                "/api/update_retained_pool", {"retained_pool_enabled": False}
            )
            self.assertEqual(200, status)
            self.assertTrue(off_payload["ok"])
            self.assertFalse(off_payload["retained_pool_enabled"])
            self.assertEqual(2, off_payload["archived"])
            self.assertEqual(1, off_payload["kept_favorites"])
            self.assertIn("已归档移除 2 个", off_payload["message"])

            status, nodes_payload = request("/api/nodes")
            self.assertEqual(200, status)
            self.assertFalse(nodes_payload["retained_pool_enabled"])
            self.assertFalse(nodes_payload["state"]["retained_pool_enabled"])

            status, bad_payload = request(
                "/api/update_retained_pool", {"retained_pool_enabled": "yes"}
            )
            self.assertEqual(400, status)
            self.assertFalse(bad_payload["ok"])

            status, on_payload = request(
                "/api/update_retained_pool", {"retained_pool_enabled": True}
            )
            self.assertEqual(200, status)
            self.assertTrue(on_payload["retained_pool_enabled"])
            self.assertTrue(manager.load_ui_config()["retained_pool_enabled"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_panel_pool_switch_and_update_ui_markers(self) -> None:
        html = manager.INDEX_HTML
        self.assertIn('id="retained_pool_enabled"', html)
        self.assertIn("toggleRetainedPoolEnabled", html)
        self.assertIn("updateRetainedPoolEnabledUI", html)
        self.assertIn("保留池已关闭", html)
        self.assertIn("立即归档并移除当前", html)
        # Stage 2 UI: side-by-side update actions + Father's wording.
        self.assertIn('class="update-action-row"', html)
        self.assertIn(".update-action-row", html)
        self.assertIn("检测到新版本", html)
        self.assertIn("请点击一键更新，或者登录后台用 ml 命令更新", html)

    # -- Stage 2: updater verification -------------------------------

    def test_worker_stale_process_fails_and_needs_terminal(self) -> None:
        install_dir = self._make_update_install_dir("1.2.4")
        fake, calls, state = self._update_fake("same", "1.2.7")
        result = manager.run_code_update_worker(
            install_dir=install_dir,
            runner=fake,
            panel_healthy=lambda h, p, t: True,
            release_check=lambda: {
                "ok": True, "latest_version": "1.2.7", "no_release": False,
            },
        )
        self.assertFalse(result)
        status = manager.read_code_update_status()
        self.assertEqual("failed", status["result"])
        self.assertEqual("health", status["stage"])
        self.assertTrue(status["needs_terminal"])
        self.assertIn("已回滚", status["error"])
        self.assertIn("服务重启未生效", status["error"])
        self.assertIn("systemctl restart aimilivpn", status["error"])
        # Forward install + rollback reinstall both ran.
        self.assertEqual(2, state["installs"])
        # The install output was traced even though the update failed.
        log_text = manager.CODE_UPDATE_LOG_FILE.read_text(encoding="utf-8")
        self.assertIn("安装脚本输出尾部", log_text)
        self.assertIn("install output line", log_text)

    def test_worker_fresh_process_succeeds_and_traces_install_output(self) -> None:
        install_dir = self._make_update_install_dir("1.2.4")
        fake, calls, state = self._update_fake("change", "1.2.7")
        result = manager.run_code_update_worker(
            install_dir=install_dir,
            runner=fake,
            panel_healthy=lambda h, p, t: True,
            release_check=lambda: {
                "ok": True, "latest_version": "1.2.7", "no_release": False,
            },
        )
        self.assertTrue(result)
        status = manager.read_code_update_status()
        self.assertEqual("success", status["result"])
        self.assertIn("更新完成，当前版本", status["message"])
        self.assertNotIn("降级核验", status["message"])
        # Baseline + freshness both consulted systemd via the runner.
        systemctl_calls = [c for c in calls if c[:2] == ["systemctl", "show"]]
        self.assertGreaterEqual(len(systemctl_calls), 2)
        log_text = manager.CODE_UPDATE_LOG_FILE.read_text(encoding="utf-8")
        self.assertIn("更新前服务基线", log_text)
        self.assertIn("安装脚本输出尾部", log_text)
        self.assertIn("install output line", log_text)
        # ... and an excerpt rides in the status log tail.
        self.assertIn("安装输出尾部节选：", status["log_tail"])
        self.assertIn("install output line", status["log_tail"])

    def test_worker_degraded_verification_when_systemd_unreadable(self) -> None:
        install_dir = self._make_update_install_dir("1.2.4")
        fake, calls, state = self._update_fake("no-systemd", "1.2.7")
        result = manager.run_code_update_worker(
            install_dir=install_dir,
            runner=fake,
            panel_healthy=lambda h, p, t: True,
            release_check=lambda: {
                "ok": True, "latest_version": "1.2.7", "no_release": False,
            },
            panel_http_check=lambda h, p, t: True,
        )
        self.assertTrue(result)
        status = manager.read_code_update_status()
        self.assertEqual("success", status["result"])
        self.assertIn("降级核验", status["message"])

    def test_worker_main_release_mismatch_aborts_before_checkout(self) -> None:
        install_dir = self._make_update_install_dir("1.2.4")
        fake, calls, state = self._update_fake("change", "9.9.9")
        result = manager.run_code_update_worker(
            install_dir=install_dir,
            runner=fake,
            panel_healthy=lambda h, p, t: True,
            release_check=lambda: {
                "ok": True, "latest_version": "1.2.7", "no_release": False,
            },
        )
        self.assertFalse(result)
        status = manager.read_code_update_status()
        self.assertEqual("failed", status["result"])
        self.assertEqual("check", status["stage"])
        self.assertIn("不一致", status["error"])
        self.assertIn("未发布代码", status["error"])
        # Zero changes to the live tree: no checkout, no install.
        self.assertNotIn(["git", "checkout", "-B", "main", "origin/main"], calls)
        self.assertNotIn(["bash", "install.sh"], calls)

    def test_worker_release_check_unreachable_aborts(self) -> None:
        install_dir = self._make_update_install_dir("1.2.4")
        fake, calls, state = self._update_fake("change", "1.2.7")

        def broken_release_check():
            raise RuntimeError("network down (test)")

        result = manager.run_code_update_worker(
            install_dir=install_dir,
            runner=fake,
            panel_healthy=lambda h, p, t: True,
            release_check=broken_release_check,
        )
        self.assertFalse(result)
        status = manager.read_code_update_status()
        self.assertEqual("failed", status["result"])
        self.assertEqual("check", status["stage"])
        self.assertIn("已中止更新", status["error"])
        self.assertNotIn(["git", "checkout", "-B", "main", "origin/main"], calls)
        self.assertNotIn(["bash", "install.sh"], calls)

    def test_installer_restart_is_verified_not_swallowed(self) -> None:
        install_text = (manager.ROOT_DIR / "install.sh").read_text(encoding="utf-8")
        self.assertIn("OLD_SERVICE_PID", install_text)
        self.assertIn("INSTALL_START_EPOCH", install_text)
        self.assertIn("restart_service_verified", install_text)
        self.assertIn("安装中止", install_text)
        self.assertNotIn("systemctl restart aimilivpn.service || true", install_text)
        self.assertNotIn("rc-service aimilivpn restart || true", install_text)
        result = subprocess.run(
            ["bash", "-n", str(manager.ROOT_DIR / "install.sh")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)


class Plus127Stage3UpdaterTests(unittest.TestCase):
    """1.2.7 stage 3: panel one-click update flow (plan §三).

    The "already latest" verdict is two-conditioned (sha equality
    AND the running process provably serving the on-disk code); a
    stale or unprovable process resumes the unfinished update from
    the install stage. Spawn method and install runs are traced to
    the update log, and a single-instance flock keeps two live
    workers from interleaving verdicts. All tests inject fake
    runners, so no real git, install, systemctl, or network runs.
    """

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.root = root
        self.path_patches = [
            mock.patch.object(manager, "DATA_DIR", root),
            mock.patch.object(manager, "CODE_UPDATE_STATUS_FILE", root / "code_update_status.json"),
            mock.patch.object(manager, "CODE_UPDATE_LOG_FILE", root / "code_update.log"),
            mock.patch.object(manager, "CODE_UPDATE_LAST_ATTEMPT_FILE", root / "code_update_last_attempt.json"),
        ]
        for patcher in self.path_patches:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.path_patches):
            patcher.stop()
        self.temp_dir.cleanup()

    def _fake_result(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        return mock.Mock(returncode=returncode, stdout=stdout, stderr=stderr)

    def _make_update_install_dir(self, version: str = "1.2.7") -> Path:
        install_dir = self.root / "install"
        install_dir.mkdir(parents=True, exist_ok=True)
        (install_dir / ".git").mkdir(exist_ok=True)
        (install_dir / "VERSION").write_text(version + "\n", encoding="utf-8")
        return install_dir

    def _stale_mono_us(self) -> int:
        """A monotonic timestamp safely in the past: minutes before
        the just-written install files, without going negative on a
        freshly booted test machine (monotonic is uptime-based)."""
        mono = manager.time.monotonic()
        delta = 120.0 if mono > 240 else mono / 2
        return int((mono - delta) * 1_000_000)

    def _resume_fake(self, process_mode: str):
        """Fake runner; git always reports local == remote.

        process_mode: "stale" (the service process started before
        the disk code was written; the install replaces it),
        "consistent" (the service started just now, after the disk
        code), "no-systemd" (systemctl unusable throughout).
        """
        state = {"pid": 111, "ts": "Mon 2026-11-03 10:00:00 UTC", "installs": 0}
        calls: list = []

        def fake(cmd, cwd, timeout, env=None):
            calls.append(list(cmd))
            if cmd[:2] == ["systemctl", "show"]:
                if process_mode == "no-systemd":
                    return self._fake_result(1, "", "System has not been booted with systemd")
                if process_mode == "consistent" or state["installs"]:
                    mono_us = int(manager.time.monotonic() * 1_000_000)
                else:
                    mono_us = self._stale_mono_us()
                return self._fake_result(
                    0,
                    f"MainPID={state['pid']}\n"
                    f"ActiveEnterTimestamp={state['ts']}\n"
                    f"ExecMainStartTimestampMonotonic={mono_us}\n",
                )
            if cmd[:2] == ["git", "rev-parse"]:
                return self._fake_result(0, "aaa111\n")
            if cmd == ["bash", "install.sh"]:
                state["installs"] += 1
                if process_mode == "stale":
                    state["pid"] = 222
                    state["ts"] = "Mon 2026-11-03 11:00:00 UTC"
                return self._fake_result(0, "resume install output\n", "")
            return self._fake_result(0)

        return fake, calls, state

    def _log_text(self) -> str:
        if not manager.CODE_UPDATE_LOG_FILE.exists():
            return ""
        return manager.CODE_UPDATE_LOG_FILE.read_text(encoding="utf-8")

    # -- Task ①: sha equal but the process is stale -> resume ------

    def test_resume_completes_unfinished_update_when_process_stale(self) -> None:
        install_dir = self._make_update_install_dir("1.2.7")
        fake, calls, state = self._resume_fake("stale")
        result = manager.run_code_update_worker(
            install_dir=install_dir,
            runner=fake,
            panel_healthy=lambda h, p, t: True,
        )
        self.assertTrue(result)
        status = manager.read_code_update_status()
        self.assertEqual("success", status["result"])
        self.assertIn("补完", status["message"])
        self.assertIn("1.2.7", status["message"])
        # The install ran exactly once, with verification ...
        self.assertEqual(1, state["installs"])
        # ... and neither checkout nor the temp-worktree stage ran:
        # the disk tree already was the target commit.
        self.assertNotIn(["git", "checkout", "-B", "main", "origin/main"], calls)
        self.assertFalse(any(c[:3] == ["git", "worktree", "add"] for c in calls))
        # Log identifiability: resume markers present, and (task ④)
        # the install pre-marker precedes the install output tail.
        log_text = self._log_text()
        self.assertIn("[resume]", log_text)
        self.assertIn("补完未竟更新", log_text)
        self.assertLess(
            log_text.index("开始执行 install.sh"),
            log_text.index("安装脚本输出尾部"),
        )

    # -- Task ②: sha equal and the process is consistent -----------

    def test_already_latest_requires_consistent_process(self) -> None:
        install_dir = self._make_update_install_dir("1.2.7")
        fake, calls, state = self._resume_fake("consistent")
        result = manager.run_code_update_worker(
            install_dir=install_dir,
            runner=fake,
            panel_healthy=lambda h, p, t: True,
        )
        self.assertTrue(result)
        status = manager.read_code_update_status()
        self.assertEqual("success", status["result"])
        self.assertIn("已是最新", status["message"])
        self.assertEqual(0, state["installs"])
        self.assertNotIn(["bash", "install.sh"], calls)
        self.assertNotIn(["git", "checkout", "-B", "main", "origin/main"], calls)

    # -- Task ⑤: consistency unprovable -> never "already latest" --

    def test_unprovable_process_resumes_instead_of_reporting_latest(self) -> None:
        install_dir = self._make_update_install_dir("1.2.7")
        fake, calls, state = self._resume_fake("no-systemd")
        result = manager.run_code_update_worker(
            install_dir=install_dir,
            runner=fake,
            panel_healthy=lambda h, p, t: True,
            panel_http_check=lambda h, p, t: True,
        )
        self.assertTrue(result)
        status = manager.read_code_update_status()
        self.assertEqual("success", status["result"])
        self.assertNotIn("已是最新", status["message"])
        # It resumed (install executed) and the verdict degraded
        # honestly instead of claiming full process proof.
        self.assertEqual(1, state["installs"])
        self.assertIn("补完", status["message"])
        self.assertIn("降级核验", status["message"])

    # -- Task ③: spawn method is traced to the update log ----------

    def test_spawn_methods_are_traced_to_update_log(self) -> None:
        with (
            mock.patch.object(manager.subprocess, "run", return_value=mock.Mock(returncode=0)),
            mock.patch.object(manager.subprocess, "Popen") as popen_mock,
        ):
            ok, method, detail = manager.spawn_code_updater_detailed()
        self.assertTrue(ok)
        self.assertEqual("systemd-run", method)
        popen_mock.assert_not_called()
        log_text = self._log_text()
        self.assertIn("systemd-run scope 成功", log_text)

        manager.CODE_UPDATE_LOG_FILE.write_text("", encoding="utf-8")
        with (
            mock.patch.object(manager.subprocess, "run", return_value=mock.Mock(returncode=1)),
            mock.patch.object(manager.subprocess, "Popen") as popen_mock,
        ):
            ok, method, detail = manager.spawn_code_updater_detailed()
        self.assertTrue(ok)
        self.assertEqual("setsid", method)
        popen_mock.assert_called_once()
        log_text = self._log_text()
        self.assertIn("systemd-run 失败", log_text)
        self.assertIn("返回码 1", log_text)
        self.assertIn("回退 setsid", log_text)

    # -- Single-instance guard --------------------------------------

    def test_second_worker_exits_without_touching_status_when_lock_held(self) -> None:
        handle, contended = manager._code_update_try_acquire_worker_lock()
        self.assertIsNotNone(handle)
        self.assertFalse(contended)
        try:
            fake, calls, state = self._resume_fake("consistent")
            result = manager.run_code_update_worker(
                install_dir=self._make_update_install_dir("1.2.7"),
                runner=fake,
                panel_healthy=lambda h, p, t: True,
            )
            self.assertFalse(result)
            self.assertEqual([], calls)
            # The losing worker writes NO status at all: it can
            # neither fake a success nor clobber the live record.
            self.assertFalse(manager.CODE_UPDATE_STATUS_FILE.exists())
            self.assertIn("已有另一个更新器进程正在运行", self._log_text())
        finally:
            handle.close()
        # The lock is free again once the holder lets go.
        handle2, contended2 = manager._code_update_try_acquire_worker_lock()
        self.assertIsNotNone(handle2)
        self.assertFalse(contended2)
        handle2.close()

    # -- The consistency signal itself -------------------------------

    def test_process_disk_consistency_verdicts(self) -> None:
        install_dir = self._make_update_install_dir("1.2.7")

        def systemd_run(mono_delta_seconds: float):
            def run(cmd, cwd, timeout, env=None):
                mono_us = int((manager.time.monotonic() + mono_delta_seconds) * 1_000_000)
                return self._fake_result(
                    0,
                    "MainPID=111\n"
                    "ActiveEnterTimestamp=Mon 2026-11-03 10:00:00 UTC\n"
                    f"ExecMainStartTimestampMonotonic={mono_us}\n",
                )
            return run

        verdict, _ = manager._code_update_process_disk_consistency(
            systemd_run(0), install_dir
        )
        self.assertEqual("consistent", verdict)
        mono = manager.time.monotonic()
        stale_delta = -120.0 if mono > 240 else -(mono / 2)
        verdict, _ = manager._code_update_process_disk_consistency(
            systemd_run(stale_delta), install_dir
        )
        self.assertEqual("stale", verdict)

        def no_systemd(cmd, cwd, timeout, env=None):
            return self._fake_result(1, "", "not booted with systemd")

        verdict, _ = manager._code_update_process_disk_consistency(
            no_systemd, install_dir
        )
        self.assertEqual("unknown", verdict)

        def no_monotonic(cmd, cwd, timeout, env=None):
            return self._fake_result(
                0, "MainPID=111\nActiveEnterTimestamp=Mon 2026-11-03 10:00:00 UTC\n"
            )

        verdict, _ = manager._code_update_process_disk_consistency(
            no_monotonic, install_dir
        )
        self.assertEqual("unknown", verdict)


class Plus126Stage2CoffeeScoreTests(unittest.TestCase):
    """1.2.6 stage 2: risk-score source swap FFraud -> IP Coffee
    (plan §一/§二/§八), replacing the 1.2.5 stage-4 FFraud tests.

    Scores still land in risk_display_* fields; the iplark_score hook
    stays None and composite ordering must be identical before/after
    a check. IP Coffee's trust_score is stored converted (risk =
    100 - trust, plan §八.1); FFraud-era records are voided on first
    read (plan §八.2). All network access is faked (opener injection),
    so no test in this class ever leaves the machine.
    """

    # Fixtures live inside the repo (tests/fixtures/coffee_samples) so
    # the suite is self-contained anywhere it is checked out; the
    # pre-1.2.5 path pointed outside the repo at the developer's goal
    # hidden_files and failed in CI with FileNotFoundError.
    SAMPLES_DIR = (
        Path(__file__).resolve().parent / "fixtures" / "coffee_samples"
    )

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.root = root
        self.path_patches = [
            mock.patch.object(manager, "DATA_DIR", root),
            mock.patch.object(manager, "CONFIG_DIR", root / "configs"),
            mock.patch.object(manager, "CONFIG_STORE_FILE", root / "node_configs.json"),
            mock.patch.object(manager, "NODES_FILE", root / "nodes.json"),
            mock.patch.object(manager, "STATE_FILE", root / "state.json"),
            mock.patch.object(manager, "AUTH_FILE", root / "auth.txt"),
            mock.patch.object(manager, "BLACKLIST_FILE", root / "blacklist.json"),
            mock.patch.object(manager, "API_CACHE_FILE", root / "api_snapshot.csv"),
            mock.patch.object(manager, "API_CACHE_META_FILE", root / "api_snapshot.meta.json"),
            mock.patch.object(manager, "BUNDLED_SNAPSHOT_FILE", root / "bundled_snapshot.csv"),
            mock.patch.object(manager, "RETAINED_ARCHIVE_FILE", root / "retained_archive.json"),
            mock.patch.object(manager, "CODE_UPDATE_STATUS_FILE", root / "code_update_status.json"),
            mock.patch.object(manager, "CODE_UPDATE_LOG_FILE", root / "code_update.log"),
            mock.patch.object(manager, "CODE_UPDATE_LAST_ATTEMPT_FILE", root / "code_update_last_attempt.json"),
        ]
        for patcher in self.path_patches:
            patcher.start()
        manager.ensure_dirs()
        manager._config_store_cache["key"] = None
        manager._config_store_cache["data"] = {}
        manager.active_openvpn_process = None
        manager.active_openvpn_node_id = ""
        manager.is_connecting = False
        manager.full_sweep_running = False
        manager.full_sweep_cancel_requested = False
        manager._retained_count_cache["key"] = None
        manager._retained_count_cache["count"] = 0
        manager.active_sessions.clear()
        manager._risk_check_inflight.clear()

    def tearDown(self) -> None:
        manager._risk_check_inflight.clear()
        manager.active_openvpn_node_id = ""
        manager._config_store_cache["key"] = None
        manager._config_store_cache["data"] = {}
        manager._retained_count_cache["key"] = None
        manager._retained_count_cache["count"] = 0
        manager.active_sessions.clear()
        for patcher in reversed(self.path_patches):
            patcher.stop()
        self.temp_dir.cleanup()

    # -- helpers -----------------------------------------------------

    def _sample(self, name: str) -> dict:
        return json.loads(
            (self.SAMPLES_DIR / f"sample_{name}.json").read_text(encoding="utf-8")
        )

    def _score_node(self, node_id: str, ip: str, **overrides) -> dict:
        node = {
            "id": node_id,
            "ip": ip,
            "remote_host": ip,
            "remote_port": 1194,
            "country": "Japan",
            "country_short": "JP",
            "ping": 10,
            "latency_ms": 10,
            "score": 100,
            "config_text": "client\nremote 192.0.2.1 1194 udp\n",
            "config_file": str(manager.CONFIG_DIR / f"{node_id}.ovpn"),
            "probe_status": "available",
            "probed_at": 0,
            "consecutive_failures": 0,
            "retention_status": "normal",
            "source_present": 1,
            "active": False,
            "last_seen_at": manager.time.time(),
            "iplark_score": None,
            **manager.RISK_DISPLAY_DEFAULTS,
            "risk_display_flags": [],
        }
        node.update(overrides)
        return node

    class _FakeResponse:
        def __init__(self, body: bytes, status: int = 200) -> None:
            self._body = body
            self.status = status

        def read(self) -> bytes:
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def _fake_opener(self, responder):
        """Patch the manager's fetch opener with a recording fake.

        fetch_coffee_score builds its opener via the manager-level
        _coffee_build_opener() seam, so ONLY the coffee fetch is
        faked; the shared urllib.request module (used by this class's
        own HTTP test client) is never touched. responder(url) ->
        _FakeResponse, or raises. Returns the list of requested URLs
        so tests can assert on (non-)network activity.
        """
        calls: list = []

        class _Opener:
            def open(self, request, timeout=None):
                url = getattr(request, "full_url", str(request))
                calls.append(url)
                return responder(url)

        patcher = mock.patch.object(
            manager, "_coffee_build_opener", return_value=_Opener()
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        return calls

    def _run_maintain(self, candidates):
        manager._first_maintain_after_startup = True
        with (
            mock.patch.object(manager, "fetch_candidates", return_value=candidates),
            mock.patch.object(manager, "active_openvpn_running", return_value=True),
            mock.patch.object(manager, "test_multiple_nodes", return_value=[]),
            mock.patch.object(manager, "sweep_retained_nodes", return_value=0),
            mock.patch.object(
                manager, "run_full_sweep",
                return_value={"skipped": True, "tested": 0, "available": 0, "unavailable": 0},
            ),
            mock.patch.object(manager, "log_to_json"),
        ):
            return manager.maintain_valid_nodes(force=False, trigger="auto")

    # -- parsing of the archived real samples -------------------------

    def test_parse_clean_sample(self) -> None:
        parsed = manager.parse_coffee_response(
            self._sample("clean_8.8.8.8"), "8.8.8.8"
        )
        # trust_score 63 -> risk 37 (plan §八.1 conversion).
        self.assertEqual(37, parsed["risk_display_score"])
        self.assertEqual("", parsed["risk_display_level"])
        self.assertEqual("机房", parsed["risk_display_connection_type"])
        # flags/reason are no longer produced at all (plan §一.2).
        self.assertEqual(
            {"risk_display_score", "risk_display_level",
             "risk_display_connection_type"},
            set(parsed),
        )

    def test_parse_vpn_sample(self) -> None:
        parsed = manager.parse_coffee_response(
            self._sample("vpn_1.1.1.1"), "1.1.1.1"
        )
        # trust_score 41 -> risk 59; the payload's own flags say
        # datacenter (the sample is Cloudflare DNS), so 机房.
        self.assertEqual(59, parsed["risk_display_score"])
        self.assertEqual("", parsed["risk_display_level"])
        self.assertEqual("机房", parsed["risk_display_connection_type"])

    def test_parse_tor_sample(self) -> None:
        parsed = manager.parse_coffee_response(
            self._sample("tor_185.220.101.34"), "185.220.101.34"
        )
        # trust_score 39 -> risk 61; abuser_score "1 (Very High)"
        # yields the tier text; is_tor outranks is_proxy/isResidential.
        self.assertEqual(61, parsed["risk_display_score"])
        self.assertEqual("Very High", parsed["risk_display_level"])
        self.assertEqual("Tor 出口", parsed["risk_display_connection_type"])

    def test_ip_type_label_priority(self) -> None:
        def label(**fields):
            payload = {
                "ip": "8.8.8.8", "trust_score": 50, "abuser_score": "",
                "is_tor": False, "is_proxy": False, "is_vpn": False,
                "is_mobile": False, "isResidential": False,
                "is_datacenter": False, "company_type": "",
            }
            payload.update(fields)
            return manager.coffee_ip_type_label(payload)

        self.assertEqual("未知", label())
        self.assertEqual("机房", label(company_type="hosting"))
        self.assertEqual("机房", label(is_datacenter=True))
        self.assertEqual("企业", label(company_type="business"))
        self.assertEqual("运营商", label(company_type="isp"))
        self.assertEqual("住宅", label(isResidential=True))
        self.assertEqual("移动网络", label(is_mobile=True))
        self.assertEqual("VPN", label(is_vpn=True))
        self.assertEqual("代理", label(is_proxy=True))
        self.assertEqual("Tor 出口", label(is_tor=True))
        # Priority conflicts, plan §一.3 order.
        self.assertEqual(
            "Tor 出口",
            label(is_tor=True, is_proxy=True, isResidential=True),
        )
        self.assertEqual("代理", label(is_proxy=True, is_vpn=True))
        self.assertEqual("VPN", label(is_vpn=True, is_mobile=True))
        self.assertEqual(
            "移动网络", label(is_mobile=True, isResidential=True)
        )
        self.assertEqual(
            "住宅", label(isResidential=True, is_datacenter=True)
        )
        self.assertEqual(
            "住宅", label(isResidential=True, company_type="hosting")
        )
        self.assertEqual(
            "机房", label(is_datacenter=True, company_type="business")
        )

    def test_parse_score_boundaries(self) -> None:
        low = manager.parse_coffee_response(
            {"ip": "8.8.8.8", "trust_score": 0}, "8.8.8.8"
        )
        self.assertEqual(100, low["risk_display_score"])
        self.assertEqual("未知", low["risk_display_connection_type"])
        self.assertEqual("", low["risk_display_level"])
        high = manager.parse_coffee_response(
            {"ip": "8.8.8.8", "trust_score": 100}, "8.8.8.8"
        )
        self.assertEqual(0, high["risk_display_score"])

    # -- response guards ------------------------------------------------

    def test_parse_guards_reject_bad_payloads(self) -> None:
        base = self._sample("clean_8.8.8.8")
        cases = {
            "not a dict": ["not", "a", "dict"],
            "trust_score missing": {
                k: v for k, v in base.items() if k != "trust_score"
            },
            "trust_score too high": {**base, "trust_score": 101},
            "trust_score negative": {**base, "trust_score": -1},
            "trust_score is bool": {**base, "trust_score": True},
            "trust_score is string": {**base, "trust_score": "63"},
            "ip mismatch": {**base, "ip": "1.1.1.1"},
            "ip missing": {k: v for k, v in base.items() if k != "ip"},
        }
        for label, payload in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(manager.RiskScoreFetchError) as ctx:
                    manager.parse_coffee_response(payload, "8.8.8.8")
                self.assertEqual(
                    manager.RISK_ERROR_BAD_RESPONSE, ctx.exception.category
                )

    # -- fetch: validation first, then guarded transport ----------------

    def test_fetch_rejects_invalid_targets_without_network(self) -> None:
        calls = self._fake_opener(
            lambda url: self._FakeResponse(b"{}")  # must never be reached
        )
        for target in (
            "notanip", "example.com", "", "999.1.1.1",
            "10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1",
            "172.16.0.5", "::1", "fe80::1", "0.0.0.0",
        ):
            with self.subTest(target=target):
                with self.assertRaises(manager.RiskScoreFetchError) as ctx:
                    manager.fetch_coffee_score(target)
                self.assertEqual(
                    manager.RISK_ERROR_TARGET_INVALID, ctx.exception.category
                )
        self.assertEqual([], calls)

    def test_fetch_success_uses_direct_api_url(self) -> None:
        body = json.dumps(self._sample("clean_8.8.8.8")).encode("utf-8")
        calls = self._fake_opener(lambda url: self._FakeResponse(body))
        parsed = manager.fetch_coffee_score("8.8.8.8")
        self.assertEqual(37, parsed["risk_display_score"])
        self.assertEqual(
            ["https://ip.net.coffee/api/ipv2/lookup/8.8.8.8"], calls
        )

    def test_fetch_http_error_is_rejected_category(self) -> None:
        def responder(url):
            raise urllib.error.HTTPError(url, 403, "Forbidden", None, None)

        self._fake_opener(responder)
        with self.assertRaises(manager.RiskScoreFetchError) as ctx:
            manager.fetch_coffee_score("8.8.8.8")
        self.assertEqual(manager.RISK_ERROR_REJECTED, ctx.exception.category)

    def test_fetch_non_200_status_is_rejected_category(self) -> None:
        self._fake_opener(
            lambda url: self._FakeResponse(b"{}", status=503)
        )
        with self.assertRaises(manager.RiskScoreFetchError) as ctx:
            manager.fetch_coffee_score("8.8.8.8")
        self.assertEqual(manager.RISK_ERROR_REJECTED, ctx.exception.category)

    def test_fetch_network_error_category(self) -> None:
        def responder(url):
            raise urllib.error.URLError("connection refused")

        self._fake_opener(responder)
        with self.assertRaises(manager.RiskScoreFetchError) as ctx:
            manager.fetch_coffee_score("8.8.8.8")
        self.assertEqual(manager.RISK_ERROR_NETWORK, ctx.exception.category)

    def test_fetch_malformed_json_is_bad_response(self) -> None:
        self._fake_opener(lambda url: self._FakeResponse(b"<html>nope</html>"))
        with self.assertRaises(manager.RiskScoreFetchError) as ctx:
            manager.fetch_coffee_score("8.8.8.8")
        self.assertEqual(manager.RISK_ERROR_BAD_RESPONSE, ctx.exception.category)

    # -- endpoint orchestration (function level) -------------------------

    def test_check_success_writes_display_fields_only(self) -> None:
        manager.write_json(
            manager.NODES_FILE,
            [self._score_node("score-1", "8.8.8.8"),
             self._score_node("other-1", "203.0.113.7")],
        )
        fake_fields = manager.parse_coffee_response(
            self._sample("clean_8.8.8.8"), "8.8.8.8"
        )
        with mock.patch.object(
            manager, "fetch_coffee_score", return_value=fake_fields
        ) as fetch_mock:
            outcome = manager.check_node_risk_score("score-1")
        self.assertTrue(outcome["ok"])
        fetch_mock.assert_called_once_with("8.8.8.8")
        stored = {n["id"]: n for n in manager.read_nodes()}
        row = stored["score-1"]
        self.assertEqual(37, row["risk_display_score"])
        self.assertEqual("", row["risk_display_level"])
        self.assertEqual("机房", row["risk_display_connection_type"])
        self.assertGreater(row["risk_display_checked_at"], 0)
        self.assertEqual("", row["risk_display_error"])
        # flags/reason are never written by the coffee path.
        self.assertEqual([], row["risk_display_flags"])
        self.assertEqual("", row["risk_display_reason"])
        # The hook field is never written and the other node is untouched.
        self.assertIsNone(row["iplark_score"])
        self.assertIsNone(stored["other-1"]["risk_display_score"])
        self.assertEqual(0, stored["other-1"]["risk_display_checked_at"])

    def test_check_success_replaces_voided_ffraud_state(self) -> None:
        # A node still carrying a 1.2.5 FFraud score: the read inside
        # check_node_risk_score voids it (plan §八.2), then the coffee
        # result lands -- no FFraud trace may survive the write-back.
        manager.write_json(
            manager.NODES_FILE,
            [self._score_node(
                "tor-1", "185.220.101.34",
                risk_display_score=100, risk_display_level="critical",
                risk_display_connection_type="Data Center",
                risk_display_flags=["代理", "VPN", "Tor", "机房托管"],
                risk_display_reason="Tor exit node actively routing traffic.",
                risk_display_checked_at=111.0,
            )],
        )
        body = json.dumps(self._sample("tor_185.220.101.34")).encode("utf-8")
        calls = self._fake_opener(lambda url: self._FakeResponse(body))
        outcome = manager.check_node_risk_score("tor-1")
        self.assertTrue(outcome["ok"])
        self.assertEqual(
            ["https://ip.net.coffee/api/ipv2/lookup/185.220.101.34"], calls
        )
        row = manager.read_nodes()[0]
        self.assertEqual(61, row["risk_display_score"])
        self.assertEqual("Very High", row["risk_display_level"])
        self.assertEqual("Tor 出口", row["risk_display_connection_type"])
        self.assertEqual([], row["risk_display_flags"])
        self.assertEqual("", row["risk_display_reason"])
        self.assertEqual("", row["risk_display_error"])
        self.assertGreater(row["risk_display_checked_at"], 111.0)

    def test_check_failure_keeps_previous_score(self) -> None:
        # The kept "previous score" is a coffee-written one (an
        # FFraud-era one would have been voided on the read inside
        # check_node_risk_score before the fetch even runs).
        manager.write_json(
            manager.NODES_FILE,
            [self._score_node(
                "score-1", "8.8.8.8",
                risk_display_score=42, risk_display_level="Very High",
                risk_display_connection_type="住宅",
                risk_display_checked_at=111.0,
            )],
        )

        def failing_fetch(ip):
            raise manager.RiskScoreFetchError(
                manager.RISK_ERROR_REJECTED, "IP Coffee HTTP 403"
            )

        with mock.patch.object(manager, "fetch_coffee_score", failing_fetch):
            outcome = manager.check_node_risk_score("score-1")
        self.assertFalse(outcome["ok"])
        self.assertEqual(manager.RISK_ERROR_REJECTED, outcome["error"])
        row = manager.read_nodes()[0]
        self.assertEqual(42, row["risk_display_score"])
        self.assertEqual("Very High", row["risk_display_level"])
        self.assertEqual("住宅", row["risk_display_connection_type"])
        self.assertEqual(manager.RISK_ERROR_REJECTED, row["risk_display_error"])
        self.assertGreater(row["risk_display_checked_at"], 111.0)
        self.assertIsNone(row["iplark_score"])

    def test_check_unknown_node_raises(self) -> None:
        manager.write_json(manager.NODES_FILE, [])
        with self.assertRaises(ValueError):
            manager.check_node_risk_score("missing")

    def test_inflight_guard_blocks_second_begin(self) -> None:
        self.assertTrue(manager._risk_check_begin("n1"))
        self.assertFalse(manager._risk_check_begin("n1"))
        self.assertTrue(manager._risk_check_begin("n2"))
        manager._risk_check_end("n1")
        self.assertTrue(manager._risk_check_begin("n1"))
        manager._risk_check_end("n1")
        manager._risk_check_end("n2")

    # -- ordering hard-acceptance: display fields never move selection ---

    def test_risk_display_fields_do_not_change_composite_ordering(self) -> None:
        pool = [
            self._score_node("a", "8.8.8.8", latency_ms=50,
                             probe_status="available"),
            self._score_node("b", "1.1.1.1", latency_ms=120,
                             probe_status="available", consecutive_failures=1),
            self._score_node("c", "185.220.101.34", latency_ms=200,
                             probe_status="not_checked"),
            self._score_node("d", "203.0.113.9", latency_ms=0,
                             probe_status="unavailable"),
        ]
        ui_cfg = {"routing_mode": "auto", "force_country": "",
                  "routing_ip_type": "all", "favorite_node_ids": []}

        def order():
            ranked = manager.rank_selection_candidates(
                [dict(n) for n in pool], ui_cfg
            )
            return [n["id"] for n in ranked]

        def composites():
            return {
                n["id"]: manager.composite_node_score(n, pool) for n in pool
            }

        before_order, before_scores = order(), composites()
        # Simulate completed coffee lookups writing ONLY display
        # fields, with wildly different scores (including the Tor 61).
        pool[0].update(risk_display_score=37, risk_display_level="",
                       risk_display_connection_type="机房",
                       risk_display_checked_at=999.0)
        pool[1].update(risk_display_score=59, risk_display_level="",
                       risk_display_connection_type="机房",
                       risk_display_checked_at=999.0)
        pool[2].update(risk_display_score=61, risk_display_level="Very High",
                       risk_display_connection_type="Tor 出口",
                       risk_display_checked_at=999.0)
        self.assertEqual(before_order, order())
        self.assertEqual(before_scores, composites())
        for n in pool:
            self.assertIsNone(n["iplark_score"])

    # -- merge backfill keeps the display fields --------------------------

    def test_merge_preserves_risk_display_fields(self) -> None:
        checked = self._score_node(
            "score-1", "185.220.101.34",
            risk_display_score=61, risk_display_level="Very High",
            risk_display_checked_at=1234567.0,
            risk_display_connection_type="Tor 出口",
            risk_display_flags=[],
            risk_display_reason="",
        )
        manager.write_json(manager.NODES_FILE, [checked])
        candidate = self._score_node("score-1", "185.220.101.34")  # fresh
        self._run_maintain([candidate])
        stored = {n["id"]: n for n in manager.read_nodes()}
        row = stored["score-1"]
        self.assertEqual(61, row["risk_display_score"])
        self.assertEqual("Very High", row["risk_display_level"])
        self.assertEqual(1234567.0, row["risk_display_checked_at"])
        self.assertEqual("Tor 出口", row["risk_display_connection_type"])
        self.assertEqual([], row["risk_display_flags"])
        self.assertEqual("", row["risk_display_reason"])
        self.assertIsNone(row["iplark_score"])

    # -- legacy FFraud-score voiding (plan §八.2) -------------------------

    def _bare_node(self, node_id: str, ip: str, **overrides) -> dict:
        """A node record without config_text, so the stage-1 config
        migration stays out of these stage-2 voiding assertions."""
        node = self._score_node(node_id, ip, **overrides)
        node.pop("config_text", None)
        return node

    def _assert_risk_cleared(self, row: dict) -> None:
        for key, default in manager.RISK_DISPLAY_DEFAULTS.items():
            self.assertEqual(default, row[key], key)

    def test_ffraud_legacy_scores_voided_on_first_read(self) -> None:
        full_trace = self._bare_node(
            "legacy-full", "8.8.8.8",
            risk_display_score=5, risk_display_level="none",
            risk_display_connection_type="Data Center",
            risk_display_flags=["机房托管"],
            risk_display_reason="Datacenter/hosting IP operated by Google.",
            risk_display_checked_at=1700000000.0,
        )
        tor_trace = self._bare_node(
            "legacy-tor", "185.220.101.34",
            risk_display_score=100, risk_display_level="critical",
            risk_display_connection_type="Data Center",
            risk_display_flags=["代理", "VPN", "Tor", "机房托管", "滥用记录"],
            risk_display_reason="Tor exit node actively routing traffic.",
            risk_display_checked_at=1700000000.0,
        )
        # Single-trace shapes: each FFraud-only marker on its own
        # must already trigger the voiding.
        level_only = self._bare_node(
            "legacy-level", "203.0.113.8",
            risk_display_score=42, risk_display_level="medium",
            risk_display_checked_at=1700000000.0,
        )
        conn_only = self._bare_node(
            "legacy-conn", "203.0.113.9",
            risk_display_score=7,
            risk_display_connection_type="Residential",
            risk_display_checked_at=1700000000.0,
        )
        flags_only = self._bare_node(
            "legacy-flags", "203.0.113.10",
            risk_display_score=88, risk_display_flags=["住宅代理"],
            risk_display_checked_at=1700000000.0,
        )
        reason_only = self._bare_node(
            "legacy-reason", "203.0.113.11",
            risk_display_score=15,
            risk_display_reason="VPN connection detected (unknown provider).",
            risk_display_checked_at=1700000000.0,
        )
        legacy = [full_trace, tor_trace, level_only, conn_only,
                  flags_only, reason_only]
        manager.write_json(manager.NODES_FILE, legacy)
        rows = {n["id"]: n for n in manager.read_nodes()}
        self.assertEqual(len(legacy), len(rows))
        for node in legacy:
            row = rows[node["id"]]
            self._assert_risk_cleared(row)
            # Non-risk fields are not the migration's business.
            self.assertEqual(node["ip"], row["ip"])
            self.assertIsNone(row["iplark_score"])
        # The voiding is persisted, not just an in-memory view.
        on_disk = {
            n["id"]: n
            for n in json.loads(manager.NODES_FILE.read_text(encoding="utf-8"))
        }
        for node in legacy:
            self._assert_risk_cleared(on_disk[node["id"]])

    def test_coffee_records_survive_reads_untouched(self) -> None:
        coffee_clean = self._bare_node(
            "coffee-1", "8.8.8.8",
            risk_display_score=37, risk_display_connection_type="机房",
            risk_display_checked_at=1700000000.0,
        )
        coffee_tor = self._bare_node(
            "coffee-2", "185.220.101.34",
            risk_display_score=61, risk_display_level="Very High",
            risk_display_connection_type="Tor 出口",
            risk_display_checked_at=1700000000.0,
        )
        # A failed re-check after a coffee success: score state kept,
        # error written -- still coffee-shaped, must not be voided.
        coffee_failed_recheck = self._bare_node(
            "coffee-3", "1.1.1.1",
            risk_display_score=59, risk_display_connection_type="机房",
            risk_display_error=manager.RISK_ERROR_NETWORK,
            risk_display_checked_at=1700000100.0,
        )
        # Error-only records carry no source-distinguishing trace and
        # are out of the voiding's scope by design.
        error_only = self._bare_node(
            "error-only", "203.0.113.12",
            risk_display_error=manager.RISK_ERROR_REJECTED,
            risk_display_checked_at=1700000000.0,
        )
        fresh = self._bare_node("fresh-1", "203.0.113.13")
        seeds = [coffee_clean, coffee_tor, coffee_failed_recheck,
                 error_only, fresh]
        manager.write_json(manager.NODES_FILE, seeds)
        before = manager.NODES_FILE.read_bytes()
        rows = {n["id"]: n for n in manager.read_nodes()}
        for seed in seeds:
            row = rows[seed["id"]]
            for key in manager.RISK_DISPLAY_DEFAULTS:
                self.assertEqual(seed[key], row[key], f"{seed['id']}:{key}")
        # No record matched the legacy shape, so the file is not
        # rewritten at all.
        self.assertEqual(before, manager.NODES_FILE.read_bytes())

    def test_voiding_is_idempotent_and_new_scores_stick(self) -> None:
        manager.write_json(
            manager.NODES_FILE,
            [self._bare_node(
                "legacy-1", "8.8.8.8",
                risk_display_score=5, risk_display_level="none",
                risk_display_connection_type="Data Center",
                risk_display_flags=["机房托管"],
                risk_display_reason="Datacenter/hosting IP.",
                risk_display_checked_at=1700000000.0,
            )],
        )
        self._assert_risk_cleared(manager.read_nodes()[0])
        after_first = manager.NODES_FILE.read_bytes()
        self._assert_risk_cleared(manager.read_nodes()[0])
        self.assertEqual(after_first, manager.NODES_FILE.read_bytes())
        # A coffee score written after the voiding is not re-voided.
        fake_fields = manager.parse_coffee_response(
            self._sample("clean_8.8.8.8"), "8.8.8.8"
        )
        with mock.patch.object(
            manager, "fetch_coffee_score", return_value=fake_fields
        ):
            outcome = manager.check_node_risk_score("legacy-1")
        self.assertTrue(outcome["ok"])
        row = manager.read_nodes()[0]
        self.assertEqual(37, row["risk_display_score"])
        self.assertEqual("机房", row["risk_display_connection_type"])

    # -- HTTP endpoint, full path -----------------------------------------

    def test_check_score_http_endpoint(self) -> None:
        manager.write_json(
            manager.NODES_FILE,
            [self._score_node("score-1", "8.8.8.8"),
             self._score_node("bad-1", "notanip")],
        )
        manager.active_sessions["plus126-stage2-token"] = manager.time.time() + 60
        server = manager.DualStackHTTPServer(("127.0.0.1", 0), manager.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}/EJsW2EeBo9lY"

        def request(path: str, payload: dict | None = None) -> tuple[int, dict]:
            data = None
            headers = {"Cookie": "session=plus126-stage2-token"}
            if payload is not None:
                data = json.dumps(payload).encode("utf-8")
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request(
                base_url + path,
                data=data,
                headers=headers,
                method="POST" if payload is not None else "GET",
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    return response.status, json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read().decode("utf-8"))

        sample_body = json.dumps(self._sample("clean_8.8.8.8")).encode("utf-8")
        try:
            # Success: real fetch runs against the faked opener.
            calls = self._fake_opener(
                lambda url: self._FakeResponse(sample_body)
            )
            status, payload = request("/api/check_score", {"id": "score-1"})
            self.assertEqual(200, status)
            self.assertTrue(payload["ok"])
            self.assertEqual(37, payload["node"]["risk_display_score"])
            self.assertNotIn("config_text", payload["node"])
            self.assertEqual(
                ["https://ip.net.coffee/api/ipv2/lookup/8.8.8.8"], calls
            )
            status, nodes_payload = request("/api/nodes")
            self.assertEqual(200, status)
            rows = {n["id"]: n for n in nodes_payload["nodes"]}
            self.assertEqual(37, rows["score-1"]["risk_display_score"])
            self.assertEqual("", rows["score-1"]["risk_display_level"])
            self.assertEqual(
                "机房", rows["score-1"]["risk_display_connection_type"]
            )
            self.assertIsNone(rows["score-1"]["iplark_score"])

            # Invalid target: rejected before any network use.
            calls.clear()
            status, payload = request("/api/check_score", {"id": "bad-1"})
            self.assertEqual(200, status)
            self.assertFalse(payload["ok"])
            self.assertEqual(manager.RISK_ERROR_TARGET_INVALID, payload["error"])
            self.assertEqual([], calls)
            rows = {n["id"]: n for n in manager.read_nodes()}
            self.assertEqual(
                manager.RISK_ERROR_TARGET_INVALID,
                rows["bad-1"]["risk_display_error"],
            )
            self.assertIsNone(rows["bad-1"]["risk_display_score"])

            # Unknown node / empty id: 400.
            status, payload = request("/api/check_score", {"id": "missing"})
            self.assertEqual(400, status)
            self.assertFalse(payload["ok"])
            status, payload = request("/api/check_score", {"id": ""})
            self.assertEqual(400, status)

            # Duplicate in-flight: pre-held guard -> 409 正在查询.
            self.assertTrue(manager._risk_check_begin("score-1"))
            try:
                status, payload = request("/api/check_score", {"id": "score-1"})
                self.assertEqual(409, status)
                self.assertFalse(payload["ok"])
                self.assertEqual("正在查询", payload["error"])
            finally:
                manager._risk_check_end("score-1")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_check_score_http_failure_writes_error_only(self) -> None:
        manager.write_json(
            manager.NODES_FILE, [self._score_node("score-1", "8.8.8.8")]
        )
        manager.active_sessions["plus126-stage2-token"] = manager.time.time() + 60
        server = manager.DualStackHTTPServer(("127.0.0.1", 0), manager.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_address[1]}/EJsW2EeBo9lY"

        def responder(url):
            raise urllib.error.HTTPError(url, 403, "Forbidden", None, None)

        try:
            self._fake_opener(responder)
            req = urllib.request.Request(
                base_url + "/api/check_score",
                data=json.dumps({"id": "score-1"}).encode("utf-8"),
                headers={
                    "Cookie": "session=plus126-stage2-token",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))
                status = response.status
            self.assertEqual(200, status)
            self.assertFalse(payload["ok"])
            self.assertEqual(manager.RISK_ERROR_REJECTED, payload["error"])
            row = manager.read_nodes()[0]
            self.assertEqual(manager.RISK_ERROR_REJECTED, row["risk_display_error"])
            self.assertGreater(row["risk_display_checked_at"], 0)
            self.assertIsNone(row["risk_display_score"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    # -- panel narrative (plan §二) and markers ---------------------------

    def test_risk_score_title_narrative_matches_plan_verbatim(self) -> None:
        html = manager.INDEX_HTML
        start = html.index("function riskScoreTitle")
        end = html.index("async function checkNodeScore")
        fn = html[start:end]
        # Unqueried state is one fully static string in the source;
        # assert it character-for-character (plan §二).
        self.assertIn(
            "尚未查询。点击「查评分」拉取该 IP 的风险系数。"
            "评分引用：IP Coffee（ip.net.coffee）。此分数只作为参考。",
            fn,
        )
        # Checked state: exactly the four items -- risk coefficient,
        # query time, IP type, citation -- assembled in plan order.
        self.assertIn("风险系数 ", fn)
        self.assertIn("（0–100，越高越危险）", fn)
        self.assertIn("查询时间：", fn)
        self.assertIn("IP 类型：", fn)
        self.assertIn(
            "评分引用：IP Coffee（ip.net.coffee）。此分数只作为参考。", fn
        )
        # Failure state: category + time + citation, nothing else.
        self.assertIn("查询失败：", fn)
        self.assertIn(
            "。评分引用：IP Coffee（ip.net.coffee）。此分数只作为参考。", fn
        )
        # Nothing beyond the four items may be narrated: no tier, no
        # flags, no reason, no old source name, no legacy field reads.
        for banned in (
            "档位", "标记", "说明：", "连接类型", "来源：", "FFraud",
            "risk_display_level", "risk_display_flags",
            "risk_display_reason",
        ):
            self.assertNotIn(banned, fn)

    def test_panel_risk_score_ui_markers(self) -> None:
        html = manager.INDEX_HTML
        self.assertIn('<th style="width: 90px;">风险分</th>', html)
        self.assertNotIn("iplark 评分</th>", html)
        self.assertNotIn("暂未启用", html)
        self.assertNotIn("FFraud", html)
        self.assertIn("checkNodeScore", html)
        self.assertIn("riskScoreTitle", html)
        self.assertIn("scoreRequestIds", html)
        self.assertIn("查询中…", html)
        self.assertIn("越高越危险", html)
        self.assertIn("此分数只作为参考", html)
        self.assertIn("risk_display_score", html)
        # New node records carry the display-field defaults.
        fresh = manager.row_to_node(
            {"IP": "8.8.8.8", "CountryShort": "US", "HostName": "x",
             "Score": "1", "Ping": "1", "Speed": "1", "NumVpnSessions": "1",
             "CountryLong": "United States"},
            "client\nremote 8.8.8.8 1194 udp\n",
        )
        for key, default in manager.RISK_DISPLAY_DEFAULTS.items():
            self.assertEqual(default, fresh[key])
        self.assertIsNone(fresh["iplark_score"])


CONFIG_STORE_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "config_store"


class Plus126ConfigStoreTests(unittest.TestCase):
    """1.2.6 stage 1: node configs move out of nodes.json into the
    dedicated config store (plan §四). Covers the fetch write path,
    the probe/connect/download consumers, legacy migration, lifecycle
    synchronisation, and the panel output contract."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.root = root
        self.path_patches = [
            mock.patch.object(manager, "DATA_DIR", root),
            mock.patch.object(manager, "CONFIG_DIR", root / "configs"),
            mock.patch.object(manager, "CONFIG_STORE_FILE", root / "node_configs.json"),
            mock.patch.object(manager, "NODES_FILE", root / "nodes.json"),
            mock.patch.object(manager, "STATE_FILE", root / "state.json"),
            mock.patch.object(manager, "AUTH_FILE", root / "auth.txt"),
            mock.patch.object(manager, "BLACKLIST_FILE", root / "blacklist.json"),
            mock.patch.object(manager, "API_CACHE_FILE", root / "api_snapshot.csv"),
            mock.patch.object(manager, "API_CACHE_META_FILE", root / "api_snapshot.meta.json"),
            mock.patch.object(manager, "BUNDLED_SNAPSHOT_FILE", root / "bundled_snapshot.csv"),
            mock.patch.object(manager, "RETAINED_ARCHIVE_FILE", root / "retained_archive.json"),
            mock.patch.object(manager.vpn_utils, "DATA_DIR", root),
            mock.patch.object(manager.vpn_utils, "IP_CACHE_FILE", root / "ip_cache.json"),
        ]
        for patcher in self.path_patches:
            patcher.start()
        manager.ensure_dirs()
        manager._config_store_cache["key"] = None
        manager._config_store_cache["data"] = {}
        self._saved_restart_first = manager._first_maintain_after_startup
        manager._first_maintain_after_startup = True
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
        manager._switch_watch_last_id = ""
        manager.clear_switch_sweep_pending()
        manager._retained_count_cache["key"] = None
        manager._retained_count_cache["count"] = 0

    def tearDown(self) -> None:
        if manager.connection_attempt_lock.locked():
            manager.connection_attempt_lock.release()
        manager.background_refill_cancel_event.set()
        manager.background_refill_thread = None
        manager._first_maintain_after_startup = self._saved_restart_first
        manager.active_openvpn_node_id = ""
        manager._switch_watch_last_id = ""
        manager.clear_switch_sweep_pending()
        manager._config_store_cache["key"] = None
        manager._config_store_cache["data"] = {}
        manager._retained_count_cache["key"] = None
        manager._retained_count_cache["count"] = 0
        for patcher in reversed(self.path_patches):
            patcher.stop()
        self.temp_dir.cleanup()

    # -- helpers ------------------------------------------------------

    def _node(self, node_id: str, ip: str, port: int = 1194, proto: str = "udp", **extra) -> dict:
        node = {
            "id": node_id,
            "country": "日本",
            "country_short": "JP",
            "ip": ip,
            "remote_host": ip,
            "remote_port": port,
            "proto": proto,
            "ping": 10,
            "score": 100,
            "latency_ms": 0,
            "config_file": str(manager.CONFIG_DIR / f"{node_id}.ovpn"),
            "probe_status": "not_checked",
            "probe_message": "",
            "probed_at": 0,
            "retention_status": "normal",
            "last_seen_at": manager.time.time(),
            "source_present": 1,
            "consecutive_failures": 0,
            "last_success_at": 0,
            "active": False,
        }
        node.update(extra)
        return node

    def _write_table_with_configs(self, specs) -> list[dict]:
        """Write a metadata-only node table and store each spec's
        config text in the config store (the post-1.2.6 on-disk form).
        specs: list of (node_id, ip) or (node_id, ip, config_text)."""
        nodes = []
        store = {}
        for spec in specs:
            node_id, ip = spec[0], spec[1]
            nodes.append(self._node(node_id, ip))
            if len(spec) > 2 and spec[2]:
                store[node_id] = spec[2]
        manager.write_json(manager.NODES_FILE, nodes)
        manager.write_config_store(store)
        return nodes

    def _run_maintain(self, candidates):
        with (
            mock.patch.object(manager, "fetch_candidates", return_value=candidates),
            mock.patch.object(manager, "active_openvpn_running", return_value=True),
            mock.patch.object(manager, "test_multiple_nodes", return_value=[]),
            mock.patch.object(manager, "sweep_retained_nodes", return_value=0),
            mock.patch.object(
                manager, "run_full_sweep",
                return_value={"skipped": True, "tested": 0, "available": 0, "unavailable": 0},
            ),
            mock.patch.object(manager, "log_to_json"),
        ):
            return manager.maintain_valid_nodes(force=False, trigger="auto")

    def _load_fixture(self, name: str) -> list:
        text = (CONFIG_STORE_FIXTURES / name).read_text(encoding="utf-8")
        return json.loads(text.replace("CONFIGS_DIR", str(manager.CONFIG_DIR)))

    # -- fetch path ---------------------------------------------------

    def test_fetch_stores_config_and_candidate_record_is_metadata_only(self) -> None:
        candidates = manager.rows_to_candidates(
            manager.parse_vpngate_rows(valid_snapshot()), {}
        )
        self.assertEqual(1, len(candidates))
        candidate = candidates[0]
        self.assertNotIn("config_text", candidate)
        self.assertEqual("198.51.100.10", candidate["remote_host"])
        self.assertEqual(1194, candidate["remote_port"])
        stored = manager.get_node_config(candidate["id"])
        self.assertIn("remote 198.51.100.10 1194", stored)
        self.assertEqual(
            stored,
            manager.read_config_store()[candidate["id"]],
        )

    # -- consumers: probe chains --------------------------------------

    def test_probe_chains_read_config_from_store(self) -> None:
        config_a = "client\nremote 192.0.2.11 1194 udp\n# store-a\n"
        config_b = "client\nremote 192.0.2.12 1194 udp\n# store-b\n"
        self._write_table_with_configs([
            ("store-node-a", "192.0.2.11", config_a),
            ("store-node-b", "192.0.2.12", config_b),
        ])
        seen: dict[str, str] = {}

        def fake_openvpn(config_file, **kwargs):
            seen[Path(config_file).name] = Path(config_file).read_text(encoding="utf-8")
            return True, "ready", None

        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(manager.vpn_utils, "enrich_ip_info"),
            mock.patch.object(manager, "run_openvpn_until_ready", side_effect=fake_openvpn),
        ):
            single = manager.test_node_by_id("store-node-a")
            batch = manager.test_multiple_nodes(["store-node-a", "store-node-b"])

        self.assertEqual("available", single["probe_status"])
        self.assertEqual(
            {"store-node-a", "store-node-b"},
            {result["id"] for result in batch},
        )
        temp_contents = set(seen.values())
        self.assertIn(config_a, temp_contents)
        self.assertIn(config_b, temp_contents)
        for node in manager.read_nodes():
            self.assertNotIn("config_text", node)

    def test_probe_of_configless_node_behaves_like_empty_config(self) -> None:
        # No store entry at all: both probe chains must take the old
        # empty-config failure path (temp file written empty, openvpn
        # reports failure, node ends unavailable) -- no new crash.
        node = self._node("store-node-none", "192.0.2.99")
        manager.write_json(manager.NODES_FILE, [node])
        seen: list[str] = []

        def fake_openvpn(config_file, **kwargs):
            seen.append(Path(config_file).read_text(encoding="utf-8"))
            return False, "cannot read config", None

        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=0),
            mock.patch.object(manager.vpn_utils, "enrich_ip_info"),
            mock.patch.object(manager, "run_openvpn_until_ready", side_effect=fake_openvpn),
        ):
            single = manager.test_node_by_id("store-node-none")
            batch = manager.test_multiple_nodes(["store-node-none"])

        self.assertEqual("unavailable", single["probe_status"])
        self.assertEqual("unavailable", batch[0]["probe_status"])
        self.assertEqual(["", ""], seen)
        self.assertEqual("", manager.get_node_config("store-node-none"))

    # -- consumers: connect + stop ------------------------------------

    def test_connect_writes_store_config_and_stop_removes_it(self) -> None:
        config = "client\nremote 192.0.2.21 1194 udp\n# store-connect\n"
        nodes = self._write_table_with_configs([
            ("store-node-c", "192.0.2.21", config),
        ])
        process = FakeProcess()
        written: dict[str, str] = {}

        def fake_openvpn(config_file, **kwargs):
            written["content"] = Path(config_file).read_text(encoding="utf-8")
            return True, "ready", process

        with (
            mock.patch.object(manager, "run_openvpn_until_ready", side_effect=fake_openvpn),
            mock.patch.object(manager, "setup_policy_routing", return_value=True),
            mock.patch.object(manager, "cleanup_policy_routing"),
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(
                manager, "check_proxy_health",
                return_value={"ok": True, "ip": "192.0.2.21", "latency_ms": 10},
            ),
            mock.patch.object(manager, "log_to_json"),
        ):
            manager.connect_node("store-node-c")

        self.assertEqual(config, written["content"])
        config_path = Path(nodes[0]["config_file"])
        self.assertEqual(config, config_path.read_text(encoding="utf-8"))
        self.assertEqual(
            config, manager.get_node_config("store-node-c")
        )
        # Disconnecting deletes the materialized connection file but
        # must NOT delete the store copy (the node still lives).
        manager.stop_active_openvpn()
        self.assertFalse(config_path.exists())
        self.assertEqual(config, manager.get_node_config("store-node-c"))

    def test_connect_without_store_config_fails_like_empty_config(self) -> None:
        node = self._node("store-node-d", "192.0.2.22")
        manager.write_json(manager.NODES_FILE, [node])
        process = FakeProcess()

        def fake_openvpn(config_file, **kwargs):
            return True, "ready", process

        with (
            mock.patch.object(manager, "run_openvpn_until_ready", side_effect=fake_openvpn),
            mock.patch.object(manager, "setup_policy_routing", return_value=False),
            mock.patch.object(manager, "cleanup_policy_routing"),
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=10),
            mock.patch.object(manager, "check_proxy_health", return_value={"ok": False, "error": "no route"}),
            mock.patch.object(manager, "log_to_json"),
        ):
            with self.assertRaisesRegex(RuntimeError, "代理出口不可用"):
                manager.connect_node("store-node-d")

        self.assertFalse(process.running)
        self.assertEqual("", manager.active_openvpn_node_id)
        stored = manager.read_nodes()
        self.assertEqual("unavailable", stored[0]["probe_status"])

    # -- consumers: download + panel output ----------------------------

    def _serve(self):
        manager.active_sessions["cfg-store-token"] = manager.time.time() + 60
        server = manager.DualStackHTTPServer(("127.0.0.1", 0), manager.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, timeout=5)
        return f"http://127.0.0.1:{server.server_address[1]}/EJsW2EeBo9lY"

    def test_download_and_nodes_api_use_store_without_leaking(self) -> None:
        config = "client\nremote 192.0.2.31 1194 udp\n# store-download\n"
        nodes = self._write_table_with_configs([
            ("store-node-e", "192.0.2.31", config),
            ("store-node-f", "192.0.2.32"),
        ])
        base_url = self._serve()
        headers = {"Cookie": "session=cfg-store-token"}

        filename = Path(nodes[0]["config_file"]).name
        req = urllib.request.Request(base_url + f"/configs/{filename}", headers=headers)
        with urllib.request.urlopen(req, timeout=5) as response:
            self.assertEqual(200, response.status)
            self.assertEqual(config.encode("utf-8"), response.read())

        # A node without a stored config 404s, exactly as a node with
        # an empty embedded config did before.
        missing_name = Path(nodes[1]["config_file"]).name
        req = urllib.request.Request(base_url + f"/configs/{missing_name}", headers=headers)
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=5)
        self.assertEqual(404, ctx.exception.code)

        # /api/nodes output: identical shape to the baseline contract --
        # same fields as the stored records minus nothing (the baseline
        # stripped config_text; records no longer carry it at all), and
        # no config content anywhere in the payload.
        req = urllib.request.Request(base_url + "/api/nodes", headers=headers)
        with urllib.request.urlopen(req, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        rows = {n["id"]: n for n in payload["nodes"]}
        self.assertEqual({"store-node-e", "store-node-f"}, set(rows))
        expected_keys = set(nodes[0].keys()) | {"active"}
        self.assertEqual(expected_keys, set(rows["store-node-e"].keys()))
        for row in payload["nodes"]:
            self.assertNotIn("config_text", row)
        self.assertNotIn("store-download", json.dumps(payload))

    # -- migration ------------------------------------------------------

    def test_legacy_tables_migrate_on_first_store_read(self) -> None:
        legacy_nodes = self._load_fixture("legacy_nodes.json")
        legacy_archive = self._load_fixture("legacy_archive.json")
        manager.write_json(manager.NODES_FILE, legacy_nodes)
        manager.write_json(manager.RETAINED_ARCHIVE_FILE, legacy_archive)

        store = manager.read_config_store()
        self.assertEqual(
            "client\nremote 198.51.100.10 1194 udp\n",
            store["JP_198.51.100.10_1194_udp"],
        )
        self.assertEqual(
            "client\nremote 198.51.100.20 443 tcp\n",
            store["KR_198.51.100.20_443_tcp"],
        )
        self.assertEqual(
            "client\nremote 203.0.113.7 1194 udp\n",
            store["US_203.0.113.7_1194_udp"],
        )
        # Both files are stripped; every other field survives verbatim.
        stripped_nodes = manager.read_json(manager.NODES_FILE, [])
        self.assertEqual(2, len(stripped_nodes))
        for raw, stripped in zip(legacy_nodes, stripped_nodes):
            expected = {k: v for k, v in raw.items() if k != "config_text"}
            self.assertEqual(expected, stripped)
        stripped_archive = manager.read_json(manager.RETAINED_ARCHIVE_FILE, [])
        self.assertEqual(2, len(stripped_archive))
        for raw, stripped in zip(legacy_archive, stripped_archive):
            expected = {k: v for k, v in raw.items() if k != "config_text"}
            self.assertEqual(expected, stripped)
        # The store file itself was persisted.
        on_disk = json.loads(manager.CONFIG_STORE_FILE.read_text(encoding="utf-8"))
        self.assertEqual(store, on_disk)

    def test_migration_is_idempotent_and_store_wins(self) -> None:
        legacy_nodes = self._load_fixture("legacy_nodes.json")
        manager.write_json(manager.NODES_FILE, legacy_nodes)
        manager.write_config_store(
            {"JP_198.51.100.10_1194_udp": "client\nremote 198.51.100.10 9999 udp\n"}
        )
        first = manager.read_config_store()
        # Pre-existing store content wins over the stale embedded copy.
        self.assertEqual(
            "client\nremote 198.51.100.10 9999 udp\n",
            first["JP_198.51.100.10_1194_udp"],
        )
        nodes_bytes = manager.NODES_FILE.read_bytes()
        store_bytes = manager.CONFIG_STORE_FILE.read_bytes()
        second = manager.read_config_store()
        self.assertEqual(first, second)
        # Second read performs no rewrites at all.
        self.assertEqual(nodes_bytes, manager.NODES_FILE.read_bytes())
        self.assertEqual(store_bytes, manager.CONFIG_STORE_FILE.read_bytes())

    def test_heal_loop_uses_store_after_migration(self) -> None:
        candidates = [self._node("store-node-g", "192.0.2.41")]
        existing = self._node(
            "legacy-node-h", "192.0.2.42",
            config_text="client\nremote 192.0.2.42 1194 udp\n",
        )
        manager.write_json(manager.NODES_FILE, [existing])

        self._run_maintain(candidates)

        merged = {n["id"]: n for n in manager.read_nodes()}
        self.assertIn("legacy-node-h", merged)
        self.assertNotIn("config_text", merged["legacy-node-h"])
        materialized = Path(merged["legacy-node-h"]["config_file"])
        self.assertEqual(
            "client\nremote 192.0.2.42 1194 udp\n",
            materialized.read_text(encoding="utf-8"),
        )

    # -- lifecycle ------------------------------------------------------

    def test_maintain_merge_grace_expiry_archives_and_keeps_config(self) -> None:
        now = manager.time.time()
        old = self._node(
            "store-node-old", "192.0.2.51",
            retention_status="observing",
            last_seen_at=now - manager.RETAINED_OBSERVING_GRACE_SECONDS - 10,
            source_present=0,
        )
        manager.write_json(manager.NODES_FILE, [old])
        manager.write_config_store(
            {"store-node-old": "client\nremote 192.0.2.51 1194 udp\n"}
        )
        candidates = [self._node("store-node-new", "192.0.2.52")]
        manager.store_node_config(
            "store-node-new", "client\nremote 192.0.2.52 1194 udp\n"
        )

        self._run_maintain(candidates)

        # Archiving is NOT config deletion: the archived node keeps
        # its config in the store (restorable / liveness-probed by
        # id); only the archive record itself drops the embedded copy.
        self.assertEqual(
            "client\nremote 192.0.2.51 1194 udp\n",
            manager.get_node_config("store-node-old"),
        )
        archive = manager.read_json(manager.RETAINED_ARCHIVE_FILE, [])
        self.assertEqual(["store-node-old"], [r["id"] for r in archive])
        self.assertNotIn("config_text", archive[0])
        remaining = {n["id"] for n in manager.read_nodes()}
        self.assertNotIn("store-node-old", remaining)

    def test_disable_pool_purge_drops_config_but_favorite_keeps_it(self) -> None:
        fav = self._node(
            "store-node-fav", "192.0.2.61", retention_status="observing",
        )
        plain = self._node(
            "store-node-plain", "192.0.2.62", retention_status="observing",
        )
        manager.write_json(manager.NODES_FILE, [fav, plain])
        manager.write_config_store({
            "store-node-fav": "client\nremote 192.0.2.61 1194 udp\n",
            "store-node-plain": "client\nremote 192.0.2.62 1194 udp\n",
        })
        manager.write_json(
            self.root / "ui_auth.json",
            {"favorite_node_ids": ["store-node-fav"], "retained_pool_enabled": True},
        )

        result = manager.disable_retained_pool()

        self.assertEqual({"archived": 1, "kept_favorites": 1}, result)
        # The purged node was archived, so its config is retained in
        # the store under its id (it leaves only when the archive
        # record itself is evicted); the favorite never left the
        # table, so its config trivially survives too.
        self.assertEqual(
            "client\nremote 192.0.2.62 1194 udp\n",
            manager.get_node_config("store-node-plain"),
        )
        archive = manager.read_json(manager.RETAINED_ARCHIVE_FILE, [])
        self.assertEqual(["store-node-plain"], [r["id"] for r in archive])
        self.assertNotIn("config_text", archive[0])
        self.assertEqual(
            "client\nremote 192.0.2.61 1194 udp\n",
            manager.get_node_config("store-node-fav"),
        )
        remaining = {n["id"]: n for n in manager.read_nodes()}
        self.assertEqual("normal", remaining["store-node-fav"]["retention_status"])

    def test_sweep_archives_dead_node_and_config_follows_archive(self) -> None:
        now = manager.time.time()
        dead = self._node(
            "store-node-dead", "192.0.2.71",
            retention_status="observing",
            consecutive_failures=9,
            last_seen_at=now - 100 * 3600,
            fetched_at=now - 100 * 3600,
            source_present=0,
        )
        alive = self._node(
            "store-node-alive", "192.0.2.72", retention_status="observing",
        )
        manager.write_json(manager.NODES_FILE, [dead, alive])
        manager.write_config_store({
            "store-node-dead": "client\nremote 192.0.2.71 1194 udp\n",
            "store-node-alive": "client\nremote 192.0.2.72 1194 udp\n",
        })

        archived = manager.sweep_retained_nodes(now=now)

        self.assertEqual(1, archived)
        self.assertEqual(
            ["store-node-alive"], [n["id"] for n in manager.read_nodes()]
        )
        # The dead node is archived, not erased: its config follows
        # the archive record...
        self.assertEqual(
            "client\nremote 192.0.2.71 1194 udp\n",
            manager.get_node_config("store-node-dead"),
        )
        # ...and is pruned only once the record is pushed out of the
        # archive by the 1000-record cap.
        fillers = [
            ({"id": f"filler-{index}"}, "filler") for index in range(1000)
        ]
        manager.archive_retained_nodes(fillers)
        self.assertEqual("", manager.get_node_config("store-node-dead"))
        self.assertEqual(
            "client\nremote 192.0.2.72 1194 udp\n",
            manager.get_node_config("store-node-alive"),
        )

    def test_archive_cap_eviction_prunes_config(self) -> None:
        initial = [
            {"id": f"existing-{index}", "archived_at": 1, "reason": "existing"}
            for index in range(999)
        ]
        manager.write_json(manager.RETAINED_ARCHIVE_FILE, initial)
        store = {f"existing-{index}": f"cfg-{index}" for index in range(999)}
        store["orphan-1"] = "orphan-config"
        manager.write_config_store(store)
        entries = [
            (
                self._node(
                    f"new-{index}", f"192.0.2.{80 + index}",
                    config_text=f"new-config-{index}",
                ),
                f"reason-{index}",
            )
            for index in range(3)
        ]

        archived = manager.archive_retained_nodes(entries)

        self.assertEqual(3, archived)
        records = manager.read_json(manager.RETAINED_ARCHIVE_FILE, [])
        self.assertEqual(1000, len(records))
        self.assertEqual("existing-2", records[0]["id"])
        for record in records:
            self.assertNotIn("config_text", record)
        # Records pushed out by the cap lose their store entries;
        # survivors and the new arrivals keep theirs.
        self.assertEqual("", manager.get_node_config("existing-0"))
        self.assertEqual("", manager.get_node_config("existing-1"))
        self.assertEqual("cfg-2", manager.get_node_config("existing-2"))
        self.assertEqual("new-config-0", manager.get_node_config("new-0"))
        # Unrelated orphans are not this function's business.
        self.assertEqual("orphan-config", manager.get_node_config("orphan-1"))
        self.assertEqual(1, manager.sync_config_store_lifecycle())
        self.assertEqual("", manager.get_node_config("orphan-1"))

    def test_table_drop_leaves_orphan_until_lifecycle_sweep(self) -> None:
        node = self._node("store-node-x", "192.0.2.91")
        manager.write_json(manager.NODES_FILE, [node])
        manager.write_config_store(
            {"store-node-x": "client\nremote 192.0.2.91 1194 udp\n"}
        )
        # A wholesale table replacement (import/restore) drops the node
        # without any lifecycle event; the config survives until the
        # explicit lifecycle sweep prunes it.
        manager.write_json(manager.NODES_FILE, [])
        self.assertEqual(
            "client\nremote 192.0.2.91 1194 udp\n",
            manager.get_node_config("store-node-x"),
        )
        self.assertEqual(1, manager.sync_config_store_lifecycle())
        self.assertEqual("", manager.get_node_config("store-node-x"))


class Plus126Stage3PanelTests(unittest.TestCase):
    """1.2.6 stage 3: panel IP display (plan §三) and connection
    state display fixes (plan §五).

    Covers the probe retest (a single failed probe is retested once
    and only a double failure counts as one failure event), the
    backend tri-state display signal (degraded below the switch
    threshold), the /api/state lightweight endpoint, and source-level
    panel markers for the IP cell / copy handler / busy-period
    polling split. All network access is faked.
    """

    class _StopChecker(Exception):
        """Sentinel raised by the fake sleep to end the checker loop."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.root = root
        self.path_patches = [
            mock.patch.object(manager, "DATA_DIR", root),
            mock.patch.object(manager, "CONFIG_DIR", root / "configs"),
            mock.patch.object(manager, "CONFIG_STORE_FILE", root / "node_configs.json"),
            mock.patch.object(manager, "NODES_FILE", root / "nodes.json"),
            mock.patch.object(manager, "STATE_FILE", root / "state.json"),
            mock.patch.object(manager, "AUTH_FILE", root / "auth.txt"),
            mock.patch.object(manager, "BLACKLIST_FILE", root / "blacklist.json"),
            mock.patch.object(manager, "API_CACHE_FILE", root / "api_snapshot.csv"),
            mock.patch.object(manager, "API_CACHE_META_FILE", root / "api_snapshot.meta.json"),
            mock.patch.object(manager, "BUNDLED_SNAPSHOT_FILE", root / "bundled_snapshot.csv"),
            mock.patch.object(manager, "RETAINED_ARCHIVE_FILE", root / "retained_archive.json"),
            mock.patch.object(manager.vpn_utils, "DATA_DIR", root),
            mock.patch.object(manager.vpn_utils, "IP_CACHE_FILE", root / "ip_cache.json"),
        ]
        for patcher in self.path_patches:
            patcher.start()
        manager.ensure_dirs()
        manager._config_store_cache["key"] = None
        manager._config_store_cache["data"] = {}
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
        manager._retained_count_cache["key"] = None
        manager._retained_count_cache["count"] = 0

    def tearDown(self) -> None:
        if manager.connection_attempt_lock.locked():
            manager.connection_attempt_lock.release()
        manager.background_refill_cancel_event.set()
        manager.background_refill_thread = None
        manager.active_openvpn_process = None
        manager.active_openvpn_node_id = ""
        manager.is_connecting = False
        manager.consecutive_proxy_failures = 0
        manager.last_proxy_failure_node_id = ""
        manager._config_store_cache["key"] = None
        manager._config_store_cache["data"] = {}
        manager._retained_count_cache["key"] = None
        manager._retained_count_cache["count"] = 0
        manager.active_sessions.clear()
        for patcher in reversed(self.path_patches):
            patcher.stop()
        self.temp_dir.cleanup()

    # -- helpers ------------------------------------------------------

    def _activate_node(self, node_id: str = "probe-node") -> FakeProcess:
        node = {
            "id": node_id,
            "country": "日本",
            "country_short": "JP",
            "ip": "192.0.2.50",
            "remote_host": "192.0.2.50",
            "remote_port": 1194,
            "ping": 10,
            "score": 100,
            "config_file": str(manager.CONFIG_DIR / f"{node_id}.ovpn"),
            "probe_status": "available",
            "probed_at": 0,
            "retention_status": "normal",
            "consecutive_failures": 0,
            "active": False,
        }
        manager.write_json(manager.NODES_FILE, [node])
        process = FakeProcess()
        manager.active_openvpn_process = process
        manager.active_openvpn_node_id = node_id
        return process

    def _run_checker_rounds(self, results: list, rounds: int):
        """Drive background_proxy_checker through exactly `rounds`
        iterations against a scripted check_proxy_health sequence.
        The fake sleep lets the initial sleep plus one end-of-round
        sleep per finished round pass and raises the sentinel on the
        sleep that ends the last requested round."""
        calls = {"health": 0, "sleep": 0}

        def fake_health():
            calls["health"] += 1
            return results.pop(0)

        def fake_sleep(_seconds):
            calls["sleep"] += 1
            if calls["sleep"] > rounds:
                raise Plus126Stage3PanelTests._StopChecker()

        with (
            mock.patch.object(manager, "check_proxy_health", side_effect=fake_health),
            mock.patch.object(manager.time, "sleep", side_effect=fake_sleep),
            mock.patch.object(manager, "log_to_json"),
            mock.patch.object(manager, "auto_switch_node") as switch_mock,
            mock.patch.object(manager, "mark_blacklisted"),
        ):
            with self.assertRaises(Plus126Stage3PanelTests._StopChecker):
                manager.background_proxy_checker()
        return calls, switch_mock

    def _serve(self) -> str:
        manager.active_sessions["stage3-token"] = manager.time.time() + 60
        server = manager.DualStackHTTPServer(("127.0.0.1", 0), manager.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, timeout=5)
        return f"http://127.0.0.1:{server.server_address[1]}/EJsW2EeBo9lY"

    def _get_json(self, base_url: str, path: str) -> dict:
        req = urllib.request.Request(
            base_url + path, headers={"Cookie": "session=stage3-token"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            self.assertEqual(200, response.status)
            return json.loads(response.read().decode("utf-8"))

    # -- plan §五.2: probe retest -------------------------------------

    def test_probe_single_failure_retest_success_keeps_proxy_ok_and_counter(self) -> None:
        self._activate_node()
        manager.set_state(proxy_ok=True, proxy_ip="203.0.113.9")
        results = [
            {"ok": False, "error": "transient blip"},
            {"ok": True, "ip": "203.0.113.9", "latency_ms": 12},
        ]
        calls, switch_mock = self._run_checker_rounds(results, rounds=1)

        # One failure event consumed exactly two probes (probe+retest).
        self.assertEqual(2, calls["health"])
        state = manager.get_state()
        self.assertTrue(state["proxy_ok"])
        self.assertEqual("203.0.113.9", state["proxy_ip"])
        self.assertEqual(0, manager.consecutive_proxy_failures)
        switch_mock.assert_not_called()

    def test_probe_retest_failure_counts_exactly_one_failure_event(self) -> None:
        self._activate_node()
        results = [
            {"ok": False, "error": "down-1"},
            {"ok": False, "error": "down-2"},
            {"ok": False, "error": "down-3"},
            {"ok": False, "error": "down-4"},
        ]
        calls, switch_mock = self._run_checker_rounds(results, rounds=2)

        # Two failure events, four probes: the retest is not a second
        # count, so after two rounds the counter is 2 -- not 4.
        self.assertEqual(4, calls["health"])
        self.assertEqual(2, manager.consecutive_proxy_failures)
        state = manager.get_state()
        self.assertFalse(state["proxy_ok"])
        self.assertIn("连续失败 2/3", state["proxy_error"])
        switch_mock.assert_not_called()

    def test_probe_threshold_counts_failure_events_not_probes(self) -> None:
        self._activate_node()
        results = [{"ok": False, "error": f"down-{i}"} for i in range(6)]
        calls, switch_mock = self._run_checker_rounds(results, rounds=3)

        # Recovery fires on the third failure *event* (sixth probe).
        # Had every probe counted, the threshold would have been hit
        # in round 2 and the counter would not be back at 0 here.
        self.assertEqual(6, calls["health"])
        switch_mock.assert_called_once_with()
        self.assertEqual(0, manager.consecutive_proxy_failures)

    # -- plan §五.1: tri-state display signal ---------------------------

    def test_display_status_degraded_window(self) -> None:
        process = self._activate_node()
        manager.set_state(tunnel_ready=True, proxy_ready=True, proxy_ok=True)

        self.assertEqual("connected", manager.connection_display_status())

        manager.set_state(proxy_ok=False)
        for count in (1, manager.PROXY_FAILURE_THRESHOLD - 1):
            manager.consecutive_proxy_failures = count
            self.assertEqual("degraded", manager.connection_display_status())
            state = manager.get_state()
            self.assertEqual("degraded", state["connection_display_status"])
            self.assertEqual(count, state["proxy_consecutive_failures"])
            self.assertEqual(
                manager.PROXY_FAILURE_THRESHOLD, state["proxy_failure_threshold"]
            )

        # Threshold reached: no longer the degraded window.
        manager.consecutive_proxy_failures = manager.PROXY_FAILURE_THRESHOLD
        self.assertEqual("disconnected", manager.connection_display_status())
        # No recorded failure event yet: not degraded either.
        manager.consecutive_proxy_failures = 0
        self.assertEqual("disconnected", manager.connection_display_status())
        # Process dead: flips regardless of the count.
        manager.consecutive_proxy_failures = 1
        process.running = False
        self.assertEqual("disconnected", manager.connection_display_status())
        # Still connecting: the busy card owns the display.
        process.running = True
        manager.is_connecting = True
        self.assertEqual("disconnected", manager.connection_display_status())
        manager.is_connecting = False

    def test_nodes_and_state_endpoints_expose_tristate_signals(self) -> None:
        self._activate_node("stage3-node")
        manager.set_state(tunnel_ready=True, proxy_ready=True, proxy_ok=True)
        base_url = self._serve()

        payload = self._get_json(base_url, "/api/nodes")
        rows = {n["id"]: n for n in payload["nodes"]}
        self.assertTrue(rows["stage3-node"]["active"])
        self.assertEqual("connected", payload["state"]["connection_display_status"])

        state_payload = self._get_json(base_url, "/api/state")
        self.assertEqual({"state"}, set(state_payload.keys()))
        light_state = state_payload["state"]
        self.assertEqual("connected", light_state["connection_display_status"])
        self.assertEqual(0, light_state["proxy_consecutive_failures"])
        self.assertEqual(
            manager.PROXY_FAILURE_THRESHOLD, light_state["proxy_failure_threshold"]
        )

        # Degraded window: the legacy /api/nodes active marking keeps
        # its exact old meaning (ready-only), while the new display
        # signal reports the tri-state.
        manager.set_state(proxy_ok=False)
        manager.consecutive_proxy_failures = 1
        payload = self._get_json(base_url, "/api/nodes")
        rows = {n["id"]: n for n in payload["nodes"]}
        self.assertFalse(rows["stage3-node"]["active"])
        self.assertEqual("degraded", payload["state"]["connection_display_status"])
        self.assertEqual(1, payload["state"]["proxy_consecutive_failures"])

        state_payload = self._get_json(base_url, "/api/state")
        self.assertEqual(
            "degraded", state_payload["state"]["connection_display_status"]
        )

    # -- plan §三 / §五.3: panel markers --------------------------------

    def test_panel_ip_display_markers(self) -> None:
        html = manager.INDEX_HTML

        # The old truncating cell and fixed-width header are gone.
        self.assertNotIn(
            '<td class="mono" style="white-space: nowrap; max-width: 220px;', html
        )
        self.assertNotIn('<th style="width: 220px;">IP 地址', html)
        self.assertIn("<th>IP 地址 : 端口</th>", html)

        # Node row: IP complete in .ip-main, port de-emphasised in
        # .ip-port, whole cell click-to-copy.
        self.assertIn('class="mono ip-cell"', html)
        self.assertIn(
            '<span class="ip-main">${esc(n.ip||n.remote_host)}</span>', html
        )
        self.assertIn('<span class="ip-port">:${n.remote_port}</span>', html)
        self.assertIn(
            "copyIpText('${esc(n.ip||n.remote_host)}', this, event)", html
        )

        # Active card: same treatment for its IP value.
        self.assertIn("active-ip-value", html)
        self.assertIn(
            "copyIpText('${esc(cardNode.ip || cardNode.remote_host)}', this, event)",
            html,
        )
        self.assertIn(
            '<span class="ip-port" style="font-size: 14px;">:${cardNode.remote_port}</span>',
            html,
        )

        # The copy handler itself: Clipboard API first, execCommand
        # fallback, 已复制 tip, and no alert() anywhere inside it.
        start = html.index("function copyIpText(ip, el, event)")
        body = html[start:html.index("function copyLogContent()", start)]
        self.assertIn("navigator.clipboard.writeText(ip)", body)
        self.assertIn('document.execCommand("copy")', body)
        self.assertIn("ip-copied-tip", body)
        self.assertIn("已复制", body)
        self.assertNotIn("alert(", body)

    def test_panel_tristate_and_busy_polling_markers(self) -> None:
        html = manager.INDEX_HTML

        # Tri-state card wiring (plan §五.1).
        self.assertIn('state.connection_display_status === "degraded"', html)
        self.assertIn("const cardNode = activeNode || degradedNode;", html)
        self.assertIn('class="badge degraded"', html)
        self.assertIn("探测异常", html)
        self.assertIn("state.proxy_consecutive_failures", html)

        # Busy-period polling split (plan §五.3): lightweight state
        # endpoint, state-first helper, and the 10s tick no longer
        # pausing wholesale while busy.
        self.assertIn("async function fetchStateSnapshot()", html)
        self.assertIn('"./api/state"', html)
        self.assertIn("function applyStateSnapshot(nextState)", html)
        self.assertIn("async function refreshStateFirst()", html)

        tick_start = html.index("// 每 10 秒在前台自动更新节点与状态")
        tick = html[tick_start:html.index("}, 10000);", tick_start)]
        self.assertIn(
            "const busy = Boolean(state.is_connecting || state.maintenance_running);",
            tick,
        )
        self.assertIn("await refreshStateFirst();", tick)
        self.assertNotIn(
            "!state.is_connecting && !state.maintenance_running &&", tick
        )

        # The refresh (更新中) polling judges completion on the fresh
        # state fetched by the same state-first split.
        refresh_start = html.index("function startRefreshPolling()")
        refresh = html[
            refresh_start:html.index("function startConnectionPolling()", refresh_start)
        ]
        self.assertIn("await refreshStateFirst();", refresh)
        self.assertIn("if (!state.maintenance_running) {", refresh)


class Plus127Stage1RiskScoreDisplayTests(unittest.TestCase):
    """1.2.7 stage 1: risk-score display fixes (plan §一).

    Two changes, both in the panel script only: esc() no longer
    swallows the number 0 (null/undefined/"" still collapse to "",
    string escaping is byte-identical), and the risk-score cell
    renders through riskScoreCellHtml(), which shows a genuine 0 and
    colours the number by band (0-19 green, 20-29 light green,
    30-49 orange, 50-100 red). Behaviour is verified by executing
    the panel's own esc()/riskScoreCellHtml() source under node,
    the same extraction style as the dashboard syntax check.
    """

    def _run_risk_cell_harness(self) -> dict:
        if not shutil.which("node"):
            self.skipTest("Node.js is not installed; JS behaviour checks skipped")
        html = manager.INDEX_HTML
        esc_line = next(
            line for line in html.splitlines() if line.startswith("const esc=")
        )
        cell_start = html.index("function riskScoreCellHtml(n) {")
        cell_end = html.index("function riskScoreTitle(n) {", cell_start)
        script = "\n".join(
            [
                esc_line,
                html[cell_start:cell_end],
                "const cellCases = [0, 1, 19, 20, 29, 30, 49, 50, 100, null, undefined];",
                "const out = {",
                "  cells: cellCases.map(s => riskScoreCellHtml({risk_display_score: s})),",
                "  escCases: [esc(null), esc(undefined), esc(''), esc(0), esc(1),"
                " esc('plain'), esc('a<b>&\"\\''), esc(false), esc('0')],",
                "};",
                "console.log(JSON.stringify(out));",
            ]
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".js", encoding="utf-8", delete=False
        ) as handle:
            handle.write(script)
            script_path = handle.name
        try:
            result = subprocess.run(
                ["node", script_path],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        finally:
            Path(script_path).unlink(missing_ok=True)
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout.strip())

    def test_panel_risk_score_cell_markers(self) -> None:
        html = manager.INDEX_HTML

        # The cell delegates to the band helper; the old inline
        # rendering (whose esc() call swallowed a genuine 0) is gone,
        # while the tooltip wiring is untouched.
        self.assertIn('title="${esc(riskTitle)}">${riskScoreCellHtml(n)}</td>', html)
        self.assertNotIn('? "—" : esc(n.risk_display_score)', html)

        # Band thresholds and colours are pinned verbatim.
        start = html.index("function riskScoreCellHtml(n) {")
        body = html[start:html.index("function riskScoreTitle(n) {", start)]
        self.assertIn('if (score === null || score === undefined) return "—";', body)
        self.assertIn('score < 20 ? "#34d399"', body)
        self.assertIn('score < 30 ? "#a3e635"', body)
        self.assertIn('score < 50 ? "#f59e0b"', body)
        self.assertIn('"#f87171"', body)
        self.assertIn("font-weight: 700", body)
        self.assertIn("${esc(score)}", body)

        # esc() numeric fidelity: the falsy `|| ""` form is gone and
        # only null/undefined collapse to "".
        self.assertIn('const esc=s=>String(s===null||s===undefined?"":s)', html)
        self.assertNotIn("const esc=s=>String(s||", html)

        # The tooltip function keeps its 1.2.6 wording verbatim.
        title_start = html.index("function riskScoreTitle(n) {")
        title_body = html[
            title_start:html.index("async function checkNodeScore", title_start)
        ]
        self.assertIn("风险系数 ${n.risk_display_score}（0–100，越高越危险）", title_body)

    def test_risk_cell_zero_and_band_boundaries(self) -> None:
        out = self._run_risk_cell_harness()
        green = '<span style="color: #34d399; font-weight: 700;">{}</span>'
        light = '<span style="color: #a3e635; font-weight: 700;">{}</span>'
        orange = '<span style="color: #f59e0b; font-weight: 700;">{}</span>'
        red = '<span style="color: #f87171; font-weight: 700;">{}</span>'
        self.assertEqual(
            [
                green.format(0),  # the fix: a genuine 0 renders, green
                green.format(1),
                green.format(19),
                light.format(20),
                light.format(29),
                orange.format(30),
                orange.format(49),
                red.format(50),
                red.format(100),
                "—",  # null: unqueried, uncoloured
                "—",  # undefined: same
            ],
            out["cells"],
        )

    def test_esc_regression_lock(self) -> None:
        out = self._run_risk_cell_harness()
        self.assertEqual(
            [
                "",  # null -> "" (unchanged from baseline)
                "",  # undefined -> "" (unchanged)
                "",  # "" -> "" (unchanged)
                "0",  # 0 -> "0" (THE fix; baseline returned "")
                "1",  # other numbers stringify (unchanged)
                "plain",
                "a&lt;b&gt;&amp;&quot;&#039;",  # escaping verbatim (unchanged)
                "false",  # boolean false now stringifies (was ""); no
                # current call site passes a boolean -- locked so a
                # future one behaves deliberately, see impl notes.
                "0",  # the string "0" (unchanged)
            ],
            out["escCases"],
        )


class Plus127Stage2ConnectionPriorityTests(unittest.TestCase):
    """1.2.7 stage 2: connection priority over probing (plan §二).

    Covers the connection-priority signal (set by begin_connection_
    attempt, cleared by finish_connection_attempt), its preemption of
    probe batches inside test_multiple_nodes, the maintenance re-order
    (connect from already-known available nodes BEFORE any probing),
    the suspension of new probe work while the signal is set, the
    startup reset of leftover "testing" rows, and connected-maintenance
    equivalence with the pre-change flow.
    """

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.root = root
        self.path_patches = [
            mock.patch.object(manager, "DATA_DIR", root),
            mock.patch.object(manager, "CONFIG_DIR", root / "configs"),
            mock.patch.object(manager, "CONFIG_STORE_FILE", root / "node_configs.json"),
            mock.patch.object(manager, "NODES_FILE", root / "nodes.json"),
            mock.patch.object(manager, "STATE_FILE", root / "state.json"),
            mock.patch.object(manager, "AUTH_FILE", root / "auth.txt"),
            mock.patch.object(manager, "BLACKLIST_FILE", root / "blacklist.json"),
            mock.patch.object(manager, "API_CACHE_FILE", root / "api_snapshot.csv"),
            mock.patch.object(manager, "API_CACHE_META_FILE", root / "api_snapshot.meta.json"),
            mock.patch.object(manager, "BUNDLED_SNAPSHOT_FILE", root / "bundled_snapshot.csv"),
            mock.patch.object(manager, "RETAINED_ARCHIVE_FILE", root / "retained_archive.json"),
            mock.patch.object(manager.vpn_utils, "DATA_DIR", root),
            mock.patch.object(manager.vpn_utils, "IP_CACHE_FILE", root / "ip_cache.json"),
        ]
        for patcher in self.path_patches:
            patcher.start()
        manager.ensure_dirs()
        manager._config_store_cache["key"] = None
        manager._config_store_cache["data"] = {}
        self._saved_restart_first = manager._first_maintain_after_startup
        manager._first_maintain_after_startup = True
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
        manager.connection_priority_event.clear()
        manager._switch_watch_last_id = ""
        manager.clear_switch_sweep_pending()
        manager._retained_count_cache["key"] = None
        manager._retained_count_cache["count"] = 0

    def tearDown(self) -> None:
        if manager.connection_attempt_lock.locked():
            manager.connection_attempt_lock.release()
        manager.connection_priority_event.clear()
        manager.background_refill_cancel_event.set()
        manager.background_refill_thread = None
        manager._first_maintain_after_startup = self._saved_restart_first
        manager.active_openvpn_node_id = ""
        manager._switch_watch_last_id = ""
        manager.clear_switch_sweep_pending()
        manager._config_store_cache["key"] = None
        manager._config_store_cache["data"] = {}
        manager._retained_count_cache["key"] = None
        manager._retained_count_cache["count"] = 0
        for patcher in reversed(self.path_patches):
            patcher.stop()
        self.temp_dir.cleanup()

    # -- helpers ------------------------------------------------------

    def _node(self, node_id: str, ip: str, country_short: str = "JP", **extra) -> dict:
        node = {
            "id": node_id,
            "country": "日本" if country_short == "JP" else "韩国",
            "country_short": country_short,
            "ip": ip,
            "remote_host": ip,
            "remote_port": 1194,
            "proto": "udp",
            "ping": 10,
            "score": 100,
            "speed": 1000,
            "sessions": 1,
            "latency_ms": 0,
            "config_file": str(manager.CONFIG_DIR / f"{node_id}.ovpn"),
            "probe_status": "not_checked",
            "probe_message": "",
            "probed_at": 0,
            "retention_status": "normal",
            "last_seen_at": manager.time.time(),
            "source_present": 1,
            "consecutive_failures": 0,
            "last_success_at": 0,
            "active": False,
        }
        node.update(extra)
        return node

    def _jp_ui_cfg(self) -> dict:
        return {
            "connection_enabled": True,
            "routing_mode": "fixed_region",
            "force_country": "JP",
            "routing_ip_type": "all",
            "favorite_node_ids": [],
            "retained_pool_enabled": True,
            "discovery_countries": [],
        }

    # -- ① maintenance connects before probing -------------------------

    def test_maintain_connects_known_available_before_any_probing(self) -> None:
        jp_prev = self._node(
            "jp-a", "198.51.100.21", probe_status="available", probed_at=111.0
        )
        kr_prev = self._node(
            "kr-b", "198.51.100.22", country_short="KR",
            probe_status="available", probed_at=111.0,
        )
        manager.write_json(manager.NODES_FILE, [jp_prev, kr_prev])
        candidates = [self._node("jp-a", "198.51.100.21"), self._node("kr-b", "198.51.100.22", country_short="KR")]

        calls: list[str] = []
        running = {"value": False}

        def fake_switch() -> None:
            calls.append("auto_switch")
            running["value"] = True

        def fake_test(ids, target_available=None, **kwargs):
            calls.append("test_multiple_nodes")
            return [
                {
                    "id": ids[0],
                    "latency_ms": 5,
                    "probe_status": "available",
                    "probe_message": "ok",
                    "probed_at": 222.0,
                }
            ]

        def fake_sweep(systemic_probe_failure=""):
            calls.append("run_full_sweep")
            return {"skipped": True, "tested": 0, "available": 0, "unavailable": 0}

        with (
            mock.patch.object(manager, "fetch_candidates", return_value=candidates),
            mock.patch.object(manager, "load_ui_config", return_value=self._jp_ui_cfg()),
            mock.patch.object(
                manager, "active_openvpn_running", side_effect=lambda: running["value"]
            ),
            mock.patch.object(manager, "auto_switch_node", side_effect=fake_switch),
            mock.patch.object(manager, "test_multiple_nodes", side_effect=fake_test),
            mock.patch.object(manager, "sweep_retained_nodes", return_value=0),
            mock.patch.object(manager, "run_full_sweep", side_effect=fake_sweep),
            mock.patch.object(manager, "log_to_json"),
        ):
            message = manager.maintain_valid_nodes(force=False, trigger="auto")

        # The pre-connect switch is the FIRST action of the round: it
        # precedes every probe batch in the round.
        self.assertEqual("auto_switch", calls[0])
        self.assertLess(calls.index("auto_switch"), calls.index("test_multiple_nodes"))
        self.assertTrue(running["value"])
        # Once connected, the fast-connect block skips itself (its
        # condition requires no running tunnel) and the round completes
        # as an ordinary connected maintain: one periodic test batch,
        # then the gated terminal sweep, baseline message shape.
        self.assertEqual(1, calls.count("auto_switch"))
        self.assertTrue(
            message.startswith(
                "Fetched 2 nodes. Tested 1 prioritized non-active nodes."
            )
        )

    # -- ② signal preempts probe batches, results persist --------------

    def test_probe_batch_yields_to_connection_priority_and_persists(self) -> None:
        ids = [f"n{i}" for i in range(1, 13)]
        nodes = []
        store = {}
        for i, nid in enumerate(ids, start=1):
            nodes.append(self._node(nid, f"198.51.100.{30 + i}"))
            store[nid] = f"client\nremote 198.51.100.{30 + i} 1194 udp\n# cfg-{nid}\n"
        manager.write_json(manager.NODES_FILE, nodes)
        manager.write_config_store(store)

        def fake_openvpn(config_path, **kwargs):
            text = Path(config_path).read_text(encoding="utf-8")
            if "# cfg-n5" in text:
                # A connection attempt begins while batch 1 is in
                # flight; the batch loop must stop before batch 2.
                manager.connection_priority_event.set()
            return True, "ok", None

        with (
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=5),
            mock.patch.object(manager.vpn_utils, "enrich_ip_info", return_value=None),
            mock.patch.object(
                manager, "run_openvpn_until_ready", side_effect=fake_openvpn
            ),
            mock.patch.object(manager, "log_to_json"),
        ):
            results = manager.test_multiple_nodes(ids)

        # Batch 1 (5 workers) completed and returned; batches 2-3
        # never started.
        self.assertEqual(5, len(results))
        self.assertEqual({f"n{i}" for i in range(1, 6)}, {r["id"] for r in results})
        on_disk = {n["id"]: n for n in manager.read_nodes()}
        for i in range(1, 6):
            self.assertEqual("available", on_disk[f"n{i}"]["probe_status"])
            self.assertGreater(on_disk[f"n{i}"]["probed_at"], 0)
        for i in range(6, 13):
            self.assertEqual("not_checked", on_disk[f"n{i}"]["probe_status"])
        # No fresh "testing" residue anywhere after the preemption.
        self.assertFalse(
            any(n.get("probe_status") == "testing" for n in on_disk.values())
        )

    def test_maintain_starts_no_probes_while_connection_priority_set(self) -> None:
        nodes = [self._node(f"m{i}", f"198.51.100.{40 + i}") for i in range(1, 4)]
        store = {
            n["id"]: f"client\nremote {n['ip']} 1194 udp\n# cfg-{n['id']}\n"
            for n in nodes
        }
        manager.write_json(manager.NODES_FILE, nodes)
        manager.write_config_store(store)
        candidates = [self._node(f"m{i}", f"198.51.100.{40 + i}") for i in range(1, 4)]
        manager.connection_priority_event.set()
        sweep_mock = mock.Mock(return_value=0)
        switch_mock = mock.Mock()

        with (
            mock.patch.object(manager, "fetch_candidates", return_value=candidates),
            mock.patch.object(manager, "load_ui_config", return_value=self._jp_ui_cfg()),
            mock.patch.object(manager, "active_openvpn_running", return_value=False),
            mock.patch.object(manager, "auto_switch_node", switch_mock),
            mock.patch.object(manager, "sweep_retained_nodes", sweep_mock),
            mock.patch.object(manager.vpn_utils, "ping_latency_ms", return_value=5),
            mock.patch.object(manager.vpn_utils, "enrich_ip_info", return_value=None),
            mock.patch.object(
                manager,
                "run_openvpn_until_ready",
                side_effect=AssertionError("probe must not run under connection priority"),
            ),
            mock.patch.object(manager, "log_to_json"),
        ):
            message = manager.maintain_valid_nodes(force=False, trigger="auto")

        # Both probe stages self-stopped at their first batch check:
        # nothing was tested, nothing connected, the liveness sweep
        # was not started.
        self.assertIn("Tested 0 prioritized non-active nodes.", message)
        switch_mock.assert_not_called()
        sweep_mock.assert_not_called()
        on_disk = manager.read_nodes()
        self.assertTrue(
            all(n.get("probe_status") == "not_checked" for n in on_disk)
        )

    # -- ③ startup reset of "testing" residue --------------------------

    def test_reset_stale_testing_nodes(self) -> None:
        stale = self._node(
            "stale-1", "198.51.100.51",
            probe_status="testing",
            probe_message="正在检测节点连通性...",
            probed_at=12345.0,
            latency_ms=7,
            consecutive_failures=2,
        )
        healthy = self._node(
            "ok-1", "198.51.100.52", probe_status="available", probed_at=999.0
        )
        fresh = self._node("new-1", "198.51.100.53")
        manager.write_json(manager.NODES_FILE, [stale, healthy, fresh])

        with mock.patch.object(manager, "log_to_json"):
            reset_count = manager.reset_stale_testing_nodes()
            second_count = manager.reset_stale_testing_nodes()

        self.assertEqual(1, reset_count)
        self.assertEqual(0, second_count)  # idempotent
        on_disk = {n["id"]: n for n in manager.read_nodes()}
        reset_row = on_disk["stale-1"]
        self.assertEqual("not_checked", reset_row["probe_status"])
        self.assertEqual("", reset_row["probe_message"])
        self.assertEqual(0, reset_row["probed_at"])
        # Nothing else on the reset row changes.
        self.assertEqual(7, reset_row["latency_ms"])
        self.assertEqual(2, reset_row["consecutive_failures"])
        # Other rows are byte-for-byte the records that were written.
        self.assertEqual(healthy, on_disk["ok-1"])
        self.assertEqual(fresh, on_disk["new-1"])

    # -- ④ signal lifecycle + connected-maintenance equivalence --------

    def test_connection_priority_signal_lifecycle(self) -> None:
        self.assertFalse(manager.connection_priority_event.is_set())
        token, cancel_event = manager.begin_connection_attempt()
        try:
            self.assertTrue(manager.connection_priority_event.is_set())
            self.assertTrue(manager.is_connecting)
            # A rejected (busy) begin must not disturb the live flag.
            with self.assertRaises(RuntimeError):
                manager.begin_connection_attempt()
            self.assertTrue(manager.connection_priority_event.is_set())
        finally:
            manager.finish_connection_attempt(token, cancel_event)
        self.assertFalse(manager.connection_priority_event.is_set())
        self.assertFalse(manager.is_connecting)
        # The attempt lock is free again for the next attempt.
        token2, cancel_event2 = manager.begin_connection_attempt()
        manager.finish_connection_attempt(token2, cancel_event2)
        self.assertFalse(manager.connection_priority_event.is_set())

    def test_connected_maintain_matches_baseline_flow(self) -> None:
        manager._first_maintain_after_startup = False
        candidate = self._node("c1", "198.51.100.61")
        calls: list[str] = []

        def fake_test(ids, target_available=None, **kwargs):
            calls.append("test_multiple_nodes")
            return [
                {
                    "id": ids[0],
                    "latency_ms": 5,
                    "probe_status": "available",
                    "probe_message": "ok",
                    "probed_at": 222.0,
                }
            ]

        def fake_sweep(systemic_probe_failure=""):
            calls.append("run_full_sweep")
            return {
                "skipped": False, "tested": 3, "available": 2,
                "unavailable": 1, "interrupted": False,
            }

        switch_mock = mock.Mock(side_effect=lambda: calls.append("auto_switch"))
        with (
            mock.patch.object(manager, "fetch_candidates", return_value=[candidate]),
            mock.patch.object(manager, "load_ui_config", return_value=self._jp_ui_cfg()),
            mock.patch.object(manager, "active_openvpn_running", return_value=True),
            mock.patch.object(manager, "auto_switch_node", switch_mock),
            mock.patch.object(manager, "test_multiple_nodes", side_effect=fake_test),
            mock.patch.object(manager, "sweep_retained_nodes", return_value=0),
            mock.patch.object(manager, "run_full_sweep", side_effect=fake_sweep),
            mock.patch.object(manager, "log_to_json"),
        ):
            message = manager.maintain_valid_nodes(force=False, trigger="auto")

        # Already connected: no pre-connect attempt, no switch at all;
        # the round is periodic testing followed by the gated sweep,
        # with the baseline message shape.
        switch_mock.assert_not_called()
        self.assertEqual(["test_multiple_nodes", "run_full_sweep"], calls)
        self.assertEqual(
            "Fetched 1 nodes. Tested 1 prioritized non-active nodes. "
            "全量检测：共 3 个，可用 2 个，不可用 1 个。",
            message,
        )
