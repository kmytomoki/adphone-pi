# -*- coding: utf-8 -*-
"""ブリッジの v2（mesh/）モードと mesh/config.py のテスト。

偽の無線（スレッドをまたいで共有するハブ）でブリッジと相手ノードをつなぎ、
BLE → メッシュ → 相手、相手 → メッシュ → BLE の往復を確かめる。
"""
from __future__ import annotations

import asyncio
import configparser
import os
import sys
import tempfile
import threading
import time
import types
import unittest
from collections import deque

_LPWA_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _LPWA_DIR)
sys.path.insert(0, os.path.join(_LPWA_DIR, "tests"))

import test_phase1_routing as phase1  # noqa: E402  (setting.ini と bless のスタブを用意する)

from mesh import packet as P  # noqa: E402
from mesh.config import load_mesh_config, make_router_factory  # noqa: E402
from mesh.realtime import RealtimeNode  # noqa: E402

GROUP_HEX = bytes(range(32)).hex()


def _cfg(state_dir: str, **kw) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    values = {"own_address": "2", "hop_limit": "3", "role": "ROUTER", "node_name": "避難所A",
              "group_key_hex": GROUP_HEX, "group_key_id": "1", "state_dir": state_dir}
    values.update(kw)
    cfg["E220-900JP"] = values
    return cfg


class _Hub:
    def __init__(self):
        self.ports = []
        self.lock = threading.Lock()


class _Port:
    def __init__(self, hub: _Hub, address: int):
        self.hub, self.address = hub, address
        self.inbox: deque[bytes] = deque()
        hub.ports.append(self)

    def send(self, pkt: bytes) -> None:
        with self.hub.lock:
            for p in self.hub.ports:
                if p is not self:
                    p.inbox.append(pkt)

    def recv(self, timeout: float):
        with self.hub.lock:
            if self.inbox:
                return self.inbox.popleft()
        time.sleep(min(timeout, 0.005))
        return None

    @property
    def last_rssi(self):
        return -100


class _Char:
    def __init__(self):
        self.value = bytearray()


class _FakeServer:
    def __init__(self):
        self.chars: dict[str, _Char] = {}
        self.notified: list[bytes] = []

    def get_characteristic(self, uuid):
        return self.chars.setdefault(uuid, _Char())

    def update_value(self, service, uuid):
        self.notified.append(bytes(self.chars[uuid].value))


class MeshConfigTest(unittest.TestCase):
    def test_load(self):
        with tempfile.TemporaryDirectory() as d:
            mc = load_mesh_config(_cfg(d), os.path.join(d, "setting.ini"))
            self.assertEqual((mc.address, mc.role, mc.hop_limit, mc.node_name), (2, "ROUTER", 3, "避難所A"))
            self.assertEqual((mc.group_key, mc.group_key_id), (bytes(range(32)), 1))
            self.assertEqual(mc.identity_path, os.path.join(d, "identity.key"))

    def test_default_state_dir_is_next_to_setting_ini(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = _cfg("")
            mc = load_mesh_config(cfg, os.path.join(d, "setting.ini"))
            self.assertEqual(mc.state_dir, os.path.join(d, "state"))

    def test_bad_role(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ValueError):
            load_mesh_config(_cfg(d, role="KING"), os.path.join(d, "setting.ini"))

    def test_identity_survives_restart(self):
        with tempfile.TemporaryDirectory() as d:
            mc = load_mesh_config(_cfg(d), os.path.join(d, "setting.ini"))
            _, first, _ = make_router_factory(mc)
            _, again, _ = make_router_factory(mc)
            self.assertEqual(first.ed_pub, again.ed_pub)


class BridgeV2Test(unittest.TestCase):
    def test_ble_roundtrip_over_mesh(self):
        bridge = phase1._load_bridge()
        import lora_e220_b
        import mesh.realtime as rt

        hub = _Hub()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        orig_port, orig_cfg = rt.E220Port, lora_e220_b.load_config_parser
        orig_target = lora_e220_b.TARGET_ADDRESS
        rt.E220Port = lambda: _Port(hub, lora_e220_b.SELF_ADDRESS)
        lora_e220_b.load_config_parser = lambda path=None: _cfg(os.path.join(tmp.name, "bridge"))

        def restore():
            rt.E220Port, lora_e220_b.load_config_parser = orig_port, orig_cfg
            lora_e220_b.TARGET_ADDRESS = orig_target
            bridge._mesh_stop.set()
            bridge._mesh_node = None
            bridge.server = None
        self.addCleanup(restore)

        # 相手ノード（アドレス 7）
        peer_mc = load_mesh_config(_cfg(os.path.join(tmp.name, "peer"), own_address="7"),
                                   os.path.join(tmp.name, "setting.ini"))
        factory, _, _ = make_router_factory(peer_mc)
        got = []
        peer = RealtimeNode(_Port(hub, 7), factory, address=7, on_deliver=got.append)

        async def scenario():
            bridge._loop = asyncio.get_running_loop()
            bridge.server = _FakeServer()
            bridge._mesh_stop.clear()
            thread = bridge._start_mesh()
            self.assertTrue(thread.is_alive())

            # 鍵を交換する
            bridge._mesh_node.post(bridge._mesh_node.router.announce)
            peer.router.announce()
            await self._pump(peer, 0.5)

            # BLE から書き込み → 相手に届く
            lora_e220_b.TARGET_ADDRESS = 7
            tx = types.SimpleNamespace(uuid=bridge.TX_CHAR_UUID)
            bridge.write_request(tx, bytearray("物資が足りません".encode()))
            await self._pump(peer, 1.0, until=lambda: got)
            self.assertEqual([d.payload.decode() for d in got], ["物資が足りません"])

            # 相手からブリッジ宛て → BLE に通知される
            notified_before = len(bridge.server.notified)
            peer.router.send(lora_e220_b.SELF_ADDRESS, "了解".encode())
            await self._pump(peer, 1.0, until=lambda: len(bridge.server.notified) > notified_before)
            self.assertIn("了解".encode(), bridge.server.notified)

            # グループ鍵でのブロードキャスト
            lora_e220_b.TARGET_ADDRESS = P.BROADCAST_ADDR
            bridge.write_request(tx, bytearray(b"all hands"))
            await self._pump(peer, 1.0, until=lambda: len(got) >= 2)
            self.assertEqual(got[-1].payload, b"all hands")
            self.assertEqual(got[-1].dest, P.BROADCAST_ADDR)

            bridge._mesh_stop.set()
            thread.join(2)

        asyncio.run(scenario())

    @staticmethod
    async def _pump(node: RealtimeNode, seconds: float, until=None):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            node.poll(0)
            await asyncio.sleep(0.01)
            if until is not None and until():
                return


if __name__ == "__main__":
    unittest.main()
