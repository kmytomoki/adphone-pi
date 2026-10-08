# -*- coding: utf-8 -*-
"""ブリッジの v2（mesh/）モードと mesh/config.py のテスト。

偽の無線（スレッドをまたいで共有するハブ）でブリッジと相手ノードをつなぎ、
BLE → メッシュ → 相手、相手 → メッシュ → BLE の往復を確かめる。
"""
from __future__ import annotations

import asyncio
import configparser
import json
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

from mesh import bleproto as B  # noqa: E402
from mesh import packet as P  # noqa: E402
from mesh.gateway import hello_payload  # noqa: E402
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

    def test_routing_choice(self):
        from mesh.reliable import ReliableRouter
        from mesh.router import ManagedFloodRouter
        from test_mesh_v2 import _Ctx
        with tempfile.TemporaryDirectory() as d:
            for routing, cls in (("routed", ReliableRouter), ("flood", ManagedFloodRouter)):
                mc = load_mesh_config(_cfg(os.path.join(d, routing), routing=routing),
                                      os.path.join(d, "setting.ini"))
                factory, _, _ = make_router_factory(mc)
                self.assertIs(type(factory(_Ctx(2))), cls)
            with self.assertRaises(ValueError):
                load_mesh_config(_cfg(d, routing="aodv"), os.path.join(d, "setting.ini"))

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
            if bridge._gateway is not None:
                time.sleep(0.3)                 # メッシュのスレッドが止まるのを待ってから閉じる
                bridge._gateway.store.close()
            bridge._gateway = None
            bridge.server = None
        self.addCleanup(restore)

        # 相手ノード（アドレス 7）
        peer_mc = load_mesh_config(_cfg(os.path.join(tmp.name, "peer"), own_address="7"),
                                   os.path.join(tmp.name, "setting.ini"))
        factory, _, _ = make_router_factory(peer_mc)
        got = []
        peer = RealtimeNode(_Port(hub, 7), factory, address=7, on_deliver=got.append)

        def notified_frames():
            r = B.Reassembler()
            out = []
            for c in bridge.server.notified:
                got = r.add(c, 0)
                if got:
                    out.append(B.Frame.decode(got[1]))
            return out

        def statuses(app_id):
            return [f.payload[0] for f in notified_frames()
                    if f.kind == B.KIND_STATUS and f.msg_id == app_id]

        tx = types.SimpleNamespace(uuid=bridge.TX_CHAR_UUID)

        def phone_write(frame):
            for c in B.chunk(frame.encode(), stream=5):
                bridge.write_request(tx, bytearray(c))

        async def scenario():
            bridge._loop = asyncio.get_running_loop()
            bridge.server = _FakeServer()
            bridge._mesh_stop.clear()
            lora_e220_b.TARGET_ADDRESS = 7          # 旧アプリの生テキストの送り先
            thread = bridge._start_mesh()
            notifier = asyncio.create_task(bridge._ble_notifier())
            self.assertTrue(thread.is_alive())

            # 鍵を交換する
            bridge._mesh_node.post(bridge._mesh_node.router.announce)
            peer.router.announce()
            await self._pump(peer, 0.5)

            # スマホが HELLO → INFO が返る
            phone_write(B.Frame(B.KIND_HELLO, payload=hello_payload(b"phone-01", 0)))
            await self._pump(peer, 0.5, until=lambda: any(f.kind == B.KIND_INFO for f in notified_frames()))
            info = json.loads([f for f in notified_frames() if f.kind == B.KIND_INFO][0].payload)
            self.assertEqual((info["addr"], info["name"]), (lora_e220_b.SELF_ADDRESS, "避難所A"))

            # スマホ → 相手（7）。届いて、配送状態が「届いた」になる
            phone_write(B.Frame(B.KIND_MSG, 100, dest=7, payload="物資が足りません".encode()))
            await self._pump(peer, 3.0, until=lambda: B.ST_DELIVERED in statuses(100))
            self.assertEqual([d.payload.decode() for d in got], ["物資が足りません"])
            self.assertEqual(statuses(100), [B.ST_SENT, B.ST_DELIVERED])

            # 相手からブリッジ宛て → スマホに MSG で通知される
            peer.router.send(lora_e220_b.SELF_ADDRESS, "了解".encode())
            await self._pump(peer, 2.0, until=lambda: any(
                f.kind == B.KIND_MSG and f.payload == "了解".encode() for f in notified_frames()))
            msg = [f for f in notified_frames() if f.kind == B.KIND_MSG][-1]
            self.assertEqual((msg.src, msg.payload.decode()), (7, "了解"))

            # グループ鍵でのブロードキャスト
            phone_write(B.Frame(B.KIND_MSG, 101, dest=B.BROADCAST, payload=b"all hands"))
            await self._pump(peer, 2.0, until=lambda: len(got) >= 2)
            self.assertEqual((got[-1].payload, got[-1].dest), (b"all hands", P.BROADCAST_ADDR))
            self.assertEqual(statuses(101)[0], B.ST_SENT)

            # 旧アプリの生テキスト（エコーはしない）
            bridge.write_request(tx, bytearray("ADCH|v1|旧".encode()))
            await self._pump(peer, 2.0, until=lambda: len(got) >= 3)
            self.assertEqual(got[-1].payload.decode(), "ADCH|v1|旧")

            bridge._mesh_stop.set()
            thread.join(2)
            notifier.cancel()

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
