# -*- coding: utf-8 -*-
"""ルーティング改善 Phase 1 のテスト（ROUTING_PLAN.md 参照）。

実機なしで動く: setting.ini は一時ファイル、シリアルは偽物、bless はスタブに差し替える。

    cd Raspberry/lpwa && python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import asyncio
import importlib
import os
import subprocess
import sys
import tempfile
import types
import unittest

_LPWA_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BRIDGE_DIR = os.path.join(_LPWA_DIR, "..", "ble_final_version")
sys.path.insert(0, _LPWA_DIR)

_INI = """[E220-900JP]
own_address=2  # コメントつきでも読めること
target_address=3
ttl=3
rssi_byte_flag=1
packet_gap_sec=0.05
transport_frame_enabled=1
transport_legacy_fallback=0
relay_jitter_ms=0
"""
_tmp = tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False, encoding="utf-8")
_tmp.write(_INI)
_tmp.close()
os.environ["ADREN_LPWA_CONFIG"] = _tmp.name

import lora_e220_b as radio  # noqa: E402
import adhoc_crypto as crypto  # noqa: E402


class FakeSerial:
    """in_waiting / read だけを持つ偽シリアル。chunks を 1 回の読み取りごとに 1 つ返す。"""

    def __init__(self, chunks: list[bytes]):
        self.chunks = list(chunks)
        self.is_open = True
        self.written = bytearray()
        self.out_waiting = 0

    @property
    def in_waiting(self) -> int:
        return len(self.chunks[0]) if self.chunks else 0

    def read(self, n: int) -> bytes:
        return self.chunks.pop(0)

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    def flush(self) -> None:
        pass


def _air(payload: bytes, rssi: int = -80) -> bytes:
    """E220 が UART に出すバイト列（フレーム + RSSI バイト）"""
    return radio._wrap_frame(payload) + bytes([rssi & 0xFF])


def _reset_rx(chunks: list[bytes]) -> FakeSerial:
    radio._rx_buf.clear()
    radio._rx_ready.clear()
    radio._rx_last_byte_time = 0.0
    ser = FakeSerial(chunks)
    radio._serial_instance = ser
    return ser


class ConfigTest(unittest.TestCase):
    def test_reads_values_with_inline_comment(self):
        self.assertEqual(radio.SELF_ADDRESS, 2)
        self.assertEqual(radio.TARGET_ADDRESS, 3)
        self.assertEqual(radio.CONFIG_PATH, _tmp.name)

    def test_missing_config_stops_startup(self):
        env = dict(os.environ, ADREN_LPWA_CONFIG=os.path.join(_LPWA_DIR, "no_such.ini"))
        r = subprocess.run([sys.executable, "-c", "import lora_e220_b"], cwd=_LPWA_DIR,
                           env=env, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("setting.ini", r.stderr)

    def test_missing_own_address_stops_startup(self):
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as f:
            f.write("[E220-900JP]\ntarget_address=1\n")
        try:
            env = dict(os.environ, ADREN_LPWA_CONFIG=f.name)
            r = subprocess.run([sys.executable, "-c", "import lora_e220_b"], cwd=_LPWA_DIR,
                               env=env, capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("own_address", r.stderr)
        finally:
            os.unlink(f.name)


class E220AddressingTest(unittest.TestCase):
    def test_module_header_is_always_broadcast(self):
        ser = _reset_rx([])
        radio.lora_send(b"x")
        self.assertEqual(bytes(ser.written[:3]), b"\xff\xff\x00")


class FrameStreamTest(unittest.TestCase):
    def test_two_back_to_back_packets_are_split(self):
        buf = bytearray(_air(b"first", -70) + _air(b"second", -90))
        frames = radio._extract_frames(buf, rssi_byte=True)
        self.assertEqual(frames, [(b"first", -70), (b"second", -90)])
        self.assertEqual(buf, bytearray())

    def test_partial_frame_is_kept(self):
        whole = _air(b"hello world")
        buf = bytearray(whole[:6])
        self.assertEqual(radio._extract_frames(buf, rssi_byte=True), [])
        buf.extend(whole[6:])
        self.assertEqual(radio._extract_frames(buf, rssi_byte=True), [(b"hello world", -80)])

    def test_leading_noise_is_skipped(self):
        # 一部のファームが付ける 3 バイトのルーティングヘッダなど
        buf = bytearray(b"\x00\x02\x00" + _air(b"payload"))
        self.assertEqual(radio._extract_frames(buf, rssi_byte=True), [(b"payload", -80)])

    def test_corrupted_frame_does_not_hide_next_one(self):
        bad = bytearray(_air(b"broken"))
        bad[7] ^= 0xFF
        buf = bytearray(bytes(bad) + _air(b"good"))
        self.assertEqual(radio._extract_frames(buf, rssi_byte=True), [(b"good", -80)])

    def test_false_magic_in_noise(self):
        buf = bytearray(b"AD\x07" + _air(b"ok"))   # バージョン不一致の "AD"
        self.assertEqual(radio._extract_frames(buf, rssi_byte=True), [(b"ok", -80)])


class LoraRecvTest(unittest.TestCase):
    def test_returns_packets_one_by_one(self):
        _reset_rx([_air(b"a", -60) + _air(b"b", -61)])
        self.assertEqual(radio.lora_recv(0.5), b"a")
        self.assertEqual(radio.LAST_RSSI, -60)
        self.assertEqual(radio.lora_recv(0.5), b"b")
        self.assertEqual(radio.LAST_RSSI, -61)
        self.assertIsNone(radio.lora_recv(0.1))

    def test_frame_split_across_calls(self):
        whole = _air(b"split-frame")
        ser = _reset_rx([whole[:5]])
        # 期限が来ても未完成フレームは捨てずに持ち越す
        self.assertIsNone(radio.lora_recv(0.02))
        ser.chunks.append(whole[5:])
        self.assertEqual(radio.lora_recv(0.5), b"split-frame")


class MsgIdTest(unittest.TestCase):
    def test_sequence_starts_from_random_value(self):
        starts = set()
        for _ in range(5):
            importlib.reload(crypto)
            starts.add(crypto._seq)
        # 5 回とも同じ値になる確率は無視できる
        self.assertGreater(len(starts), 1)


# ─── ブリッジ（bless をスタブにして読み込む） ─────────────────────────────────
def _load_bridge():
    bless = types.ModuleType("bless")
    bless.BlessServer = object
    bless.GATTCharacteristicProperties = types.SimpleNamespace(
        write=1, write_without_response=2, notify=4, read=8)
    bless.GATTAttributePermissions = types.SimpleNamespace(writeable=1, readable=2)
    sys.modules.setdefault("bless", bless)
    sys.path.insert(0, os.path.normpath(_BRIDGE_DIR))
    import adphone_ble_lpwa_bridge as bridge
    return bridge


class BridgeTest(unittest.TestCase):
    def setUp(self):
        self.bridge = _load_bridge()
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        b = self.bridge
        b._ed_priv = ed25519.Ed25519PrivateKey.generate()
        b._dh_priv = X25519PrivateKey.generate()
        b._peer_keys.clear()
        b._pending_crypto.clear()
        self.peer_ed = ed25519.Ed25519PrivateKey.generate()
        self.peer_dh = X25519PrivateKey.generate()

    def _announce_from(self, addr: int) -> bytes:
        return crypto.encode_announce(
            addr, self.peer_ed.public_key().public_bytes_raw(),
            self.peer_dh.public_key().public_bytes_raw(), ttl=3)

    def test_message_waits_for_key_then_is_sent(self):
        b = self.bridge

        async def scenario():
            b._lpwa_send_queue = asyncio.Queue()
            b._reannounce_event = asyncio.Event()
            # 鍵が届く前に BLE から 0x0003 宛て
            b._hold_pending(3, b"hello")
            self.assertEqual(len(b._pending_crypto), 1)
            b._handle_announce_packet(self._announce_from(3))
            self.assertTrue(b._reannounce_event.is_set(), "新ピアには ANNOUNCE を返す")
            self.assertEqual(b._pending_crypto, [])
            return b._lpwa_send_queue.get_nowait()

        kind, (target, data) = asyncio.run(scenario())
        self.assertEqual((kind, target, data), ("crypto_send", 3, b"hello"))

    def test_known_key_does_not_trigger_reannounce(self):
        b = self.bridge

        async def scenario():
            b._lpwa_send_queue = asyncio.Queue()
            b._reannounce_event = asyncio.Event()
            b._handle_announce_packet(self._announce_from(4))
            b._reannounce_event.clear()
            b._handle_announce_packet(self._announce_from(4))   # 定期 ANNOUNCE
            return b._reannounce_event.is_set()

        self.assertFalse(asyncio.run(scenario()))

    def test_pending_is_bounded(self):
        b = self.bridge
        for i in range(b._PENDING_MAX + 5):
            b._hold_pending(9, str(i).encode())
        self.assertEqual(len(b._pending_crypto), b._PENDING_MAX)
        self.assertEqual(b._pending_crypto[0][2], b"5")   # 古いものから捨てる

    def test_relay_is_queued_after_jitter(self):
        b = self.bridge

        async def scenario():
            b._lpwa_send_queue = asyncio.Queue()
            b._schedule_relay(b"pkt")
            return await asyncio.wait_for(b._lpwa_send_queue.get(), timeout=1)

        self.assertEqual(asyncio.run(scenario()), ("relay", b"pkt"))


def tearDownModule():
    os.unlink(_tmp.name)


if __name__ == "__main__":
    unittest.main()
