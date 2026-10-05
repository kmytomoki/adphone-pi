# -*- coding: utf-8 -*-
"""ルーティング Phase 2（シミュレータ・Router 抽象化）のテスト。

    cd Raspberry/lpwa && python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import random
import sys
import unittest
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mesh import FloodRouterV1  # noqa: E402
from mesh.core import Delivery, MessageKey, TxMeta  # noqa: E402
from mesh.realtime import RealtimeNode  # noqa: E402
from sim.engine import Simulator  # noqa: E402
from sim.metrics import BROADCAST_ADDR, MessageRecord  # noqa: E402
from sim.radio import Medium, RadioParams, Transmission, lora_airtime  # noqa: E402
from sim.scenarios import SCENARIOS, line, run_scenario  # noqa: E402


def _ideal(**kw) -> RadioParams:
    """ばらつき・ランダム損失のない電波（結果を決定的にする）。"""
    base = dict(shadowing_sigma_db=0.0, fading_sigma_db=0.0, packet_error_rate=0.0)
    base.update(kw)
    return RadioParams(**base)


class AirtimeTest(unittest.TestCase):
    def test_matches_semtech_calculator(self):
        # SF7 / BW125 / CR4/5 / プリアンブル 8 / 10 バイト = 41.216ms
        self.assertAlmostEqual(lora_airtime(10, sf=7), 0.041216, places=6)

    def test_low_data_rate_optimize_for_sf12(self):
        # SF12 / BW125 / 10 バイト = 991.232ms（LDRO 有効）
        self.assertAlmostEqual(lora_airtime(10, sf=12), 0.991232, places=6)


class MediumTest(unittest.TestCase):
    def setUp(self):
        self.p = _ideal()
        d = self.p.nominal_range_m() * 0.5
        # 1 と 2 は 3 から等距離、4 は 3 のすぐ隣
        self.medium = Medium({1: (-d, 0), 2: (d, 0), 3: (0, 0), 4: (0, 1)}, self.p, random.Random(0))

    def _tx(self, sender, start, dur=0.2):
        tx = Transmission(sender, b"x", TxMeta("origin"), start, start + dur)
        self.medium.begin(tx)
        return tx

    def _result(self, tx, receiver):
        return {r: why for r, _, why in self.medium.receptions(tx, lambda a: True)}.get(receiver)

    def test_equal_power_overlap_is_collision(self):
        a = self._tx(1, 0.0)
        self._tx(2, 0.1)
        self.assertEqual(self._result(a, 3), "collision")

    def test_much_stronger_signal_captures(self):
        a = self._tx(4, 0.0)       # 1m 先からの強い電波
        self._tx(1, 0.1)
        self.assertEqual(self._result(a, 3), "ok")

    def test_transmitting_node_cannot_receive(self):
        a = self._tx(1, 0.0)
        self._tx(3, 0.05)
        self.assertEqual(self._result(a, 3), "half_duplex")

    def test_non_overlapping_is_fine(self):
        a = self._tx(1, 0.0)
        self._tx(2, 0.5)
        self.assertEqual(self._result(a, 3), "ok")


class FloodV1OnLineTest(unittest.TestCase):
    """5 台直線・理想電波で、現行ルーティングの TTL の振る舞いを確認する。"""

    def _run(self, ttl, src, dest):
        p = _ideal()
        pos = line(5, p.nominal_range_m(margin_db=4.0))
        sim = Simulator(pos, lambda ctx: FloodRouterV1(ctx, ttl=ttl, relay_jitter=0.3,
                                                        announce_interval=None), p, seed=1)
        key = sim.nodes[src].router.send(dest, b"hello")
        expected = frozenset(a for a in pos if a != src) if dest == BROADCAST_ADDR else frozenset([dest])
        sim.metrics.on_origin(key, MessageRecord(src, dest, 0.0, expected, None))
        sim.run(30.0)
        return sim.metrics.messages[key]

    def test_three_hops_with_ttl3(self):
        rec = self._run(3, 1, 4)
        self.assertIn(4, rec.receivers)

    def test_four_hops_needs_ttl4(self):
        self.assertNotIn(5, self._run(3, 1, 5).receivers)
        self.assertIn(5, self._run(4, 1, 5).receivers)

    def test_broadcast_relay_count(self):
        # 送信元 + ノード 2・3 が中継（ノード 4 は TTL=1 で受けるので中継しない）
        rec = self._run(3, 1, BROADCAST_ADDR)
        self.assertEqual(set(rec.receivers), {2, 3, 4})
        self.assertEqual(rec.tx_count, 3)

    def test_unicast_dest_does_not_relay(self):
        # 2 宛ては 2 で止まり、2 は中継しない（1 の送信だけ）
        rec = self._run(3, 1, 2)
        self.assertEqual(rec.tx_count, 1)


class ScenarioTest(unittest.TestCase):
    def test_all_scenarios_run_and_are_reproducible(self):
        params = {"ttl": 3, "relay_jitter": 0.5, "announce_interval": 300.0}
        for name, sc in SCENARIOS.items():
            with self.subTest(name):
                a = run_scenario(sc, "flood_v1", seed=3, router_params=params)
                b = run_scenario(sc, "flood_v1", seed=3, router_params=params)
                self.assertEqual(a, b, "同じ seed なら同じ結果")
                self.assertGreater(a["unicast_count"] + a["broadcast_count"], 0)
                self.assertIsNotNone(a["unicast_delivery"])


# ─── 実時間ランタイム（偽の無線と時計で動かす） ─────────────────────────────
class _Hub:
    def __init__(self):
        self.ports: list[_Port] = []


class _Port:
    def __init__(self, hub: _Hub, address: int):
        self.hub = hub
        self.address = address
        self.inbox: deque[bytes] = deque()
        hub.ports.append(self)

    def send(self, pkt: bytes) -> None:
        for p in self.hub.ports:
            if p is not self:
                p.inbox.append(pkt)

    def recv(self, timeout: float):
        return self.inbox.popleft() if self.inbox else None

    @property
    def last_rssi(self):
        return -90


class RealtimeNodeTest(unittest.TestCase):
    def test_router_runs_on_realtime_runtime(self):
        clock = [0.0]
        hub = _Hub()
        got: list[Delivery] = []
        factory = lambda ctx: FloodRouterV1(ctx, ttl=3, relay_jitter=0.2, announce_interval=None)  # noqa: E731
        a = RealtimeNode(_Port(hub, 1), factory, clock=lambda: clock[0], rng=random.Random(1))
        b = RealtimeNode(_Port(hub, 2), factory, on_deliver=got.append,
                         clock=lambda: clock[0], rng=random.Random(2))
        key = a.router.send(2, b"ping")
        for _ in range(5):
            clock[0] += 0.1
            b.poll(0)
            a.poll(0)
        self.assertEqual(len(got), 1)
        self.assertEqual(MessageKey(got[0].src, got[0].msg_id), key)
        self.assertTrue(got[0].payload.startswith(b"ping"))

    def test_relay_waits_for_jitter_timer(self):
        clock = [0.0]
        hub = _Hub()
        factory = lambda ctx: FloodRouterV1(ctx, ttl=3, relay_jitter=0.5, announce_interval=None)  # noqa: E731
        src = _Port(hub, 9)
        relay = RealtimeNode(_Port(hub, 1), factory, clock=lambda: clock[0], rng=random.Random(5))
        sink = _Port(hub, 3)
        src.send(_data_pkt(src=9, dest=3, ttl=3))   # sink にも元パケットが 1 つ届く
        relay.poll(0)                       # 受信 → 中継タイマーをセット
        self.assertEqual(len(sink.inbox), 1, "ジッタの前には中継しない")
        clock[0] += 0.6
        relay.poll(0)
        self.assertEqual(len(sink.inbox), 2)  # 元パケット + 中継
        self.assertEqual(sink.inbox[1][6], 2, "TTL が 1 減っている")


def _data_pkt(src: int, dest: int, ttl: int) -> bytes:
    import struct
    from mesh.flood_v1 import HEADER_FORMAT, TYPE_DATA
    return struct.pack(HEADER_FORMAT, src, dest, 1, ttl, TYPE_DATA) + bytes(100)


if __name__ == "__main__":
    unittest.main()
