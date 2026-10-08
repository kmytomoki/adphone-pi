# -*- coding: utf-8 -*-
"""ルーティング Phase 4（ACK・経路学習・DIRECT・区間ごとの再送・送信予算）のテスト。

    cd Raspberry/lpwa && python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import random
import struct
import sys
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mesh import packet as P  # noqa: E402
from mesh.identity import AnnounceInfo, Identity  # noqa: E402
from mesh.links import LinkTable  # noqa: E402
from mesh.reliable import ReliableRouter, link_cost  # noqa: E402
from sim.engine import Simulator  # noqa: E402
from sim.metrics import MessageRecord  # noqa: E402
from sim.radio import RadioParams  # noqa: E402
from sim.scenarios import grid, line  # noqa: E402
from test_mesh_v2 import _Ctx  # noqa: E402

GROUP_KEY = bytes(range(32))


class LinkTableTest(unittest.TestCase):
    def test_prefers_two_good_links_over_one_weak(self):
        t = LinkTable()
        t.observe(1, 3, 1, 0)            # 直接は弱い（余裕 1dB → コスト 6）
        t.observe(1, 2, 15, 0)
        t.observe(2, 3, 15, 0)           # 2 経由は強い（コスト 1 + 1）
        self.assertEqual(t.best_path(1, 3, 0, link_cost, 8), ((2,), 2.0))

    def test_ewma_and_symmetry(self):
        t = LinkTable(alpha=0.5)
        t.observe(1, 2, 10, 0)
        t.observe(2, 1, 20, 1)
        self.assertEqual(t.quality(1, 2, 1), 15.0)

    def test_failed_link_is_avoided_until_seen_again(self):
        t = LinkTable()
        for a, b in ((1, 2), (2, 3), (1, 4), (4, 3)):
            t.observe(a, b, 15, 0)
        t.observe(4, 3, 4, 0)            # 4 経由はやや悪い
        self.assertEqual(t.best_path(1, 3, 0, link_cost, 8)[0], (2,))
        t.fail(2, 3, 1)
        self.assertEqual(t.best_path(1, 3, 1, link_cost, 8)[0], (4,))
        t.observe(2, 3, 15, 2)
        self.assertEqual(t.best_path(1, 3, 2, link_cost, 8)[0], (2,))

    def test_fail_node_and_ttl(self):
        t = LinkTable(ttl=100)
        t.observe(1, 2, 15, 0)
        t.observe(2, 3, 15, 0)
        t.fail_node(2, 1)
        self.assertIsNone(t.best_path(1, 3, 1, link_cost, 8))
        t2 = LinkTable(ttl=100)
        t2.observe(1, 2, 15, 0)
        self.assertIsNone(t2.best_path(1, 2, 200, link_cost, 8), "古いリンクは使わない")

    def test_max_links(self):
        t = LinkTable()
        for a in range(1, 6):
            t.observe(a, a + 1, 15, 0)
        self.assertIsNone(t.best_path(1, 6, 0, link_cost, 4))
        self.assertEqual(t.best_path(1, 6, 0, link_cost, 5)[0], (2, 3, 4, 5))


class PacketPhase4Test(unittest.TestCase):
    def test_attempt_bits_and_dedup(self):
        pkt = P.Packet(P.TYPE_DATA, 1, 2, 9, 3, 3, b"x", flags=P.FLAG_WANT_ACK)
        retry = pkt.with_attempt(2)
        self.assertEqual(P.Packet.decode(retry.encode()).attempt, 2)
        self.assertNotEqual(pkt.dedup_key, retry.dedup_key)
        self.assertEqual(pkt.aad(), retry.aad())

    def test_direct_forward_keeps_path_and_records_quality(self):
        pkt = P.Packet(P.TYPE_DATA, 1, 9, 5, 2, 2, b"x", flags=P.FLAG_DIRECT, path=(3, 4))
        self.assertEqual(pkt.next_hop, 3)
        hop1 = pkt.forwarded(12)
        self.assertEqual((hop1.path, hop1.link_q, hop1.next_hop, hop1.last_hop),
                         ((3, 4), (12, P.LINK_Q_UNKNOWN), 4, 3))
        hop2 = hop1.forwarded(7)
        self.assertEqual((hop2.link_q, hop2.next_hop, hop2.last_hop), ((12, 7), 9, 4))


# ════════════════════════════════════════════════════════════
#  シミュレータ上で（ばらつきのない電波）
# ════════════════════════════════════════════════════════════
def _ideal() -> RadioParams:
    return RadioParams(shadowing_sigma_db=0.0, fading_sigma_db=0.0, packet_error_rate=0.0)


class ReliableOnSimTest(unittest.TestCase):
    def _sim(self, positions, **kw):
        self.events: list[tuple[int, str, dict]] = []
        params = dict(hop_limit=3, group_key=GROUP_KEY, startup_announce_spread=200.0)
        params.update(kw)

        def factory(ctx):
            return ReliableRouter(ctx, on_event=lambda e, i, a=ctx.address: self.events.append((a, e, i)),
                                  **params)
        sim = Simulator(positions, factory, _ideal(), seed=4)
        sim.run(300.0)      # ANNOUNCE が行き渡るまで
        return sim

    def _send(self, sim, src, dest, wait=60.0):
        key = sim.nodes[src].router.send(dest, b"hello")
        sim.metrics.on_origin(key, MessageRecord(src, dest, sim.now, frozenset([dest]), None))
        sim.run(sim.now + wait)
        return key, sim.metrics.messages[key]

    def _delivered_events(self, src):
        return [i for a, e, i in self.events if a == src and e == "delivered"]

    def test_ack_then_direct(self):
        p = _ideal()
        sim = self._sim(line(5, p.nominal_range_m(margin_db=8.0)))
        key, rec = self._send(sim, 1, 5)
        self.assertIn(5, rec.receivers)
        self.assertEqual([e["msg_id"] for e in self._delivered_events(1)], [key.msg_id])
        r = sim.nodes[1].router
        self.assertEqual(r.route_for(5), (2, 3, 4))
        # 2 回目: 経路に沿って送る。データ 4 区間 + ACK 4 区間
        direct_before = r.stats.direct_sent
        key2, rec2 = self._send(sim, 1, 5)
        self.assertIn(5, rec2.receivers)
        self.assertEqual(r.stats.direct_sent, direct_before + 1)
        self.assertEqual(rec2.tx_count, 8)

    def test_switches_route_when_relay_dies(self):
        p = _ideal()
        # 2 行 3 列の格子: 1-2-3 / 4-5-6（縦と横がつながる。斜めは弱い）
        sim = self._sim(grid(2, 3, p.nominal_range_m(margin_db=8.0)))
        self._send(sim, 1, 3)
        first = sim.nodes[1].router.route_for(3)
        self.assertIsNotNone(first)
        dead = first[0]
        sim.nodes[dead].kill()
        sim.run(sim.now + 120)     # 止まったノードが黙っている時間（node_silent_sec）を過ぎる
        delivered = len(self._delivered_events(1))
        key, rec = self._send(sim, 1, 3, wait=240)
        self.assertIn(3, rec.receivers, "別の経路で届く")
        self.assertEqual(len(self._delivered_events(1)), delivered + 1, "送信元に届いたと分かる")
        new = sim.nodes[1].router.route_for(3)
        self.assertNotIn(dead, new or ())
        self.assertGreater(sim.nodes[1].router.stats.links_failed
                           + sum(n.router.stats.nacks_sent for n in sim.nodes.values()), 0)

    def test_send_failed_event(self):
        p = _ideal()
        sim = self._sim(line(3, p.nominal_range_m(margin_db=8.0)))
        self._send(sim, 1, 3)
        sim.nodes[3].kill()
        self._send(sim, 1, 3, wait=900)
        self.assertTrue(any(e == "send_failed" for a, e, _ in self.events if a == 1))


# ════════════════════════════════════════════════════════════
#  手動の NodeContext で（タイミングを決め打ちで確かめる）
# ════════════════════════════════════════════════════════════
class ReliableUnitTest(unittest.TestCase):
    def _router(self, addr=5, **kw):
        ctx = _Ctx(address=addr)
        params = dict(group_key=GROUP_KEY, announce_interval=None)
        params.update(kw)
        r = ReliableRouter(ctx, **params)
        return ctx, r

    def test_broadcast_retry_when_no_neighbor_relays(self):
        ctx, r = self._router()
        r.nodedb.heard(1, 1, 1, -100, 0)        # 隣が 1 台いる
        r.send(P.BROADCAST_ADDR, b"all")
        self.assertEqual(len(ctx.sent), 1)
        ctx.advance(1000)
        self.assertEqual(len(ctx.sent), 2)
        self.assertEqual(P.Packet.decode(ctx.sent[1]).attempt, 1)
        self.assertEqual(r.stats.broadcast_retries, 1)

    def test_broadcast_no_retry_when_neighbor_relays(self):
        ctx, r = self._router()
        r.nodedb.heard(1, 1, 1, -100, 0)
        r.send(P.BROADCAST_ADDR, b"all")
        mine = P.Packet.decode(ctx.sent[0])
        r.on_receive(mine.relayed_by(1, 10).encode(), -100)    # 隣が中継した
        ctx.advance(1000)
        self.assertEqual(len(ctx.sent), 1)

    def test_relay_answers_retransmission_with_hop_ack(self):
        # 5 は経路 (5, 6) の 1 番目。転送 → 次(6)の転送を聞く → 前(1)の再送には HOP_ACK
        ctx, r = self._router(addr=5)
        data = P.Packet(P.TYPE_DATA, 1, 9, 77, 2, 2, b"x" * 40,
                        flags=P.FLAG_DIRECT | P.FLAG_WANT_ACK, path=(5, 6))
        r.on_receive(data.encode(), -100)
        ctx.advance(1)
        self.assertEqual(len(ctx.sent), 1)                      # 転送した
        fwd = P.Packet.decode(ctx.sent[0])
        r.on_receive(fwd.forwarded(10).encode(), -100)          # 6 が転送したのを聞いた
        r.on_receive(data.encode(), -100)                       # 1 が聞き逃して送り直してきた
        hack = P.Packet.decode(ctx.sent[-1])
        self.assertEqual((hack.type, hack.dest), (P.TYPE_HOP_ACK, 1))
        self.assertEqual(struct.unpack("!HIBB", hack.body), (1, 77, 0, 0))
        self.assertEqual(len(ctx.sent), 2, "データは転送し直さない")

    def test_hop_retry_then_nack(self):
        ctx, r = self._router(addr=5, hop_retries=2)
        data = P.Packet(P.TYPE_DATA, 1, 9, 77, 2, 2, b"x" * 40,
                        flags=P.FLAG_DIRECT | P.FLAG_WANT_ACK, path=(5, 6))
        r.on_receive(data.encode(), -100)
        for _ in range(5):
            ctx.advance(30)
        kinds = [P.Packet.decode(x).type for x in ctx.sent]
        self.assertEqual(kinds, [P.TYPE_DATA] * 3 + [P.TYPE_NACK])   # 転送 + 再送 2 回 + NACK
        nack = P.Packet.decode(ctx.sent[-1])
        self.assertEqual(nack.dest, 1)
        self.assertEqual(struct.unpack("!IBH", nack.body)[0::2], (77, 6))

    def test_budget_stops_flood_relays(self):
        ctx, r = self._router(airtime_budget=0.001)
        src = Identity.generate()
        r.nodedb.learn(1, AnnounceInfo(src.ed_pub, src.dh_pub, "CLIENT", ""), 0)
        r.send(P.BROADCAST_ADDR, b"use up the budget")
        base = P.Packet(P.TYPE_GROUP_DATA, 1, P.BROADCAST_ADDR, 7, 3, 3)
        pkt = replace(base, body=src.seal_group(base.aad(), b"x", GROUP_KEY, 0))
        r.on_receive(pkt.encode(), -110)
        ctx.advance(100)
        self.assertEqual(r.stats.budget_drops, 1)


if __name__ == "__main__":
    unittest.main()
