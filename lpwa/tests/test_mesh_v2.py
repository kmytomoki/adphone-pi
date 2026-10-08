# -*- coding: utf-8 -*-
"""ルーティング Phase 3（パケット v2・鍵・NodeDB・管理型フラッディング）のテスト。

    cd Raspberry/lpwa && python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import os
import random
import sys
import tempfile
import unittest
from dataclasses import replace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mesh import packet as P  # noqa: E402
from mesh.core import Delivery, TxMeta  # noqa: E402
from mesh.identity import AnnounceInfo, CryptoError, Identity  # noqa: E402
from mesh.nodedb import NodeDB  # noqa: E402
from mesh.router import ManagedFloodRouter  # noqa: E402
from sim.engine import Simulator  # noqa: E402
from sim.metrics import BROADCAST_ADDR, MessageRecord  # noqa: E402
from sim.radio import RadioParams  # noqa: E402
from sim.scenarios import line  # noqa: E402

GROUP_KEY = bytes(range(32))


# ════════════════════════════════════════════════════════════
#  packet
# ════════════════════════════════════════════════════════════
class PacketTest(unittest.TestCase):
    def _pkt(self, **kw):
        base = dict(type=P.TYPE_DATA, src=1, dest=2, msg_id=0xABCD1234, hop_limit=3, hop_start=3,
                    body=b"hello")
        base.update(kw)
        return P.Packet(**base)

    def test_roundtrip(self):
        pkt = self._pkt(flags=P.FLAG_WANT_ACK, path=(5, 6))
        self.assertEqual(P.Packet.decode(pkt.encode()), pkt)
        self.assertEqual(len(pkt.encode()), P.HEADER_SIZE + 2 * P.PATH_ENTRY + 5)

    def test_relay_decrements_and_appends_path(self):
        out = self._pkt().relayed_by(7, 12).relayed_by(8, 3)
        self.assertEqual((out.hop_limit, out.hop_start, out.path), (1, 3, (7, 8)))
        self.assertEqual(out.link_q, (12, 3))
        self.assertEqual(P.Packet.decode(out.encode()).link_q, (12, 3))
        self.assertEqual(out.hops_taken, 2)
        self.assertEqual(out.last_hop, 8)

    def test_aad_is_unchanged_by_relay(self):
        pkt = self._pkt()
        self.assertEqual(pkt.aad(), pkt.relayed_by(9).aad())

    def test_max_hops_never_overflow_path(self):
        pkt = self._pkt(hop_limit=P.MAX_HOP_LIMIT, hop_start=P.MAX_HOP_LIMIT,
                        body=bytes(P.MAX_BODY))
        for addr in range(P.MAX_HOP_LIMIT):
            pkt = pkt.relayed_by(addr + 10)
        self.assertEqual(len(pkt.encode()), P.MAX_PACKET)
        self.assertEqual(P.Packet.decode(pkt.encode()).last_hop, P.MAX_HOP_LIMIT + 9)

    def test_rejects_bad_packets(self):
        good = self._pkt().encode()
        for raw in (good[:10], bytes([1]) + good[1:], good[:1] + b"\x7f" + good[2:]):
            with self.assertRaises(P.PacketError):
                P.Packet.decode(raw)
        with self.assertRaises(P.PacketError):
            P.Packet.decode(self._pkt(hop_limit=4, hop_start=3).encode())

    def test_fragment_and_reassemble(self):
        body = bytes(range(256)) * 2   # 512B → 4 分割
        frags = P.fragment(self._pkt(), body)
        self.assertEqual(len(frags), 4)
        self.assertTrue(all(len(f.encode()) <= P.MAX_PACKET - 2 * P.MAX_PATH for f in frags))
        self.assertEqual(len({f.dedup_key for f in frags}), 4, "分割ごとに重複キーが違う")
        reasm = P.Reassembler()
        decoded = [P.Packet.decode(f.encode()) for f in reversed(frags)]
        results = [reasm.add(f, 0.0) for f in decoded]
        self.assertEqual(results[:3], [None, None, None])
        self.assertEqual(results[3], body)

    def test_reassembly_times_out(self):
        frags = P.fragment(self._pkt(), bytes(400))
        reasm = P.Reassembler(timeout=30)
        reasm.add(frags[0], 0.0)
        reasm.add(frags[1], 31.0)   # 1 個目は期限切れで捨てられている
        self.assertIsNone(reasm.add(frags[2], 31.5))

    def test_too_long_message(self):
        with self.assertRaises(P.PacketError):
            P.fragment(self._pkt(), bytes(P.MAX_FRAGMENTS * P.MAX_FRAGMENT_BODY + 1))


# ════════════════════════════════════════════════════════════
#  identity / nodedb
# ════════════════════════════════════════════════════════════
class IdentityTest(unittest.TestCase):
    def setUp(self):
        self.a, self.b, self.c = Identity.generate(), Identity.generate(), Identity.generate()
        self.aad = P.Packet(P.TYPE_DATA, 1, 2, 5, 3, 3).aad()

    def test_announce_signature(self):
        body = self.a.announce_body(self.aad, "ROUTER", "避難所A")
        info = Identity.parse_announce(self.aad, body)
        self.assertEqual((info.ed_pub, info.role, info.name), (self.a.ed_pub, "ROUTER", "避難所A"))
        tampered = body[:64] + bytes([0]) + body[65:]   # role を書き換え
        with self.assertRaises(CryptoError):
            Identity.parse_announce(self.aad, tampered)

    def test_pair_encryption(self):
        body = self.a.seal_data(self.aad, b"secret", self.b.dh_pub)
        self.assertEqual(self.b.open_data(self.aad, body, self.a.dh_pub), b"secret")
        with self.assertRaises(CryptoError):
            self.c.open_data(self.aad, body, self.a.dh_pub)        # 第三者は読めない
        other_aad = P.Packet(P.TYPE_DATA, 1, 3, 5, 3, 3).aad()    # 宛先を書き換えると失敗
        with self.assertRaises(CryptoError):
            self.b.open_data(other_aad, body, self.a.dh_pub)

    def test_group_encryption_and_signature(self):
        body = self.a.seal_group(self.aad, b"all", GROUP_KEY, 7)
        self.assertEqual(Identity.group_key_id(body), 7)
        self.assertEqual(Identity.open_group(self.aad, body, GROUP_KEY, self.a.ed_pub), b"all")
        with self.assertRaises(CryptoError):
            Identity.open_group(self.aad, body, GROUP_KEY, self.b.ed_pub)   # 別人の署名

    def test_key_file_persists(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub", "identity.key")
            first = Identity.load_or_create(path)
            again = Identity.load_or_create(path)
            self.assertEqual((first.ed_pub, first.dh_pub), (again.ed_pub, again.dh_pub))
            if os.name == "posix":
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)


class NodeDBTest(unittest.TestCase):
    def _info(self, ident, role="CLIENT"):
        return AnnounceInfo(ident.ed_pub, ident.dh_pub, role, "")

    def test_tofu_rejects_key_change(self):
        db = NodeDB()
        a, evil = Identity.generate(), Identity.generate()
        self.assertEqual(db.learn(5, self._info(a), 0), "new")
        self.assertEqual(db.learn(5, self._info(a), 1), "known")
        self.assertEqual(db.learn(5, self._info(evil), 2), "conflict")
        self.assertEqual(db.get(5).ed_pub, a.ed_pub, "上書きしない")
        db.forget(5)
        self.assertEqual(db.learn(5, self._info(evil), 3), "new")

    def test_persistence(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nodedb.json")
            a = Identity.generate()
            NodeDB(path).learn(9, self._info(a, "ROUTER"), 0)
            again = NodeDB(path)
            self.assertEqual(again.get(9).dh_pub, a.dh_pub)
            self.assertEqual(again.get(9).role, "ROUTER")


# ════════════════════════════════════════════════════════════
#  router（理想電波の直線上で動かす）
# ════════════════════════════════════════════════════════════
def _ideal() -> RadioParams:
    return RadioParams(shadowing_sigma_db=0.0, fading_sigma_db=0.0, packet_error_rate=0.0)


class RouterOnLineTest(unittest.TestCase):
    def _sim(self, n=5, **kw):
        p = _ideal()
        pos = line(n, p.nominal_range_m(margin_db=4.0))
        # 起動時の ANNOUNCE 同士が衝突しないよう、200 秒に散らして行き渡るまで待つ
        params = dict(hop_limit=3, group_key=GROUP_KEY, startup_announce_spread=200.0)
        params.update(kw)
        sim = Simulator(pos, lambda ctx: ManagedFloodRouter(ctx, **params), p, seed=2)
        sim.run(300.0)
        return sim

    def _send(self, sim, src, dest, payload=b"hello", until=60.0):
        key = sim.nodes[src].router.send(dest, payload)
        expected = (frozenset(a for a in sim.nodes if a != src) if dest == BROADCAST_ADDR
                    else frozenset([dest]))
        sim.metrics.on_origin(key, MessageRecord(src, dest, sim.now, expected, None))
        sim.run(sim.now + until)
        return sim.metrics.messages[key]

    def test_keys_are_exchanged(self):
        sim = self._sim()
        for node in sim.nodes.values():
            others = set(sim.nodes) - {node.address}
            self.assertEqual(set(node.router.nodedb.nodes), others)

    def test_unicast_reaches_four_hops_with_hop_limit_3(self):
        rec = self._send(self._sim(), 1, 5)
        self.assertIn(5, rec.receivers)

    def test_hop_limit_bounds_reach(self):
        rec = self._send(self._sim(hop_limit=2), 1, 5)
        self.assertNotIn(5, rec.receivers)

    def test_broadcast_on_line(self):
        rec = self._send(self._sim(), 1, BROADCAST_ADDR)
        self.assertEqual(set(rec.receivers), {2, 3, 4, 5})
        # 直線では中継の省略が起きない: 送信元 + 2・3・4 が中継（5 は端なので省略）
        self.assertEqual(rec.tx_count, 4)

    def test_payload_is_decrypted(self):
        sim = self._sim()
        got: list[Delivery] = []
        sim.nodes[3].deliver = got.append
        sim.nodes[1].router.send(3, "こんにちは".encode())
        sim.run(sim.now + 60)
        self.assertEqual([d.payload.decode() for d in got], ["こんにちは"])
        self.assertEqual(got[0].hops, 2)

    def test_long_message_is_fragmented(self):
        sim = self._sim()
        got: list[Delivery] = []
        sim.nodes[4].deliver = got.append
        sim.nodes[1].router.send(4, bytes(400))
        sim.run(sim.now + 120)
        self.assertEqual([len(d.payload) for d in got], [400])

    def test_unknown_key_is_requested(self):
        # ANNOUNCE を流さず、送信時の「鍵の要求」だけで届くこと
        p = _ideal()
        pos = line(3, p.nominal_range_m(margin_db=4.0))
        sim = Simulator(pos, lambda ctx: ManagedFloodRouter(ctx, announce_interval=None,
                                                            group_key=GROUP_KEY), p, seed=3)
        got: list[Delivery] = []
        sim.nodes[3].deliver = got.append
        sim.nodes[1].router.send(3, b"late key")
        sim.run(120)
        self.assertEqual([d.payload for d in got], [b"late key"])
        self.assertEqual(sim.nodes[1].router.stats.key_requests, 1)

    def test_client_mute_does_not_relay(self):
        sim = self._sim(roles={2: "CLIENT_MUTE"})
        rec = self._send(sim, 1, BROADCAST_ADDR)
        self.assertEqual(set(rec.receivers), {2})


class _Ctx:
    """手動で動かす NodeContext（重複受信による取りやめを決定的に確かめる）。"""

    def __init__(self, address):
        self.address = address
        self.t = 0.0
        self.sent: list[bytes] = []
        self.timers: list = []
        self._rng = random.Random(1)

    def now(self):
        return self.t

    def random(self):
        return self._rng

    def call_later(self, delay, fn):
        h = _Handle(self.t + delay, fn)
        self.timers.append(h)
        return h

    def transmit(self, pkt: bytes, meta: TxMeta):
        self.sent.append(pkt)

    def deliver(self, d):
        pass

    def advance(self, dt):
        self.t += dt
        for h in sorted(self.timers, key=lambda h: h.at):
            if h.at <= self.t and not h.cancelled and not h.fired:
                h.fired = True
                h.fn()


class _Handle:
    def __init__(self, at, fn):
        self.at, self.fn, self.cancelled, self.fired = at, fn, False, False

    def cancel(self):
        self.cancelled = True


class RelayCancelTest(unittest.TestCase):
    def _group_pkt(self, src_ident, src=1):
        base = P.Packet(P.TYPE_GROUP_DATA, src, P.BROADCAST_ADDR, 77, 3, 3)
        return replace(base, body=src_ident.seal_group(base.aad(), b"x", GROUP_KEY, 0))

    def _router(self, role="CLIENT"):
        ctx = _Ctx(address=5)
        r = ManagedFloodRouter(ctx, role=role, group_key=GROUP_KEY, announce_interval=None)
        src = Identity.generate()
        r.nodedb.learn(1, AnnounceInfo(src.ed_pub, src.dh_pub, "CLIENT", ""), 0)
        for a in (1, 2, 3):
            r.nodedb.heard(a, a, 1, -100, 0)
        return ctx, r, src

    def test_duplicate_cancels_pending_relay(self):
        ctx, r, src = self._router()
        pkt = self._group_pkt(src)
        r.on_receive(pkt.encode(), -110)
        r.on_receive(pkt.relayed_by(2).encode(), -110)   # 他のノードが先に中継した
        ctx.advance(100)
        self.assertEqual(ctx.sent, [])
        self.assertEqual(r.stats.relay_cancelled, 1)

    def test_router_role_always_relays(self):
        ctx, r, src = self._router(role="ROUTER")
        pkt = self._group_pkt(src)
        r.on_receive(pkt.encode(), -110)
        r.on_receive(pkt.relayed_by(2).encode(), -110)
        ctx.advance(100)
        self.assertEqual(len(ctx.sent), 1)
        self.assertEqual(P.Packet.decode(ctx.sent[0]).path, (5,))

    def test_weak_signal_relays_earlier(self):
        delays = {}
        for rssi in (-121, -95):
            ctx, r, _ = self._router()
            ctx._rng = random.Random(7)
            delays[rssi] = r._relay_delay(100, rssi)
        self.assertLess(delays[-121], delays[-95])

    def test_bad_announce_is_not_relayed(self):
        ctx, r, _ = self._router()
        evil = Identity.generate()
        base = P.Packet(P.TYPE_ANNOUNCE, 9, P.BROADCAST_ADDR, 1, 3, 3)
        body = evil.announce_body(base.aad(), "CLIENT", "")
        forged = replace(base, body=body[:-1] + bytes([body[-1] ^ 1]))
        r.on_receive(forged.encode(), -110)
        ctx.advance(100)
        self.assertEqual(ctx.sent, [])
        self.assertIsNone(r.nodedb.get(9))


if __name__ == "__main__":
    unittest.main()
