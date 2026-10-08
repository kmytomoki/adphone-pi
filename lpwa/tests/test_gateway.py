# -*- coding: utf-8 -*-
"""ルーティング Phase 5（BLE プロトコル v2・蓄積転送・ゲートウェイ）のテスト。

    cd Raspberry/lpwa && python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mesh import bleproto as B  # noqa: E402
from mesh.gateway import MeshGateway, hello_payload  # noqa: E402
from mesh.reliable import ReliableRouter  # noqa: E402
from mesh.store import Store  # noqa: E402
from sim.engine import Simulator  # noqa: E402
from sim.radio import RadioParams  # noqa: E402
from sim.scenarios import line  # noqa: E402

GROUP_KEY = bytes(range(32))


# ════════════════════════════════════════════════════════════
#  フレームとチャンク
# ════════════════════════════════════════════════════════════
class BleProtoTest(unittest.TestCase):
    def test_frame_roundtrip(self):
        f = B.Frame(B.KIND_MSG, 0xDEADBEEF, 3, B.BROADCAST, "こんにちは".encode())
        self.assertEqual(B.Frame.decode(f.encode()), f)
        with self.assertRaises(B.ProtocolError):
            B.Frame.decode(b"\x01" + f.encode()[1:])      # 旧バージョン

    def test_chunk_and_reassemble_long_frame(self):
        raw = B.Frame(B.KIND_MSG, 1, payload=bytes(range(256)) * 3).encode()
        chunks = B.chunk(raw, stream=7)
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(len(c) <= B.CHUNK_MAX for c in chunks))
        r = B.Reassembler()
        results = [r.add(c, 0) for c in chunks]
        self.assertEqual(results[-1], (7, raw))
        self.assertTrue(all(x is None for x in results[:-1]))

    def test_streams_do_not_mix(self):
        a = B.chunk(B.Frame(B.KIND_MSG, 1, payload=b"a" * 400).encode(), stream=1)
        b = B.chunk(B.Frame(B.KIND_MSG, 2, payload=b"b" * 400).encode(), stream=2)
        r = B.Reassembler()
        out = [x for pair in zip(a, b) for x in (r.add(pair[0], 0), r.add(pair[1], 0)) if x]
        self.assertEqual(sorted(B.Frame.decode(raw).msg_id for _, raw in out), [1, 2])

    def test_missing_chunk_drops_frame(self):
        chunks = B.chunk(B.Frame(B.KIND_MSG, 1, payload=b"x" * 400).encode(), stream=1)
        r = B.Reassembler()
        self.assertIsNone(r.add(chunks[0], 0))
        self.assertIsNone(r.add(chunks[2], 0))           # 1 番目が抜けた
        self.assertIsNone(r.add(chunks[-1], 0))

    def test_legacy_text_is_not_a_chunk(self):
        self.assertFalse(B.is_chunk("ADCH|v1|こんにちは".encode()))
        self.assertFalse(B.is_chunk("あ".encode()))      # UTF-8 の先頭は 0xAD にならない


# ════════════════════════════════════════════════════════════
#  受信箱・送信箱
# ════════════════════════════════════════════════════════════
class StoreTest(unittest.TestCase):
    def _store(self, **kw) -> Store:
        s = Store(**kw)
        self.addCleanup(s.close)
        return s

    def test_inbox_dedupe_and_since(self):
        s = self._store()
        self.assertEqual(s.add_inbox(1, 2, 100, b"a", 0), 1)
        self.assertIsNone(s.add_inbox(1, 2, 100, b"a", 1), "同じメッセージは 1 回だけ")
        s.add_inbox(1, 2, 101, b"b", 2)
        s.add_inbox(3, 2, 100, b"c", 3)
        self.assertEqual([i.payload for i in s.inbox_since(1)], [b"b", b"c"])
        self.assertEqual([i.payload for i in s.inbox_since(0, limit=2)], [b"b", b"c"])
        self.assertEqual(s.last_seq(), 3)

    def test_purge(self):
        s = self._store(hold_sec=100, max_inbox=2)
        for i in range(4):
            s.add_inbox(1, 2, i, b"x", 50 + i)
        s.purge(152)              # 50, 51 は保持期間切れ。残りも上限 2 件
        self.assertEqual([i.seq for i in s.inbox_since(0)], [3, 4])

    def test_outbox_due_expired_and_recover(self):
        s = self._store(hold_sec=1000)
        a = s.add_outbox(b"c", 1, 5, b"a", 0)
        s.update_outbox(a, 0, state=B.ST_WAITING, next_try_at=100)
        self.assertEqual(s.outbox_due(50), [])
        self.assertEqual([i.id for i in s.outbox_due(100)], [a])
        self.assertEqual([i.id for i in s.outbox_expired(1001)], [a])
        b = s.add_outbox(b"c", 2, 5, b"b", 0)
        s.update_outbox(b, 0, state=B.ST_SENT, mesh_msg_id=77)
        s.recover(10)             # 再起動: ACK 待ちは再送待ちへ
        self.assertEqual(s.outbox_get(b).state, B.ST_WAITING)


# ════════════════════════════════════════════════════════════
#  ゲートウェイ（シミュレータの 3 台直線の上で）
# ════════════════════════════════════════════════════════════
class _Phone:
    """Pi の notify を受けるスマホ役。"""

    def __init__(self, stream: int, client_id: bytes):
        self.stream = stream
        self.client_id = client_id
        self.frames: list[B.Frame] = []
        self._r = B.Reassembler()

    def on_notify(self, chunk: bytes) -> None:
        got = self._r.add(chunk, 0)
        if got:
            self.frames.append(B.Frame.decode(got[1]))

    def write(self, gw: MeshGateway, frame: B.Frame) -> None:
        for c in B.chunk(frame.encode(), self.stream):
            gw.on_ble_write(c)

    def hello(self, gw: MeshGateway, since: int = 0) -> None:
        self.write(gw, B.Frame(B.KIND_HELLO, payload=hello_payload(self.client_id, since)))

    def statuses(self, app_id: int) -> list[int]:
        return [f.payload[0] for f in self.frames if f.kind == B.KIND_STATUS and f.msg_id == app_id]

    def messages(self) -> list[B.Frame]:
        return [f for f in self.frames if f.kind == B.KIND_MSG]


class GatewayTest(unittest.TestCase):
    def setUp(self):
        p = RadioParams(shadowing_sigma_db=0.0, fading_sigma_db=0.0, packet_error_rate=0.0)
        pos = line(3, p.nominal_range_m(margin_db=8.0))
        self.gw: dict[int, MeshGateway] = {}
        self.phones: dict[int, _Phone] = {}

        def factory(ctx):
            return ReliableRouter(ctx, hop_limit=3, group_key=GROUP_KEY, startup_announce_spread=100.0,
                                  on_event=lambda e, i, a=ctx.address: self.gw[a].on_event(e, i))
        self.sim = Simulator(pos, factory, p, seed=7)
        for a, node in self.sim.nodes.items():
            phone = _Phone(stream=a, client_id=bytes([a]) * 8)
            store = Store()
            self.addCleanup(store.close)
            gw = MeshGateway(node, node.router, store, phone.on_notify,
                             info={"name": "node{}".format(a)}, retry_base=60.0,
                             wall=lambda: self.sim.now)
            node.deliver = gw.on_deliver
            self.gw[a], self.phones[a] = gw, phone
            gw.start()
        self.sim.run(200.0)           # ANNOUNCE が行き渡るまで
        for a in self.sim.nodes:
            self.phones[a].hello(self.gw[a])

    def _run(self, sec):
        self.sim.run(self.sim.now + sec)

    def test_unicast_status_and_delivery(self):
        p1, p3 = self.phones[1], self.phones[3]
        p1.write(self.gw[1], B.Frame(B.KIND_MSG, 42, dest=3, payload="物資不足".encode()))
        self._run(60)
        self.assertEqual(p1.statuses(42), [B.ST_SENT, B.ST_DELIVERED])
        got = [f for f in p3.messages() if f.src == 1]
        self.assertEqual([(f.dest, f.payload.decode()) for f in got], [(3, "物資不足")])
        delivered = [f for f in p1.frames if f.kind == B.KIND_STATUS and f.msg_id == 42][-1]
        self.assertEqual(delivered.payload[1], 2, "ホップ数")

    def test_broadcast_relayed_and_seen_by_local_phones(self):
        p2 = self.phones[2]
        p2.write(self.gw[2], B.Frame(B.KIND_MSG, 7, dest=B.BROADCAST, payload=b"all"))
        self._run(60)
        self.assertEqual(p2.statuses(7), [B.ST_SENT, B.ST_RELAYED])
        self.assertEqual([f.payload for f in self.phones[1].messages()], [b"all"])
        self.assertEqual([f.payload for f in self.phones[3].messages()], [b"all"])
        self.assertEqual([f.payload for f in p2.messages()], [b"all"], "同じ Pi の他のスマホにも見せる")

    def test_store_and_forward_when_dest_is_down(self):
        p1 = self.phones[1]
        self.sim.nodes[3].alive = False
        p1.write(self.gw[1], B.Frame(B.KIND_MSG, 9, dest=3, payload=b"later"))
        self._run(400)
        self.assertIn(B.ST_WAITING, p1.statuses(9))
        self.assertNotIn(B.ST_DELIVERED, p1.statuses(9))
        self.sim.nodes[3].alive = True        # 宛先が戻る
        self._run(1200)
        self.assertEqual(p1.statuses(9)[-1], B.ST_DELIVERED)
        self.assertIn(b"later", [f.payload for f in self.phones[3].messages()])

    def test_reconnecting_phone_gets_missed_messages_and_statuses(self):
        p1 = self.phones[1]
        p1.write(self.gw[1], B.Frame(B.KIND_MSG, 5, dest=3, payload=b"one"))
        self.phones[3].write(self.gw[3], B.Frame(B.KIND_MSG, 6, dest=1, payload=b"two"))
        self._run(300)
        # 1 のスマホが入れ替わった（別の stream）。最後に受け取った連番 0 で HELLO
        again = _Phone(stream=99, client_id=p1.client_id)
        self.gw[1].notify = again.on_notify
        again.hello(self.gw[1], since=0)
        info = json.loads([f for f in again.frames if f.kind == B.KIND_INFO][0].payload)
        self.assertEqual((info["addr"], info["name"]), (1, "node1"))
        self.assertEqual([f.payload for f in again.messages()], [b"two"])
        self.assertEqual(again.statuses(5), [B.ST_DELIVERED], "自分が送ったものの最新の状態")
        # 受け取り済みの連番を伝えれば、もう送られない
        again.frames.clear()
        again.hello(self.gw[1], since=info["last_seq"])
        self.assertEqual(again.messages(), [])

    def test_legacy_text_is_sent_to_default_dest(self):
        self.gw[1].default_dest = B.BROADCAST
        self.gw[1].on_ble_write("ADCH|v1|旧アプリ".encode())
        self._run(60)
        self.assertIn("ADCH|v1|旧アプリ".encode(), [f.payload for f in self.phones[3].messages()])
        self.assertEqual([f for f in self.phones[1].frames if f.kind == B.KIND_STATUS], [])

    def test_nodes(self):
        p1 = self.phones[1]
        p1.write(self.gw[1], B.Frame(B.KIND_NODES_REQ))
        nodes = json.loads([f for f in p1.frames if f.kind == B.KIND_NODES][-1].payload)
        self.assertEqual(sorted(n["addr"] for n in nodes), [2, 3])

    def test_too_long_message_fails(self):
        p1 = self.phones[1]
        p1.write(self.gw[1], B.Frame(B.KIND_MSG, 11, dest=3, payload=bytes(5000)))
        self.assertEqual(p1.statuses(11), [B.ST_FAILED])


if __name__ == "__main__":
    unittest.main()
