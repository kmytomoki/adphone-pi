# -*- coding: utf-8 -*-
"""
mesh/reliable.py  ―  ACK・経路学習・ソースルーティング（ROUTING_PLAN.md 3.2・3.3・3.5, Phase 4）

ManagedFloodRouter（Phase 3）に次を足したもの（名前: routed_v2）:

ユニキャストの送り方
    - 宛先への経路を知っていれば DIRECT（path に経路を入れ、経路上のノードだけが転送する）
    - 知らなければ WANT_ACK つきでフラッディング
    - 宛先は ACK を「届いた経路の逆順」で DIRECT で返す。ACK の中身（ペア鍵で暗号化）に
      経路を入れるので、送信元はそれを経路キャッシュに入れ、次からは DIRECT で送る
    - ACK が来なければ再送（最大 max_attempts 回）。DIRECT で direct_attempts 回失敗したら
      経路を捨ててフラッディングに戻る

経路の決め方（mesh/links.py）
    受信したパケットの path には、各中継ノードが受信したときのリンク品質（電波の余裕 dB）が
    入っている。フラッディングの全コピー（重複も含む）・DIRECT・ACK から「リンク a–b の品質」の
    表を作り、送るたびにその上で最小コスト経路（リンクごとのコストの和。ETX に近い）を求める。
    失敗したリンクは品質を 0 にし、以後の観測で戻す。
    管理型フラッディングは「電波の弱い遠いノードが先に中継する」ため、最初に届いたコピーの
    道筋をそのまま経路にすると、不安定な長いリンクを通って DIRECT が失敗し続ける

区間ごとの再送（hop-by-hop）
    DIRECT で送ったノードは、次のノードがさらに転送するのを聞いたら「届いた」とみなす
    （次が宛先なら宛先の ACK を聞いたら）。聞こえなければその区間だけ hop_retries 回送り直し、
    それでもだめなら送信元へ NACK を返し、その隣を経由する経路を捨てる。
    E220 は受信したかを返さないので、Meshtastic と同じく「立ち聞き」で確かめる。
    前の区間のノードが立ち聞きに失敗して送り直してきたときは、データを転送し直さず
    （下流へ再送が連鎖するため）、短い HOP_ACK を前のノードにだけ返す。
    ACK は必ずデータが通った経路を逆にたどる（最後の区間のノードが ACK を聞けるように）。

ブロードキャストの暗黙の ACK
    送信元は、隣のだれかが中継するのを聞けば届いたとみなす。聞こえなければ 1 回だけ再送する。
    再送は重複判定で試行回数を無視するので、すでに受け取ったノードは中継しない。

送信予算（ARIB STD-T108）
    直近 1 時間の自分の送信時間が airtime_budget × budget_ratio を超えたら、
    フラッディングの中継をやめる（自分のメッセージと DIRECT の転送は続ける）。
    既定の 360 秒/時は仮の値。E220-900JP の設定と ARIB の区分を確認して決めること。
"""
from __future__ import annotations

import struct
from collections import OrderedDict, deque
from dataclasses import dataclass, replace

from . import packet as P
from .airtime import lora_airtime
from .core import MessageKey, NodeContext, TimerHandle, TxMeta
from .identity import CryptoError
from .links import LinkTable
from .router import _E220_OVERHEAD, ManagedFloodRouter, RouterStats

NACK_ROUTE_BROKEN = 1


def link_cost(q: int) -> float:
    """リンク品質（感度からの余裕 dB）→ コスト。1 回で届く見込みが低いほど高い。"""
    if q == P.LINK_Q_UNKNOWN:
        return 3.0          # 分からないリンクは弱めに見積もる（楽観すると弱いリンクを選んでしまう）
    if q >= 10:
        return 1.0
    if q >= 6:
        return 1.5
    if q >= 3:
        return 3.0
    return 6.0


@dataclass
class ReliableStats(RouterStats):
    acked: int = 0
    send_failed: int = 0
    retries: int = 0
    direct_sent: int = 0
    flood_sent: int = 0
    hop_retries: int = 0
    hop_failures: int = 0
    nacks_sent: int = 0
    nacks_received: int = 0
    acks_sent: int = 0
    hop_acks_sent: int = 0
    links_failed: int = 0
    broadcast_retries: int = 0
    budget_drops: int = 0


@dataclass
class _Outgoing:
    dest: int
    msg_id: int
    payload: bytes
    attempt: int = 0
    direct_tries: int = 0
    last_route: tuple[int, ...] | None = None      # 直前の試行で使った経路（フラッディングなら None）
    timer: TimerHandle | None = None


@dataclass
class _HopWait:
    pkt: P.Packet
    meta: TxMeta
    expect_forward: bool        # True: 次のノードの転送を待つ / False: 宛先の ACK を待つ
    tries: int = 0
    timer: TimerHandle | None = None


class ReliableRouter(ManagedFloodRouter):
    name = "routed_v2"

    def __init__(self, ctx: NodeContext, max_attempts: int = 4, direct_attempts: int = 2,
                 hop_retries: int = 2, route_ttl: float = 1800.0,
                 airtime_budget: float = 360.0, budget_ratio: float = 0.8,
                 broadcast_retry: bool = True, max_avg_link_cost: float = 3.0,
                 node_silent_sec: float = 60.0, track_ack_hops: bool = True, **kw):
        super().__init__(ctx, **kw)
        if not 1 <= max_attempts <= P.MAX_ATTEMPT + 1:
            raise ValueError("max_attempts は 1〜{}".format(P.MAX_ATTEMPT + 1))
        self.max_attempts = max_attempts
        self.direct_attempts = direct_attempts
        self.hop_retries = hop_retries
        self.route_ttl = route_ttl
        self.airtime_budget = airtime_budget
        self.budget_ratio = budget_ratio
        self.broadcast_retry = broadcast_retry
        self.max_avg_link_cost = max_avg_link_cost
        self.node_silent_sec = node_silent_sec
        self.track_ack_hops = track_ack_hops
        self.stats = ReliableStats()
        self._rx_q = P.LINK_Q_UNKNOWN          # 処理中のパケットを受けたときのリンク品質

        self.links = LinkTable(ttl=route_ttl)
        self._outgoing: dict[int, _Outgoing] = {}                 # msg_id → 送信中
        self._hop_waits: dict[tuple, _HopWait] = {}
        self._ack_index: dict[tuple[int, int], tuple] = {}         # (データの宛先, msg_id) → hop wait キー
        self._fwd_count: dict[tuple, int] = {}
        self._delivered: OrderedDict[tuple[int, int], float] = OrderedDict()
        self._ack_sent: dict[tuple[int, int], float] = {}
        self._bcast_waits: dict[tuple, TimerHandle] = {}
        self._airlog: deque[tuple[float, float]] = deque()

    # ════════════════════════════════════════════════════════
    #  経路（リンク品質表の上の最小コスト経路）
    # ════════════════════════════════════════════════════════
    def route_for(self, dest: int) -> tuple[int, ...] | None:
        """DIRECT に使う経路（中継ノード列）。知らない・弱すぎる（平均リンクコストが高い）なら None。"""
        found = self.links.best_path(self.addr, dest, self.ctx.now(), link_cost,
                                     P.MAX_HOP_LIMIT + 1)
        if found is None:
            return None
        path, cost = found
        if cost > self.max_avg_link_cost * (len(path) + 1):
            return None
        return path

    def _observe_chain(self, nodes: tuple[int, ...], quals: tuple[int, ...]) -> None:
        """nodes[i] → nodes[i+1] のリンクを品質 quals[i] で使えたと記録する。"""
        now = self.ctx.now()
        for a, b, q in zip(nodes, nodes[1:], quals):
            self.links.observe(a, b, q, now)

    def _observe_packet(self, pkt: P.Packet, my_q: int) -> None:
        """受信したパケットが通ってきたリンク（送信元 → 中継 → … → 自分）を記録する。"""
        h = pkt.hops_taken if pkt.is_direct else len(pkt.path)
        senders = (pkt.src,) + tuple(pkt.path[:h])
        self._observe_chain(senders + (self.addr,), tuple(pkt.link_q[:h]) + (my_q,))

    def _link_failed(self, a: int, b: int) -> None:
        """a から b へ届かなかった。b がしばらく何も送っていなければ、止まったとみなす。"""
        now = self.ctx.now()
        self.links.fail(a, b, now)
        self.stats.links_failed += 1
        heard = self.links.last_heard(b)
        if heard is None or now - heard > self.node_silent_sec:
            self.links.fail_node(b, now)

    def _on_copy(self, pkt: P.Packet, rssi: int | None) -> None:
        # フラッディングのコピー（重複も含む）は、それぞれ別の道筋のリンクを教えてくれる
        self._observe_packet(pkt, self.link_quality(rssi))

    # ════════════════════════════════════════════════════════
    #  送信
    # ════════════════════════════════════════════════════════
    def send(self, dest: int, payload: bytes) -> MessageKey:
        if dest != P.BROADCAST_ADDR:
            return super().send(dest, payload)
        if self.group_key is None:
            raise ValueError("グループ鍵が未設定のためブロードキャストできません")
        mid = self._next_msg_id()
        key = MessageKey(self.addr, mid)
        base = self._base(P.TYPE_GROUP_DATA, dest, mid)
        body = self.identity.seal_group(base.aad(), payload, self.group_key, self.group_key_id)
        frags = P.fragment(base, body)
        for f in frags:
            self._mark_seen(self._dkey(f))
            self._tx(f, TxMeta("origin", key))
        if self.broadcast_retry and self._my_neighbors():
            k = self._dkey(frags[0])
            self._bcast_waits[k] = self.ctx.call_later(
                self._bcast_wait(frags[0]), lambda: self._broadcast_retry(k, frags, key))
        return key

    def _bcast_wait(self, pkt: P.Packet) -> float:
        return self._flood_hop_time(len(pkt.encode())) + 2 * self.slot_time(P.MAX_PACKET)

    def _broadcast_retry(self, k: tuple, frags: list[P.Packet], key: MessageKey) -> None:
        if self._bcast_waits.pop(k, None) is None:
            return
        self.stats.broadcast_retries += 1
        for f in frags:
            self._tx(f.with_attempt(1), TxMeta("retry", key))
        # 再送の後も聞こえなければ「中継を確認できなかった」と知らせる
        self._bcast_waits[k] = self.ctx.call_later(
            self._bcast_wait(frags[0]), lambda: self._broadcast_unconfirmed(k))

    def _broadcast_unconfirmed(self, k: tuple) -> None:
        if self._bcast_waits.pop(k, None) is not None:
            self._event("broadcast_unconfirmed", msg_id=k[1])

    def _send_data(self, dest: int, mid: int, payload: bytes) -> None:
        """宛先の鍵がある状態で呼ばれる（鍵待ちの保留から呼ばれることもある）。"""
        out = _Outgoing(dest, mid, payload)
        self._outgoing[mid] = out
        self._attempt(out)

    def _attempt(self, out: _Outgoing) -> None:
        route = self.route_for(out.dest) if out.direct_tries < self.direct_attempts else None
        direct = route is not None
        flags = P.FLAG_WANT_ACK | (P.FLAG_DIRECT if direct else 0)
        hops = len(route) if direct else self.hop_limit
        base = P.Packet(P.TYPE_DATA, self.addr, out.dest, out.msg_id, hops, hops,
                        flags=flags, path=route if direct else ()).with_attempt(out.attempt)
        body = self.identity.seal_data(base.aad(), out.payload, self.nodedb.get(out.dest).dh_pub)
        frags = P.fragment(base, body)
        key = MessageKey(self.addr, out.msg_id)
        kind = "origin" if out.attempt == 0 else "retry"
        for f in frags:
            self._mark_seen(self._dkey(f))
            self._send_tracked(f, TxMeta(kind, key))
        out.last_route = route
        if direct:
            out.direct_tries += 1
            self.stats.direct_sent += 1
        else:
            self.stats.flood_sent += 1
        timeout = self._e2e_timeout(direct, len(route) if direct else self.hop_limit,
                                    len(frags[-1].encode()), len(frags))
        timeout *= 1.5 ** out.attempt
        timeout += self.ctx.random().uniform(0, self.slot_time(P.MAX_PACKET))
        out.timer = self.ctx.call_later(timeout, lambda: self._on_e2e_timeout(out.msg_id))

    def _e2e_timeout(self, direct: bool, hops: int, pkt_len: int, nfrags: int) -> float:
        slot = self.slot_time(pkt_len)
        legs = hops + 1
        if direct:
            # データの各区間（区間ごとの再送込み）+ ACK の戻り
            per_hop = (self.hop_retries + 1) * 3.5 * slot
            return legs * per_hop * nfrags + legs * per_hop
        return legs * self._flood_hop_time(pkt_len) * nfrags + legs * (self.hop_retries + 1) * 3.5 * slot

    def _flood_hop_time(self, pkt_len: int) -> float:
        """フラッディングで 1 ホップ進むのにかかる時間の目安（中継の待ち窓）。"""
        n = max(1, len(self._my_neighbors()))
        return self.slot_time(pkt_len) * (self.slots_per_neighbor * n * 2 + 2)

    def _on_e2e_timeout(self, mid: int) -> None:
        out = self._outgoing.get(mid)
        if out is None:
            return
        if out.last_route is not None:
            # どこで失敗したか分からないので、使った経路のリンクを少し悪く見積もる
            nodes = (self.addr,) + out.last_route + (out.dest,)
            for a, b in zip(nodes, nodes[1:]):
                self.links.degrade(a, b, self.ctx.now())
        self._retry(out)

    def _retry(self, out: _Outgoing) -> None:
        if out.timer is not None:
            out.timer.cancel()
        out.attempt += 1
        if out.attempt >= self.max_attempts:
            del self._outgoing[out.msg_id]
            self.stats.send_failed += 1
            self._event("send_failed", dest=out.dest, msg_id=out.msg_id)
            return
        self.stats.retries += 1
        self._attempt(out)

    # ── 区間ごとの確認と再送 ────────────────────────────────
    def _send_tracked(self, pkt: P.Packet, meta: TxMeta) -> None:
        """送信し、DIRECT なら次のノードが受け取ったかを立ち聞きで確かめる。"""
        self._tx(pkt, meta)
        if not pkt.is_direct:
            return
        if pkt.type in (P.TYPE_ACK, P.TYPE_NACK) and not self.track_ack_hops:
            return
        if pkt.next_hop != pkt.dest:
            expect_forward = True
        elif pkt.type == P.TYPE_DATA and pkt.flags & P.FLAG_WANT_ACK and not pkt.is_fragment:
            expect_forward = False
        else:
            return     # 宛先が返事をしないパケット（ACK・NACK の最後の区間など）
        k = self._dkey(pkt)
        old = self._hop_waits.pop(k, None)
        if old is not None and old.timer is not None:
            old.timer.cancel()
        hw = _HopWait(pkt, meta, expect_forward)
        self._hop_waits[k] = hw
        if not expect_forward:
            self._ack_index[(pkt.dest, pkt.msg_id)] = k
        self._arm_hop_timer(k, hw)

    def _arm_hop_timer(self, k: tuple, hw: _HopWait) -> None:
        slot = self.slot_time(len(hw.pkt.encode()))
        # 自分の送信 + 次の転送（待ち 0.3 スロット）+ 立ち聞き ≒ 2.3 スロット。送信待ちの列の分を足す
        wait = slot * (4.0 if hw.expect_forward else 5.0) + self.ctx.random().uniform(0, slot / 2)
        hw.timer = self.ctx.call_later(wait, lambda: self._on_hop_timeout(k))

    def _on_hop_timeout(self, k: tuple) -> None:
        hw = self._hop_waits.get(k)
        if hw is None:
            return
        if hw.tries < self.hop_retries:
            hw.tries += 1
            self.stats.hop_retries += 1
            self._tx(hw.pkt, hw.meta)
            self._arm_hop_timer(k, hw)
            return
        self._clear_hop_wait(k)
        self.stats.hop_failures += 1
        nxt = hw.pkt.next_hop
        self._link_failed(self.addr, nxt)
        pkt = hw.pkt
        if pkt.type != P.TYPE_DATA:
            return
        if pkt.src == self.addr:
            out = self._outgoing.get(pkt.msg_id)
            if out is not None and out.attempt == pkt.attempt:
                self._retry(out)        # 最初の区間で失敗 → すぐ次の手へ（そのリンクを避けた経路で）
        elif pkt.flags & P.FLAG_WANT_ACK:
            self._send_nack(pkt, nxt)

    def _check_hop_ack(self, pkt: P.Packet) -> None:
        """受信したパケットが、自分の待っている「次のノードの転送」や「宛先の ACK」なら解決する。"""
        k = self._dkey(pkt)
        hw = self._hop_waits.get(k)
        if hw is not None and hw.expect_forward and pkt.hops_taken > hw.pkt.hops_taken:
            self._clear_hop_wait(k)
        if pkt.type == P.TYPE_ACK and len(pkt.body) >= 4:
            acked = struct.unpack("!I", pkt.body[:4])[0]
            wk = self._ack_index.get((pkt.src, acked))
            if wk is not None:
                self._clear_hop_wait(wk)
        if pkt.type == P.TYPE_HOP_ACK and pkt.dest == self.addr and len(pkt.body) >= 8:
            self._clear_hop_wait(struct.unpack("!HIBB", pkt.body[:8]))

    def _clear_hop_wait(self, k: tuple) -> None:
        hw = self._hop_waits.pop(k, None)
        if hw is None:
            return
        if hw.timer is not None:
            hw.timer.cancel()
        if not hw.expect_forward:
            self._ack_index.pop((hw.pkt.dest, hw.pkt.msg_id), None)

    # ════════════════════════════════════════════════════════
    #  受信
    # ════════════════════════════════════════════════════════
    def on_receive(self, raw: bytes, rssi: int | None) -> None:
        try:
            pkt = P.Packet.decode(raw)
        except P.PacketError:
            self.stats.bad_packet += 1
            return
        self._rx_q = self.link_quality(rssi)
        self._check_hop_ack(pkt)
        if pkt.type == P.TYPE_HOP_ACK:
            return              # 自分宛てなら _check_hop_ack で処理済み。中継はしない
        if pkt.is_direct:
            self._on_direct(pkt, rssi)
        else:
            self._on_flood(pkt, raw, rssi)

    def _on_direct(self, pkt: P.Packet, rssi: int | None) -> None:
        if pkt.src == self.addr:
            return          # 自分のパケットを次のノードが転送した（_check_hop_ack で処理済み）
        now = self.ctx.now()
        k = self._dkey(pkt)
        self.nodedb.heard(pkt.src, pkt.last_hop, pkt.hops_taken + 1, rssi, now)
        self._observe_packet(pkt, self._rx_q)

        if pkt.dest == self.addr:
            if self._is_seen(k, now):
                # 前の区間が ACK を聞き逃して送り直してきた
                if pkt.type == P.TYPE_DATA:
                    if (pkt.src, pkt.msg_id) in self._delivered:
                        self._send_ack(pkt)         # ACK を返し直す
                    else:
                        self._send_hop_ack(pkt)     # まだ渡せていない（鍵待ちなど）が受け取ってはいる
                return
            self._mark_seen(k)
            if pkt.type == P.TYPE_DATA:
                self._on_data(pkt)
                if (pkt.src, pkt.msg_id) not in self._delivered and not pkt.is_fragment:
                    # 送信元の鍵がなく保留した → ACK は鍵が届いてから。前の区間には受け取ったと知らせる
                    self._send_hop_ack(pkt)
            elif pkt.type == P.TYPE_ACK:
                self._on_ack(pkt)
            elif pkt.type == P.TYPE_NACK:
                self._on_nack(pkt)
            return

        h = pkt.hops_taken
        if h >= len(pkt.path) or pkt.path[h] != self.addr:
            return          # 経路上の自分の番ではない（立ち聞き）
        if self._is_seen(k, now):
            # 前の区間が自分の転送を聞き逃して送り直してきた
            if k in self._hop_waits:
                return          # まだ次の区間を確かめ中 → 自分の再送が前のノードへの返事になる
            self._send_hop_ack(pkt)
            return
        self._mark_seen(k)
        self._forward_direct(pkt, k)

    def _send_hop_ack(self, pkt: P.Packet) -> None:
        """pkt を送ってきた前の区間のノードに「受け取って先へ渡した」と知らせる。"""
        prev = pkt.last_hop
        body = struct.pack("!HIBB", pkt.src, pkt.msg_id, pkt.frag_index, pkt.attempt)
        hack = P.Packet(P.TYPE_HOP_ACK, self.addr, prev, self._next_msg_id(), 0, 0, body,
                        flags=P.FLAG_DIRECT)
        self._tx(hack, TxMeta("hop_ack", MessageKey(pkt.src, pkt.msg_id)))
        self.stats.hop_acks_sent += 1

    def _forward_direct(self, pkt: P.Packet, k: tuple) -> None:
        self._fwd_count[k] = self._fwd_count.get(k, 0) + 1
        if len(self._fwd_count) > self.seen_max:
            self._fwd_count.pop(next(iter(self._fwd_count)))
        out = pkt.forwarded(self._rx_q)       # 経路上の自分の位置に、いま測ったリンク品質を入れる
        meta = self._meta_for(out)
        delay = self.ctx.random().uniform(0, 0.3 * self.slot_time(len(out.encode())))
        self.ctx.call_later(delay, lambda: self._send_tracked(out, meta))
        self.stats.relayed += 1

    @staticmethod
    def _meta_for(pkt: P.Packet) -> TxMeta:
        """集計用: ACK・NACK は「どのメッセージのための送信か」に振り分ける。"""
        if pkt.type in (P.TYPE_ACK, P.TYPE_NACK) and len(pkt.body) >= 4:
            acked = struct.unpack("!I", pkt.body[:4])[0]
            kind = "ack" if pkt.type == P.TYPE_ACK else "nack"
            return TxMeta(kind, MessageKey(pkt.dest, acked))
        return TxMeta("relay", MessageKey(pkt.src, pkt.msg_id))

    # ── 宛先側: 重複を除いて届け、ACK を返す ────────────────
    def _deliver(self, pkt: P.Packet, plaintext: bytes) -> None:
        if pkt.type != P.TYPE_DATA or pkt.dest != self.addr:
            super()._deliver(pkt, plaintext)
            return
        dk = (pkt.src, pkt.msg_id)
        if dk not in self._delivered:
            self._delivered[dk] = self.ctx.now()
            while len(self._delivered) > self.seen_max:
                self._delivered.popitem(last=False)
            super()._deliver(pkt, plaintext)
        if pkt.flags & P.FLAG_WANT_ACK:
            self._send_ack(pkt)

    def _send_ack(self, pkt: P.Packet) -> None:
        now = self.ctx.now()
        dk = (pkt.src, pkt.msg_id)
        if now - self._ack_sent.get(dk, -1e9) < 2 * self.slot_time(P.MAX_PACKET):
            return
        peer = self.nodedb.get(pkt.src)
        if peer is None:
            return
        self._ack_sent[dk] = now
        if len(self._ack_sent) > self.seen_max:
            self._ack_sent.pop(next(iter(self._ack_sent)))
        # データが通った経路（送信元 → 自分）とリンク品質。最後のリンクは自分が測った値
        forward = tuple(pkt.path)
        quals = tuple(pkt.link_q) + (self._rx_q,)
        back = tuple(reversed(forward))     # 最後の区間のノードが ACK を聞けるよう、往路を逆にたどる
        mid = self._next_msg_id()
        base = P.Packet(P.TYPE_ACK, self.addr, pkt.src, mid, len(back), len(back),
                        flags=P.FLAG_DIRECT, path=back)
        acked = struct.pack("!I", pkt.msg_id)
        inner = (acked + bytes([len(forward)])
                 + b"".join(struct.pack("!HB", a, q) for a, q in zip(forward, quals))
                 + bytes([quals[-1]]))
        ack = replace(base, body=acked + self.identity.seal_data(base.aad(), inner, peer.dh_pub))
        self._mark_seen(self._dkey(ack))
        self._send_tracked(ack, TxMeta("ack", MessageKey(pkt.src, pkt.msg_id)))
        self.stats.acks_sent += 1

    # ── 送信元側: ACK・NACK ─────────────────────────────────
    def _on_ack(self, pkt: P.Packet) -> None:
        if len(pkt.body) < 4:
            return
        acked = struct.unpack("!I", pkt.body[:4])[0]
        out = self._outgoing.get(acked)
        peer = self.nodedb.get(pkt.src)
        if out is None or out.dest != pkt.src or peer is None:
            return
        try:
            inner = self.identity.open_data(pkt.aad(), pkt.body[4:], peer.dh_pub)
        except CryptoError:
            self.stats.decrypt_failed += 1
            return
        n = inner[4] if len(inner) >= 5 else -1
        if n < 0 or inner[:4] != pkt.body[:4] or len(inner) != 6 + 3 * n:
            self.stats.bad_packet += 1
            return
        entries = [struct.unpack("!HB", inner[5 + 3 * j:8 + 3 * j]) for j in range(n)]
        route = tuple(a for a, _ in entries)
        quals = tuple(q for _, q in entries) + (inner[-1],)
        if out.timer is not None:
            out.timer.cancel()
        del self._outgoing[acked]
        self._observe_chain((self.addr,) + route + (out.dest,), quals)
        self.stats.acked += 1
        self._event("delivered", dest=out.dest, msg_id=acked, hops=len(route) + 1,
                    attempts=out.attempt + 1)

    def _send_nack(self, pkt: P.Packet, broken_next: int) -> None:
        """自分が経路の i 番目で、次へ渡せなかった → 送信元へ知らせる。"""
        i = pkt.hops_taken - 1          # 自分が送ったパケットの hops_taken = 自分の位置 + 1
        back = tuple(reversed(pkt.path[:max(0, i)]))
        mid = self._next_msg_id()
        body = struct.pack("!IBH", pkt.msg_id, NACK_ROUTE_BROKEN, broken_next)
        nack = P.Packet(P.TYPE_NACK, self.addr, pkt.src, mid, len(back), len(back), body,
                        flags=P.FLAG_DIRECT, path=back)
        self._mark_seen(self._dkey(nack))
        self._send_tracked(nack, TxMeta("nack", MessageKey(pkt.src, pkt.msg_id)))
        self.stats.nacks_sent += 1

    def _on_nack(self, pkt: P.Packet) -> None:
        # NACK は署名していない（偽の NACK でできるのはフラッディングに戻させることだけ）
        if len(pkt.body) < 7:
            return
        acked, _, broken = struct.unpack("!IBH", pkt.body[:7])
        out = self._outgoing.get(acked)
        if out is None:
            return
        self.stats.nacks_received += 1
        self._link_failed(pkt.src, broken)       # 壊れたリンクを避けた経路で送り直す
        self._retry(out)

    # ════════════════════════════════════════════════════════
    #  フラッディング側のフック
    # ════════════════════════════════════════════════════════
    def _dkey(self, pkt: P.Packet) -> tuple:
        # ブロードキャストと ANNOUNCE は試行回数を区別しない（再送を受け取り済みのノードは中継しない）
        if pkt.type in (P.TYPE_GROUP_DATA, P.TYPE_ANNOUNCE):
            return (pkt.src, pkt.msg_id, pkt.frag_index, 0)
        return pkt.dedup_key

    def _on_duplicate(self, pkt: P.Packet) -> None:
        super()._on_duplicate(pkt)
        k = self._dkey(pkt)
        t = self._bcast_waits.pop(k, None)
        if t is not None:
            t.cancel()          # 隣が中継した = 暗黙の ACK
            self._event("broadcast_relayed", msg_id=k[1])

    def _maybe_relay(self, pkt: P.Packet, raw_len: int, rssi: int | None) -> None:
        if self.budget_used() > self.airtime_budget * self.budget_ratio:
            self.stats.budget_drops += 1
            return
        super()._maybe_relay(pkt, raw_len, rssi)

    # ── 送信予算 ────────────────────────────────────────────
    def _tx(self, pkt: P.Packet, meta: TxMeta) -> None:
        raw_len = len(pkt.encode())
        self._airlog.append((self.ctx.now(), lora_airtime(raw_len + _E220_OVERHEAD, self.sf, self.bw_hz)))
        super()._tx(pkt, meta)

    def budget_used(self) -> float:
        """直近 1 時間の送信時間（秒）。"""
        horizon = self.ctx.now() - 3600.0
        while self._airlog and self._airlog[0][0] < horizon:
            self._airlog.popleft()
        return sum(a for _, a in self._airlog)
