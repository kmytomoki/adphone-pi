# -*- coding: utf-8 -*-
"""
mesh/router.py  ―  管理型フラッディング（ROUTING_PLAN.md 3.1, Phase 3）

v1（flood_v1）からの変更:
    - パケット v2（mesh/packet.py）: 32bit msg_id・hop_start・path・分割
    - 中継の待ち時間を受信 RSSI で決める（Meshtastic 方式）。弱い電波で受けたノード
      （= 遠くにいて、新しい範囲をカバーできる可能性が高いノード）ほど早く中継する
    - 待っている間に同じパケットの中継を cancel_threshold 回聞いたら、自分の中継を取りやめる
      E220 は受信を UART で受け取り終わるまで分からないため、待ち時間の単位（スロット）は
      「UART 送信 + 電波 + UART 受信」の 1 パケット分と長い。窓は隣ノードの数に比例させる
      （隣が少ない網で無駄に待たない）。既定値はシミュレータで決めた（ROUTING_PLAN.md Phase 3）
    - 役割: ROUTER は早く・必ず中継する / CLIENT は待って取りやめ可 / CLIENT_MUTE は中継しない
      隣に ROUTER がいる CLIENT は、ROUTER の窓の後ろで待つ
    - DATA は署名なし（ペア鍵の AES-GCM で送信者を認証）、ANNOUNCE は自己署名
    - 鍵は永続化して TOFU で固定（mesh/identity.py, mesh/nodedb.py）
    - 宛先の鍵がないときは「宛先つき ANNOUNCE」（= 鍵の要求）を流し、届くまで保留する

ユニキャストもまだフラッディングで届ける（経路学習・ACK は Phase 4）。
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable

from . import packet as P
from .airtime import lora_airtime, lora_sensitivity
from .core import Delivery, MessageKey, NodeContext, TimerHandle, TxMeta
from .identity import CryptoError, Identity
from .nodedb import NEIGHBOR_TTL_SEC, NodeDB

_E220_OVERHEAD = 7 + 3     # 外層フレーム + Fixed Mode ヘッダ


@dataclass
class _PendingRelay:
    pkt: P.Packet
    timer: TimerHandle
    q: int = P.LINK_Q_UNKNOWN     # このパケットを受けたときのリンク品質
    dups: int = 0


@dataclass
class _PendingTx:
    since: float
    dest: int
    msg_id: int
    payload: bytes


@dataclass
class _PendingRx:
    since: float
    pkt: P.Packet          # 組み立て済み（body = 本文全体）


@dataclass
class RouterStats:
    relayed: int = 0
    relay_cancelled: int = 0
    duplicates: int = 0
    bad_packet: int = 0
    bad_signature: int = 0
    decrypt_failed: int = 0
    key_conflicts: int = 0
    send_expired: int = 0
    key_requests: int = 0


class ManagedFloodRouter:
    name = "managed_v2"

    def __init__(self, ctx: NodeContext, identity: Identity | None = None,
                 nodedb: NodeDB | None = None, role: str = "CLIENT",
                 roles: dict[int, str] | None = None, hop_limit: int = 3,
                 group_key: bytes | None = None, group_key_id: int = 0, node_name: str = "",
                 announce_interval: float | None = 900.0, startup_announce_spread: float = 60.0,
                 sf: int = 7, bw_hz: int = 125_000, uart_baud: int = 9600,
                 slots_per_neighbor: float = 2.0, rssi_span: float = 3.0, cancel_threshold: int = 1,
                 rssi_low_margin: float = 3.0, rssi_high_margin: float = 20.0,
                 seen_ttl: float = 600.0, seen_max: int = 2048,
                 pending_hold: float = 120.0, key_request_gap: float = 30.0,
                 on_event: Callable[[str, dict], None] | None = None):
        self.ctx = ctx
        self.addr = ctx.address
        rnd = ctx.random()
        self.identity = identity or Identity.from_seed(bytes(rnd.getrandbits(8) for _ in range(64)))
        self.nodedb = nodedb or NodeDB()
        self.role = (roles or {}).get(self.addr, role)
        if not 0 <= hop_limit <= P.MAX_HOP_LIMIT:
            raise ValueError("hop_limit は 0〜{}".format(P.MAX_HOP_LIMIT))
        self.hop_limit = hop_limit
        self.group_key = group_key
        self.group_key_id = group_key_id
        self.node_name = node_name
        self.announce_interval = announce_interval
        self.startup_announce_spread = startup_announce_spread
        self.sf, self.bw_hz, self.uart_baud = sf, bw_hz, uart_baud
        self.sensitivity = lora_sensitivity(sf, bw_hz)
        self.slots_per_neighbor, self.rssi_span = slots_per_neighbor, rssi_span
        self.cancel_threshold = cancel_threshold
        self.rssi_low_margin, self.rssi_high_margin = rssi_low_margin, rssi_high_margin
        self.seen_ttl, self.seen_max = seen_ttl, seen_max
        self.pending_hold = pending_hold
        self.key_request_gap = key_request_gap
        self.on_event = on_event
        self.stats = RouterStats()

        # msg_id = 起動ごとの乱数(上位 16bit) + 連番(下位 16bit)
        self._boot_id = rnd.getrandbits(16)
        self._counter = 0
        self._seen: OrderedDict[tuple[int, int, int], float] = OrderedDict()
        self._relays: dict[tuple[int, int, int], _PendingRelay] = {}
        self._reasm = P.Reassembler()
        self._pending_tx: list[_PendingTx] = []
        self._pending_rx: dict[int, list[_PendingRx]] = {}
        self._last_key_request: dict[int, float] = {}
        self._last_bcast_announce = -1e9

    @staticmethod
    def reach_hops(params: dict) -> int:
        """何ホップ先まで届くか（シミュレータの「TTL 圏内」の判定用）。"""
        return params.get("hop_limit", 3) + 1

    # ════════════════════════════════════════════════════════
    #  送信
    # ════════════════════════════════════════════════════════
    def start(self) -> None:
        if self.announce_interval:
            delay = self.ctx.random().uniform(0, self.startup_announce_spread)
            self.ctx.call_later(delay, self._periodic_announce)

    def send(self, dest: int, payload: bytes) -> MessageKey:
        """メッセージを送る。宛先の鍵がまだなければ鍵を要求し、届くまで保留する。"""
        mid = self._next_msg_id()
        key = MessageKey(self.addr, mid)
        if dest == P.BROADCAST_ADDR:
            if self.group_key is None:
                raise ValueError("グループ鍵が未設定のためブロードキャストできません")
            base = self._base(P.TYPE_GROUP_DATA, dest, mid)
            body = self.identity.seal_group(base.aad(), payload, self.group_key, self.group_key_id)
            self._originate(base, body, key)
            return key
        if self.nodedb.get(dest) is None:
            self._pending_tx.append(_PendingTx(self.ctx.now(), dest, mid, payload))
            self._event("key_wait", dest=dest, msg_id=mid)
            self._request_key(dest)
            return key
        self._send_data(dest, mid, payload)
        return key

    def _send_data(self, dest: int, mid: int, payload: bytes) -> None:
        base = self._base(P.TYPE_DATA, dest, mid)
        body = self.identity.seal_data(base.aad(), payload, self.nodedb.get(dest).dh_pub)
        self._originate(base, body, MessageKey(self.addr, mid))

    def _base(self, ptype: int, dest: int, mid: int) -> P.Packet:
        return P.Packet(ptype, self.addr, dest, mid, self.hop_limit, self.hop_limit)

    def _originate(self, base: P.Packet, body: bytes, key: MessageKey, kind: str = "origin") -> None:
        for pkt in P.fragment(base, body):
            self._mark_seen(self._dkey(pkt))
            self._tx(pkt, TxMeta(kind, key))

    def _next_msg_id(self) -> int:
        self._counter = (self._counter + 1) & 0xFFFF
        return (self._boot_id << 16) | self._counter

    # ── ANNOUNCE ────────────────────────────────────────────
    def _periodic_announce(self) -> None:
        self._announce(P.BROADCAST_ADDR)
        rnd = self.ctx.random()
        self.ctx.call_later(self.announce_interval * rnd.uniform(0.9, 1.1), self._periodic_announce)

    def announce(self) -> None:
        """今すぐ ANNOUNCE を送る（CLI の reannounce 用）。"""
        self._announce(P.BROADCAST_ADDR)

    def _announce(self, dest: int) -> None:
        """dest がブロードキャスト以外なら、dest への「鍵の要求」を兼ねる。"""
        mid = self._next_msg_id()
        if dest == P.BROADCAST_ADDR:
            self._last_bcast_announce = self.ctx.now()
        base = self._base(P.TYPE_ANNOUNCE, dest, mid)
        body = self.identity.announce_body(base.aad(), self.role, self.node_name)
        self._originate(base, body, MessageKey(self.addr, mid), kind="announce")

    def _request_key(self, dest: int) -> None:
        now = self.ctx.now()
        if now - self._last_key_request.get(dest, -1e9) < self.key_request_gap:
            return
        self._last_key_request[dest] = now
        self.stats.key_requests += 1
        self._announce(dest)

    # ════════════════════════════════════════════════════════
    #  受信
    # ════════════════════════════════════════════════════════
    def on_receive(self, raw: bytes, rssi: int | None) -> None:
        try:
            pkt = P.Packet.decode(raw)
        except P.PacketError:
            self.stats.bad_packet += 1
            return
        self._on_flood(pkt, raw, rssi)

    def _on_flood(self, pkt: P.Packet, raw: bytes, rssi: int | None) -> None:
        now = self.ctx.now()
        k = self._dkey(pkt)
        if self._is_seen(k, now):
            self._on_duplicate(pkt)
            if pkt.src != self.addr:
                self._on_copy(pkt, rssi)
            return
        self._mark_seen(k)
        if pkt.src == self.addr:
            return
        self.nodedb.heard(pkt.src, pkt.last_hop, pkt.hops_taken + 1, rssi, now)
        self._on_copy(pkt, rssi)

        if pkt.type == P.TYPE_ANNOUNCE:
            ok = self._on_announce(pkt)
        elif pkt.type == P.TYPE_DATA:
            ok = self._on_data(pkt) if pkt.dest == self.addr else True
        elif pkt.type == P.TYPE_GROUP_DATA:
            ok = self._on_group(pkt)
        else:
            ok = True   # ACK / NACK は Phase 4

        if ok and pkt.dest != self.addr:
            self._maybe_relay(pkt, len(raw), rssi)

    # ── 管理型フラッディング ────────────────────────────────
    def _maybe_relay(self, pkt: P.Packet, raw_len: int, rssi: int | None) -> None:
        if pkt.hop_limit <= 0 or self.role == "CLIENT_MUTE":
            return
        k = self._dkey(pkt)
        delay = self._relay_delay(raw_len + P.PATH_ENTRY, rssi)
        self._relays[k] = _PendingRelay(pkt, self.ctx.call_later(delay, lambda: self._do_relay(k)),
                                        self.link_quality(rssi))

    def _my_neighbors(self) -> set[int]:
        """最近聞こえた隣ノード（待ち窓の大きさを決めるのに使う）。

        「隣が全員もう送っていれば中継しない」という省略も試したが、シミュレータで
        送信数が変わらず（20 台で 7.34 → 7.32）、起動直後に隣を把握しきれていないと
        中継を誤って省略する危険があるため採らなかった。
        """
        now = self.ctx.now()
        return {a for a, nb in self.nodedb.neighbors.items()
                if now - nb.last_heard < NEIGHBOR_TTL_SEC}

    def _relay_delay(self, pkt_len: int, rssi: int | None) -> float:
        """中継までの待ち時間。

        窓の大きさ = スロット × 隣ノード数 × slots_per_neighbor（競合する相手が多いほど広げる）。
        受信 RSSI が弱いほど窓の前のほう（最大で 2^rssi_span 倍の差）から選ぶ。
        """
        rnd = self.ctx.random()
        slot = self.slot_time(pkt_len)
        base = slot * self.slots_per_neighbor * max(1, len(self._my_neighbors()))
        if self.role == "ROUTER":
            return rnd.uniform(0, base)
        if rssi is None:
            frac = 0.5
        else:
            margin = rssi - self.sensitivity
            frac = (margin - self.rssi_low_margin) / (self.rssi_high_margin - self.rssi_low_margin)
            frac = min(1.0, max(0.0, frac))
        window = base * 2 ** (frac * self.rssi_span)
        offset = base if self.nodedb.has_router_neighbor(self.ctx.now()) else 0.0
        return offset + rnd.uniform(0, window)

    def slot_time(self, pkt_len: int) -> float:
        """1 パケットが隣に届いて処理されるまでの時間（UART 送信 + 電波 + UART 受信）。"""
        on_air = pkt_len + _E220_OVERHEAD
        uart = on_air * 10 / self.uart_baud
        return lora_airtime(on_air, self.sf, self.bw_hz) + 2 * uart + 0.02

    def _on_duplicate(self, pkt: P.Packet) -> None:
        self.stats.duplicates += 1
        k = self._dkey(pkt)
        pr = self._relays.get(k)
        if pr is None or self.role == "ROUTER":
            return
        pr.dups += 1
        if pr.dups >= self.cancel_threshold:
            pr.timer.cancel()
            del self._relays[k]
            self.stats.relay_cancelled += 1

    def _do_relay(self, k: tuple[int, int, int]) -> None:
        pr = self._relays.pop(k, None)
        if pr is None:
            return
        out = pr.pkt.relayed_by(self.addr, pr.q)
        kind = "announce" if out.type == P.TYPE_ANNOUNCE else "relay"
        self._tx(out, TxMeta(kind, MessageKey(out.src, out.msg_id)))
        self.stats.relayed += 1

    # ── フック（Phase 4 の ReliableRouter が上書きする） ────
    def _dkey(self, pkt: P.Packet) -> tuple:
        """重複判定のキー。"""
        return pkt.dedup_key

    def _on_copy(self, pkt: P.Packet, rssi: int | None) -> None:
        """フラッディングのパケットを受けたとき（重複のコピーも含む。他ノード発のみ）。"""

    def link_quality(self, rssi: int | None) -> int:
        """受信 RSSI → リンク品質（感度からの余裕 dB, 0〜254。不明は 255）。"""
        if rssi is None:
            return P.LINK_Q_UNKNOWN
        return int(min(254, max(0, round(rssi - self.sensitivity))))

    def _tx(self, pkt: P.Packet, meta: TxMeta) -> None:
        self.ctx.transmit(pkt.encode(), meta)

    # ── 種類ごとの処理（False を返したら中継しない） ─────────
    def _on_announce(self, pkt: P.Packet) -> bool:
        try:
            info = Identity.parse_announce(pkt.aad(), pkt.body)
        except CryptoError:
            self.stats.bad_signature += 1
            return False
        now = self.ctx.now()
        result = self.nodedb.learn(pkt.src, info, now)
        if result == "conflict":
            self.stats.key_conflicts += 1
            self._event("key_conflict", addr=pkt.src, fingerprint=info.ed_pub[:8].hex())
        elif result == "new":
            self._event("peer", addr=pkt.src, role=info.role, name=info.name,
                        fingerprint=info.ed_pub[:8].hex())
            self._flush_pending(pkt.src)
        if pkt.dest == self.addr:
            # 自分宛ての ANNOUNCE = 鍵の要求。全体へ ANNOUNCE を返す（要求した以外のノードも
            # 鍵を覚えるので、複数のノードから要求が来ても 1 回の応答で済ませる）
            if now - self._last_bcast_announce >= self.key_request_gap / 3:
                self._announce(P.BROADCAST_ADDR)
        elif pkt.dest != P.BROADCAST_ADDR:
            # 他のノードが pkt.dest の鍵を要求した → 応答は全体に流れるので、自分は要求を控える
            self._last_key_request[pkt.dest] = now
        return True

    def _on_data(self, pkt: P.Packet) -> bool:
        body = self._reasm.add(pkt, self.ctx.now())
        if body is None:
            return True
        whole = P.Packet(pkt.type, pkt.src, pkt.dest, pkt.msg_id, pkt.hop_limit, pkt.hop_start,
                         body, pkt.flags & ~P.FLAG_FRAGMENT, pkt.path)
        peer = self.nodedb.get(pkt.src)
        if peer is None:
            self._hold_rx(whole)
            return True
        try:
            plaintext = self.identity.open_data(whole.aad(), body, peer.dh_pub)
        except CryptoError:
            self.stats.decrypt_failed += 1
            return True
        self._deliver(whole, plaintext)
        return True

    def _on_group(self, pkt: P.Packet) -> bool:
        body = self._reasm.add(pkt, self.ctx.now())
        if body is None or self.group_key is None:
            return True
        whole = P.Packet(pkt.type, pkt.src, pkt.dest, pkt.msg_id, pkt.hop_limit, pkt.hop_start,
                         body, pkt.flags & ~P.FLAG_FRAGMENT, pkt.path)
        try:
            if Identity.group_key_id(body) != self.group_key_id:
                self._event("group_key_mismatch", addr=pkt.src, key_id=body[0])
                return True
        except ValueError:
            self.stats.bad_packet += 1
            return False
        sender = self.nodedb.get(pkt.src)
        if sender is None:
            self._hold_rx(whole)
            return True
        return self._open_group(whole, sender.ed_pub)

    def _open_group(self, whole: P.Packet, ed_pub: bytes) -> bool:
        try:
            plaintext = Identity.open_group(whole.aad(), whole.body, self.group_key, ed_pub)
        except CryptoError:
            self.stats.bad_signature += 1
            return False
        self._deliver(whole, plaintext)
        return True

    def _deliver(self, pkt: P.Packet, plaintext: bytes) -> None:
        self.ctx.deliver(Delivery(pkt.src, pkt.dest, pkt.msg_id, plaintext, pkt.hops_taken + 1))

    # ── 鍵待ち ──────────────────────────────────────────────
    def _hold_rx(self, whole: P.Packet) -> None:
        self._pending_rx.setdefault(whole.src, []).append(_PendingRx(self.ctx.now(), whole))
        self._request_key(whole.src)

    def _flush_pending(self, peer: int) -> None:
        now = self.ctx.now()
        keep = []
        for p in self._pending_tx:
            if now - p.since > self.pending_hold:
                self.stats.send_expired += 1
                self._event("send_expired", dest=p.dest, msg_id=p.msg_id)
            elif p.dest == peer:
                self._send_data(p.dest, p.msg_id, p.payload)
                self._event("key_ready", dest=p.dest, msg_id=p.msg_id)
            else:
                keep.append(p)
        self._pending_tx = keep

        node = self.nodedb.get(peer)
        for p in self._pending_rx.pop(peer, []):
            if now - p.since > self.pending_hold:
                continue
            if p.pkt.type == P.TYPE_GROUP_DATA:
                self._open_group(p.pkt, node.ed_pub)
            else:
                try:
                    self._deliver(p.pkt, self.identity.open_data(p.pkt.aad(), p.pkt.body, node.dh_pub))
                except CryptoError:
                    self.stats.decrypt_failed += 1

    # ── 重複キャッシュ ──────────────────────────────────────
    def _is_seen(self, k: tuple[int, int, int], now: float) -> bool:
        t = self._seen.get(k)
        return t is not None and now - t < self.seen_ttl

    def _mark_seen(self, k: tuple[int, int, int]) -> None:
        now = self.ctx.now()
        self._seen[k] = now
        self._seen.move_to_end(k)
        while len(self._seen) > self.seen_max:
            self._seen.popitem(last=False)
        # 古いものを先頭から捨てる
        while self._seen:
            first_k, first_t = next(iter(self._seen.items()))
            if now - first_t < self.seen_ttl:
                break
            self._seen.popitem(last=False)

    def _event(self, event: str, **info) -> None:
        if self.on_event:
            self.on_event(event, info)

