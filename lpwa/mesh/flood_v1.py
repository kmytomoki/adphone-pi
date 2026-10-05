# -*- coding: utf-8 -*-
"""
mesh/flood_v1.py  ―  現行ルーティング（Phase 1 時点）の移植

adphone_ble_lpwa_bridge.py / node_mesh.py の暗号モードと同じ規則で中継する。
シミュレータのベースライン（Phase 3 以降のアルゴリズムと比べる基準）として使う。

    - ヘッダは adhoc_crypto.py と同じ 8 バイト（src / dest / msg_id / ttl / type）
    - (src, msg_id) を最大 128 件覚えて重複を捨てる
    - 自分宛て DATA は受け取って終わり。それ以外（他者宛て・ブロードキャスト・
      GROUP_DATA・ANNOUNCE）は TTL-1 で中継する。TTL が 1 なら中継しない
    - 中継の前に 0〜relay_jitter 秒のランダム遅延を置く
    - ANNOUNCE を announce_interval 秒ごとに送る（None なら送らない）

暗号処理は行わず、パケット長だけを実物に合わせる（送信時間の再現に必要なのは長さだけ）。
"""
from __future__ import annotations

import struct
from collections import deque

from .core import Delivery, MessageKey, NodeContext, TxMeta

HEADER_FORMAT = "!HHHBB"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)   # 8

TYPE_ANNOUNCE = 0x01
TYPE_DATA = 0x02
TYPE_GROUP_DATA = 0x03
BROADCAST_ADDR = 0xFFFF

_SIG_NONCE = 12 + 64      # nonce + Ed25519 署名
_GCM_TAG = 16
_ANNOUNCE_BODY = 32 + 32  # Ed25519 公開鍵 + X25519 公開鍵


class FloodRouterV1:
    name = "flood_v1"

    def __init__(self, ctx: NodeContext, ttl: int = 3, relay_jitter: float = 0.5,
                 seen_max: int = 128, announce_interval: float | None = 300.0,
                 max_accept_ttl: int | None = None):
        self.ctx = ctx
        self.ttl = ttl
        self.relay_jitter = relay_jitter
        self.announce_interval = announce_interval
        self.max_accept_ttl = max_accept_ttl if max_accept_ttl is not None else min(255, ttl + 2)
        self._seen: deque[tuple[int, int]] = deque(maxlen=seen_max)
        self._seq = ctx.random().getrandbits(16)

    # ── 送信 ────────────────────────────────────────────────
    def start(self) -> None:
        if self.announce_interval:
            # 起動直後に送る（同時起動の衝突を少し散らす）
            self.ctx.call_later(self.ctx.random().uniform(0, 2.0), self._announce)

    def send(self, dest: int, payload: bytes) -> MessageKey:
        mid = self._next_seq()
        if dest == BROADCAST_ADDR:
            body = bytes(_SIG_NONCE + 1) + bytes(len(payload) + _GCM_TAG)   # key_id(1)
            ptype = TYPE_GROUP_DATA
        else:
            body = bytes(_SIG_NONCE) + bytes(len(payload) + _GCM_TAG)
            ptype = TYPE_DATA
        # 平文の代わりに先頭へ payload を置く（シミュレータで中身を確認できるように）
        body = payload + body[len(payload):]
        pkt = struct.pack(HEADER_FORMAT, self.ctx.address, dest, mid, self.ttl, ptype) + body
        key = MessageKey(self.ctx.address, mid)
        self.ctx.transmit(pkt, TxMeta("origin", key))
        return key

    def _announce(self) -> None:
        mid = self._next_seq()
        pkt = struct.pack(HEADER_FORMAT, self.ctx.address, BROADCAST_ADDR, mid, self.ttl,
                          TYPE_ANNOUNCE) + bytes(_ANNOUNCE_BODY)
        self.ctx.transmit(pkt, TxMeta("announce", MessageKey(self.ctx.address, mid)))
        rnd = self.ctx.random()
        self.ctx.call_later(self.announce_interval * rnd.uniform(0.9, 1.1), self._announce)

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0xFFFF
        self._seen.append((self.ctx.address, self._seq))
        return self._seq

    # ── 受信 ────────────────────────────────────────────────
    def on_receive(self, pkt: bytes, rssi: int | None) -> None:
        if len(pkt) < HEADER_SIZE:
            return
        src, dest, mid, ttl, ptype = struct.unpack(HEADER_FORMAT, pkt[:HEADER_SIZE])
        if ptype not in (TYPE_ANNOUNCE, TYPE_DATA, TYPE_GROUP_DATA):
            return
        if ttl == 0 or ttl > self.max_accept_ttl:
            return
        key = (src, mid)
        if key in self._seen:
            return
        self._seen.append(key)
        if src == self.ctx.address:
            return

        hops = self.ttl - ttl + 1
        if ptype == TYPE_ANNOUNCE:
            self._relay(pkt, ttl, "announce")
        elif ptype == TYPE_GROUP_DATA:
            self._deliver(src, dest, mid, pkt, hops)
            self._relay(pkt, ttl, "relay")
        elif dest == self.ctx.address:
            self._deliver(src, dest, mid, pkt, hops)
        elif dest == BROADCAST_ADDR:
            self._deliver(src, dest, mid, pkt, hops)
            self._relay(pkt, ttl, "relay")
        else:
            self._relay(pkt, ttl, "relay")

    def _deliver(self, src: int, dest: int, mid: int, pkt: bytes, hops: int) -> None:
        self.ctx.deliver(Delivery(src, dest, mid, pkt[HEADER_SIZE:], hops))

    def _relay(self, pkt: bytes, ttl: int, kind: str) -> None:
        if ttl <= 1:
            return
        src, dest, mid, _, ptype = struct.unpack(HEADER_FORMAT, pkt[:HEADER_SIZE])
        relay = struct.pack(HEADER_FORMAT, src, dest, mid, ttl - 1, ptype) + pkt[HEADER_SIZE:]
        meta = TxMeta(kind, MessageKey(src, mid))
        delay = self.ctx.random().uniform(0, self.relay_jitter)
        self.ctx.call_later(delay, lambda: self.ctx.transmit(relay, meta))
