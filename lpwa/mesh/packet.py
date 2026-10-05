# -*- coding: utf-8 -*-
"""
mesh/packet.py  ―  パケットフォーマット v2（ROUTING_PLAN.md 2 章）

共通ヘッダ（16 bytes + path）:

  ┌─────┬──────┬──────┬──────┬────────┬───────────┬───────────┬───────┬──────────┬────────┐
  │ ver │ type │ src  │ dest │ msg_id │ hop_limit │ hop_start │ flags │ path_len │ path   │
  │ 1B  │ 1B   │ 2B   │ 2B   │ 4B     │ 1B        │ 1B        │ 1B    │ 1B       │ 2B × n │
  └─────┴──────┴──────┴──────┴────────┴───────────┴───────────┴───────┴──────────┴────────┘

  hop_limit : 残り中継回数。中継のたびに 1 減らし、0 で受け取ったノードは中継しない
              （v1 の ttl と違い、hop_limit=3 なら送信元 + 3 回中継 = 最大 4 ホップ届く）
  hop_start : 送信時の hop_limit（変えない）。hop_start - hop_limit = 経由した中継の数
  path      : 中継したノードが自分のアドレスを末尾に追加する（中継は最大 7 回なので最大 7 個）

FRAGMENT フラグが立っていれば、本文の先頭 2 バイトが frag_index / frag_total。
重複判定のキーは (src, msg_id, frag_index)。

中継で変わるのは hop_limit・flags・path だけ。暗号の AAD には変わらない部分（aad()）を使う。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field, replace

VERSION = 0x02

TYPE_ANNOUNCE = 0x01
TYPE_DATA = 0x02
TYPE_GROUP_DATA = 0x03
TYPE_ACK = 0x04
TYPE_NACK = 0x05
KNOWN_TYPES = (TYPE_ANNOUNCE, TYPE_DATA, TYPE_GROUP_DATA, TYPE_ACK, TYPE_NACK)

FLAG_WANT_ACK = 0x01
FLAG_DIRECT = 0x02
FLAG_FRAGMENT = 0x04
FLAG_RETRY = 0x08

BROADCAST_ADDR = 0xFFFF
MAX_HOP_LIMIT = 7
MAX_PATH = MAX_HOP_LIMIT   # 中継は最大 MAX_HOP_LIMIT 回なので path があふれることはない

_HEADER_FMT = "!BBHHIBBBB"
HEADER_SIZE = struct.calcsize(_HEADER_FMT)      # 16
_AAD_FMT = "!BBHHIB"                            # ver, type, src, dest, msg_id, hop_start

# 1 パケットの上限: E220 のサブパケット 200B - 外層フレーム 7B
MAX_PACKET = 193
# path を MAX_PATH 個まで伸ばせるよう、本文はこれ以下にする
MAX_BODY = MAX_PACKET - HEADER_SIZE - 2 * MAX_PATH      # 163
FRAG_PREFIX = 2
MAX_FRAGMENT_BODY = MAX_BODY - FRAG_PREFIX              # 161
MAX_FRAGMENTS = 8


class PacketError(ValueError):
    pass


@dataclass(frozen=True)
class Packet:
    type: int
    src: int
    dest: int
    msg_id: int
    hop_limit: int
    hop_start: int
    body: bytes = b""
    flags: int = 0
    path: tuple[int, ...] = field(default_factory=tuple)
    frag_index: int = 0
    frag_total: int = 1

    # ── 派生値 ──────────────────────────────────────────────
    @property
    def is_broadcast(self) -> bool:
        return self.dest == BROADCAST_ADDR

    @property
    def is_fragment(self) -> bool:
        return bool(self.flags & FLAG_FRAGMENT)

    @property
    def hops_taken(self) -> int:
        return self.hop_start - self.hop_limit

    @property
    def dedup_key(self) -> tuple[int, int, int]:
        return (self.src, self.msg_id, self.frag_index)

    @property
    def last_hop(self) -> int:
        """このパケットを直前に送ったノード（中継がなければ送信元）。"""
        return self.path[-1] if self.path else self.src

    def aad(self) -> bytes:
        """中継で変わらない部分。暗号の AAD・署名対象に使う。"""
        return struct.pack(_AAD_FMT, VERSION, self.type, self.src, self.dest,
                           self.msg_id, self.hop_start)

    # ── 中継 ────────────────────────────────────────────────
    def relayed_by(self, addr: int) -> "Packet":
        """hop_limit を 1 減らし、path に addr を追加した中継用パケット。"""
        if self.hop_limit <= 0:
            raise PacketError("hop_limit is 0")
        return replace(self, hop_limit=self.hop_limit - 1, path=self.path + (addr,))

    # ── バイト列 ────────────────────────────────────────────
    def encode(self) -> bytes:
        if not 0 <= self.hop_limit <= self.hop_start <= MAX_HOP_LIMIT:
            raise PacketError("bad hop_limit/hop_start: {}/{}".format(self.hop_limit, self.hop_start))
        if len(self.path) > MAX_PATH:
            raise PacketError("path too long")
        body = self.body
        if self.is_fragment:
            body = bytes([self.frag_index, self.frag_total]) + body
        out = struct.pack(_HEADER_FMT, VERSION, self.type, self.src, self.dest,
                          self.msg_id & 0xFFFFFFFF, self.hop_limit, self.hop_start,
                          self.flags, len(self.path))
        out += b"".join(struct.pack("!H", a) for a in self.path) + body
        if len(out) > MAX_PACKET:
            raise PacketError("packet too long: {} > {}".format(len(out), MAX_PACKET))
        return out

    @classmethod
    def decode(cls, raw: bytes) -> "Packet":
        if len(raw) < HEADER_SIZE:
            raise PacketError("too short")
        ver, ptype, src, dest, mid, hop_limit, hop_start, flags, path_len = struct.unpack(
            _HEADER_FMT, raw[:HEADER_SIZE])
        if ver != VERSION:
            raise PacketError("unsupported version {}".format(ver))
        if ptype not in KNOWN_TYPES:
            raise PacketError("unknown type 0x{:02X}".format(ptype))
        if hop_start > MAX_HOP_LIMIT or hop_limit > hop_start:
            raise PacketError("bad hop_limit/hop_start: {}/{}".format(hop_limit, hop_start))
        if path_len > MAX_PATH:
            raise PacketError("path too long")
        end = HEADER_SIZE + 2 * path_len
        if len(raw) < end:
            raise PacketError("truncated path")
        path = tuple(struct.unpack("!{}H".format(path_len), raw[HEADER_SIZE:end]))
        body = raw[end:]
        frag_index, frag_total = 0, 1
        if flags & FLAG_FRAGMENT:
            if len(body) < FRAG_PREFIX:
                raise PacketError("truncated fragment header")
            frag_index, frag_total = body[0], body[1]
            if not 0 <= frag_index < frag_total <= MAX_FRAGMENTS:
                raise PacketError("bad fragment {}/{}".format(frag_index, frag_total))
            body = body[FRAG_PREFIX:]
        return cls(ptype, src, dest, mid, hop_limit, hop_start, body, flags, path,
                   frag_index, frag_total)


def fragment(base: Packet, body: bytes) -> list[Packet]:
    """body を 1 パケットに収まるように分割する（収まれば 1 個、FRAGMENT なし）。"""
    if len(body) <= MAX_BODY:
        return [replace(base, body=body, flags=base.flags & ~FLAG_FRAGMENT)]
    chunks = [body[i:i + MAX_FRAGMENT_BODY] for i in range(0, len(body), MAX_FRAGMENT_BODY)]
    if len(chunks) > MAX_FRAGMENTS:
        raise PacketError("message too long: {} bytes (max {})".format(
            len(body), MAX_FRAGMENTS * MAX_FRAGMENT_BODY))
    return [replace(base, body=c, flags=base.flags | FLAG_FRAGMENT,
                    frag_index=i, frag_total=len(chunks))
            for i, c in enumerate(chunks)]


class Reassembler:
    """分割パケットを (src, msg_id) ごとに組み立てる。timeout 秒で揃わなければ捨てる。"""

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout
        self._parts: dict[tuple[int, int], tuple[float, dict[int, bytes], int]] = {}

    def add(self, pkt: Packet, now: float) -> bytes | None:
        """揃ったら本文全体を返す。分割でないパケットはそのまま本文を返す。"""
        if not pkt.is_fragment:
            return pkt.body
        self._expire(now)
        key = (pkt.src, pkt.msg_id)
        started, parts, total = self._parts.get(key, (now, {}, pkt.frag_total))
        if total != pkt.frag_total:
            return None
        parts[pkt.frag_index] = pkt.body
        if len(parts) == total:
            self._parts.pop(key, None)
            return b"".join(parts[i] for i in range(total))
        self._parts[key] = (started, parts, total)
        return None

    def _expire(self, now: float) -> None:
        for key in [k for k, (t, _, _) in self._parts.items() if now - t > self.timeout]:
            del self._parts[key]
