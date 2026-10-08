# -*- coding: utf-8 -*-
"""
mesh/bleproto.py  ―  スマホ ↔ Pi の BLE プロトコル v2（ROUTING_PLAN.md 5 章, Phase 5）

アプリ側の実装: ReactNative/my-app/lib/bleProtocol.ts（形式を変えるときは両方そろえること）

BLE の 1 パケット（チャンク）:
  ┌──────┬────────┬─────┬──────────────┐
  │ 0xAD │ stream │ ctl │ data          │   ctl: bit7 = 続きがある, bit0-6 = 何番目か
  │ 1B   │ 1B     │ 1B  │ ≤ CHUNK_DATA  │
  └──────┴────────┴─────┴──────────────┘
  - stream: 送り手ごとの番号。スマホは接続ごとに 1〜255 の乱数を選ぶ（Pi は 0）。
    複数のスマホが同時に書き込んでも、Pi が混ぜずに組み立てられるようにするため
  - 先頭 0xAD は UTF-8 の文字列の先頭には現れないので、旧アプリの生テキストと区別できる

チャンクを組み立てたもの（フレーム）:
  ┌─────┬──────┬────────┬──────┬──────┬─────────┐
  │ ver │ kind │ msg_id │ from │ to   │ payload │
  │ 1B  │ 1B   │ 4B     │ 2B   │ 2B   │ ...     │
  └─────┴──────┴────────┴──────┴──────┴─────────┘

kind:
  MSG       スマホ→Pi: 送信（msg_id = アプリが付けた番号, to = 宛先, from は無視）
            Pi→スマホ: 受信（msg_id = Pi の受信箱の連番, from = 送信元ノード, to = 宛先）
  STATUS    Pi→スマホ: 配送状態（msg_id = アプリが付けた番号, payload = 状態 1B [+ ホップ数 1B]）
  HELLO     スマホ→Pi: 接続直後に送る（payload = client_id 8B + 最後に受け取った連番 4B）
  INFO      Pi→スマホ: HELLO への返事（from = Pi のノードアドレス, payload = JSON）
  NODES_REQ スマホ→Pi: ノード一覧を求める
  NODES     Pi→スマホ: ノード一覧（payload = JSON の配列）
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

MAGIC = 0xAD
VERSION = 2
CHUNK_MAX = 180                    # 1 パケットの上限（iOS の既定 MTU 185 - ATT ヘッダ 3 に収まる）
CHUNK_HEADER = 3
CHUNK_DATA = CHUNK_MAX - CHUNK_HEADER
MAX_CHUNKS = 64
PI_STREAM = 0

KIND_MSG = 0x01
KIND_STATUS = 0x02
KIND_HELLO = 0x03
KIND_INFO = 0x04
KIND_NODES_REQ = 0x05
KIND_NODES = 0x06
KINDS = (KIND_MSG, KIND_STATUS, KIND_HELLO, KIND_INFO, KIND_NODES_REQ, KIND_NODES)

# 配送状態（STATUS）
ST_QUEUED = 1       # Pi が受け付けた（宛先の鍵を待っている場合もここ）
ST_SENT = 2         # 電波に出した
ST_RELAYED = 3      # ブロードキャストを隣のノードが中継した
ST_DELIVERED = 4    # 宛先から ACK が返った
ST_WAITING = 5      # 届かなかった。Pi が保持して後で送り直す
ST_FAILED = 6       # 期限切れ・送れない内容

BROADCAST = 0xFFFF
_FRAME_FMT = "!BBIHH"
FRAME_HEADER = struct.calcsize(_FRAME_FMT)     # 10


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Frame:
    kind: int
    msg_id: int = 0
    src: int = 0
    dest: int = BROADCAST
    payload: bytes = b""

    def encode(self) -> bytes:
        return struct.pack(_FRAME_FMT, VERSION, self.kind, self.msg_id & 0xFFFFFFFF,
                           self.src, self.dest) + self.payload

    @classmethod
    def decode(cls, raw: bytes) -> "Frame":
        if len(raw) < FRAME_HEADER:
            raise ProtocolError("short frame")
        ver, kind, mid, src, dest = struct.unpack(_FRAME_FMT, raw[:FRAME_HEADER])
        if ver != VERSION:
            raise ProtocolError("unsupported version {}".format(ver))
        if kind not in KINDS:
            raise ProtocolError("unknown kind {}".format(kind))
        return cls(kind, mid, src, dest, raw[FRAME_HEADER:])


def is_chunk(data: bytes) -> bool:
    return len(data) >= CHUNK_HEADER and data[0] == MAGIC


def chunk(frame: bytes, stream: int = PI_STREAM) -> list[bytes]:
    """フレームを BLE のパケットに分ける。"""
    parts = [frame[i:i + CHUNK_DATA] for i in range(0, len(frame), CHUNK_DATA)] or [b""]
    if len(parts) > MAX_CHUNKS:
        raise ProtocolError("frame too long: {} bytes".format(len(frame)))
    out = []
    for i, part in enumerate(parts):
        more = 0x80 if i < len(parts) - 1 else 0
        out.append(bytes([MAGIC, stream & 0xFF, more | i]) + part)
    return out


class Reassembler:
    """チャンクを stream ごとに組み立てる。順番が飛んだら、その stream の途中のものは捨てる。"""

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._buf: dict[int, tuple[float, int, bytearray]] = {}   # stream → (開始時刻, 次の番号, データ)

    def add(self, data: bytes, now: float) -> tuple[int, bytes] | None:
        """完成したら (stream, フレームのバイト列) を返す。"""
        if not is_chunk(data):
            raise ProtocolError("not a chunk")
        stream, ctl = data[1], data[2]
        more, index = bool(ctl & 0x80), ctl & 0x7F
        body = data[CHUNK_HEADER:]
        cur = self._buf.get(stream)
        if cur is not None and now - cur[0] > self.timeout:
            cur = None
        if index == 0:
            cur = (now, 0, bytearray())
        if cur is None or cur[1] != index:
            self._buf.pop(stream, None)
            return None
        started, _, buf = cur
        buf.extend(body)
        if more:
            self._buf[stream] = (started, index + 1, buf)
            return None
        self._buf.pop(stream, None)
        return stream, bytes(buf)


def status_frame(msg_id: int, state: int, hops: int | None = None) -> Frame:
    payload = bytes([state]) if hops is None else bytes([state, min(255, hops)])
    return Frame(KIND_STATUS, msg_id, payload=payload)


def parse_hello(frame: Frame) -> tuple[bytes, int]:
    """HELLO の (client_id, 最後に受け取った連番)。"""
    if len(frame.payload) < 12:
        raise ProtocolError("short hello")
    return frame.payload[:8], struct.unpack("!I", frame.payload[8:12])[0]
