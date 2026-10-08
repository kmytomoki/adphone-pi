# -*- coding: utf-8 -*-
from __future__ import annotations
"""
adhoc.py  ―  TTL ベース軽量アドホック通信ヘルパー

パケットフォーマット (5 バイトヘッダ + ペイロード):

    ┌────────────┬────────────┬──────────┬───────────────────────┐
    │  src_addr  │   msg_id   │   ttl    │       payload         │
    │  2 bytes   │  2 bytes   │  1 byte  │       N bytes         │
    └────────────┴────────────┴──────────┴───────────────────────┘

    src_addr : 送信元ノードアドレス (uint16)
    msg_id   : ノードごとの送信連番 (uint16, 0〜65535 でラップ)
               起動ごとに乱数から始める（再起動直後のパケットが重複扱いされないように）
    ttl      : 残りホップ数 (uint8, デフォルト 3)
    payload  : データ本体

重複検知:
    (src_addr, msg_id) の組み合わせを seen キャッシュ（最大 64 件）で管理。
    同じキーを持つパケットは decode() が None を返し、中継・通知をスキップする。

使い方:
    # 送信
    pkt = adhoc.encode(b"hello", src_addr=SELF_ADDRESS)
    lora_send(pkt)

    # 受信
    raw = lora_recv(2)
    result = adhoc.decode(raw)          # 重複なら None
    if result:
        src, msg_id, ttl, payload = result
        # 中継
        relay = adhoc.make_relay(raw)   # TTL=1 なら None
        if relay:
            lora_send(relay)
"""

import configparser
import os
import random
import struct
from collections import deque

# ── setting.ini から TTL をロード ─────────────────────────────
_CONFIG_PATH = os.path.join(os.path.dirname(__file__), 'config_code', 'setting.ini')


def _load_ttl() -> int:
    """setting.ini の ttl フィールドを読み込む。未設定・不正値は 3 を返す。1〜255 にクランプ。"""
    cfg = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    cfg.read(_CONFIG_PATH, encoding="utf-8")
    try:
        val = int(cfg.get('E220-900JP', 'ttl', fallback='3'))
        return max(1, min(val, 255))
    except ValueError:
        return 3


# ── パケット定義 ──────────────────────────────────────────────
HEADER_FORMAT = "!HHB"                          # big-endian: uint16, uint16, uint8
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)  # = 5 bytes
DEFAULT_TTL: int = _load_ttl()                  # setting.ini から読み込む
_SEEN_MAXLEN  = 64  # 重複検知キャッシュの最大保持件数

# ── モジュールレベル状態 ──────────────────────────────────────
_seen: deque[tuple[int, int]] = deque(maxlen=_SEEN_MAXLEN)
# 送信連番。起動ごとに乱数から始める。0 から始めると、再起動前の (src, msg_id) が
# 隣接ノードの seen キャッシュに残っている間、新しいパケットが重複として捨てられる。
_seq: int = random.getrandbits(16)


def encode(payload: bytes, src_addr: int, ttl: int = DEFAULT_TTL) -> bytes:
    """送信用アドホックパケットを組み立て、seen キャッシュに登録する。

    Args:
        payload : 送信するデータ本体
        src_addr: 自ノードアドレス（SELF_ADDRESS）
        ttl     : 初期 TTL（デフォルト 3）
    Returns:
        5 バイトヘッダ + payload のバイト列
    """
    global _seq
    _seq = (_seq + 1) & 0xFFFF
    _seen.append((src_addr, _seq))
    return struct.pack(HEADER_FORMAT, src_addr, _seq, ttl) + payload


def decode(raw: bytes) -> tuple[int, int, int, bytes] | None:
    """受信パケットをパースし、重複なら None を返す。

    Args:
        raw: lora_recv() が返したバイト列（E220 ヘッダ除去済み）
    Returns:
        (src_addr, msg_id, ttl, payload) または None（短すぎる / 重複）
    """
    if len(raw) < HEADER_SIZE:
        return None
    src_addr, msg_id, ttl = struct.unpack(HEADER_FORMAT, raw[:HEADER_SIZE])
    key = (src_addr, msg_id)
    if key in _seen:
        return None
    _seen.append(key)
    return src_addr, msg_id, ttl, raw[HEADER_SIZE:]


def make_relay(raw: bytes) -> bytes | None:
    """TTL を 1 減らした中継パケットを返す。TTL が 1 以下なら None（中継しない）。

    decode() を呼んだ後に使うこと（seen 登録は decode() で完了済み）。

    Args:
        raw: lora_recv() が返したバイト列（decode 前の元パケット）
    Returns:
        TTL-1 のアドホックパケット、または None
    """
    if len(raw) < HEADER_SIZE:
        return None
    src_addr, msg_id, ttl = struct.unpack(HEADER_FORMAT, raw[:HEADER_SIZE])
    if ttl <= 1:
        return None
    return struct.pack(HEADER_FORMAT, src_addr, msg_id, ttl - 1) + raw[HEADER_SIZE:]
