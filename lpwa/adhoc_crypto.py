# -*- coding: utf-8 -*-
from __future__ import annotations
"""
adhoc_crypto.py  ―  暗号化対応アドホック通信ヘルパー

node_a.py / node_b.py の 1 対 1 暗号方式を、TTL ベースのメッシュに拡張する。
adhoc.py はそのまま残し、本ファイルは独立した暗号メッシュ用モジュールとして動作する。

パケットフォーマット:

  ┌──────────┬──────────┬──────────┬──────┬──────┐
  │ src_addr │ dest_addr│ msg_id   │ ttl  │ type │
  │  2 bytes │  2 bytes │  2 bytes │ 1 B  │ 1 B  │
  └──────────┴──────────┴──────────┴──────┴──────┘
  合計 8 bytes (HEADER_SIZE)

  dest_addr = 0xFFFF : ブロードキャスト (ANNOUNCE 用)
  dest_addr = ノードアドレス : ユニキャスト (DATA 用)

パケット種別:

  TYPE_ANNOUNCE (0x01):
      header(8) + ed_pub(32) + dh_pub(32) = 72 bytes

  TYPE_DATA (0x02):
      header(8) + nonce(12) + signature(64) + ciphertext(N)
      ※ ciphertext = AES-GCM 暗号文 (平文 + 16 byte タグ)
      ※ 最小 100 bytes (平文 0 byte 時)

  TYPE_GROUP_DATA (0x03):
      header(8) + nonce(12) + signature(64) + key_id(1) + ciphertext(N)
      グループ鍵（事前共有 PSK）で暗号化したブロードキャスト。
      key_id はローテーション時の世代識別子。
      全ノードが同じグループ鍵を持てば全員が復号できる。

暗号方式 (node_a/b と同じ):
    鍵交換  : X25519 (ECDH)  → 共通鍵を導出 (電波に乗らない)
    暗号化  : AES-GCM 256bit → メッセージを暗号化
    署名    : Ed25519        → なりすまし・改ざん検知

中継ノードの動作:
    DATA パケットのヘッダ (src/dest/ttl) は読めるが、
    ペイロードは共通鍵なしでは復号不可。ログに暗号文プレビューを出力する。
"""

import os
import struct
from collections import deque

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── パケットヘッダ定義 ────────────────────────────────────────
# big-endian: uint16 × 3 + uint8 × 2
HEADER_FORMAT = "!HHHBB"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)   # 8 bytes

TYPE_ANNOUNCE   = 0x01
TYPE_DATA       = 0x02
TYPE_GROUP_DATA = 0x03
BROADCAST_ADDR  = 0xFFFF

# DATA ペイロード先頭部: nonce(12) + Ed25519 署名(64)
_DATA_PL_FORMAT = "!12s64s"
_DATA_PL_SIZE   = struct.calcsize(_DATA_PL_FORMAT)   # 76 bytes

# GROUP_DATA ペイロード先頭部: nonce(12) + Ed25519 署名(64) + key_id(1)
_GROUP_PL_FORMAT = "!12s64sB"
_GROUP_PL_SIZE   = struct.calcsize(_GROUP_PL_FORMAT)  # 77 bytes

# ── 重複検知キャッシュ ────────────────────────────────────────
_SEEN_MAXLEN = 128
_seen: deque[tuple[int, int]] = deque(maxlen=_SEEN_MAXLEN)
_seq: int = 0


def _next_seq() -> int:
    global _seq
    _seq = (_seq + 1) & 0xFFFF
    return _seq


# ─────────────────────────────────────────────────────────────
#  公開 API
# ─────────────────────────────────────────────────────────────

def derive_shared_key(dh_priv: X25519PrivateKey, peer_dh_pub_bytes: bytes) -> bytes:
    """X25519 ECDH で共通鍵(32 bytes)を導出する。共通鍵は電波に乗らない。"""
    peer_pub = X25519PublicKey.from_public_bytes(peer_dh_pub_bytes)
    return dh_priv.exchange(peer_pub)


# ── ANNOUNCE ─────────────────────────────────────────────────

def encode_announce(
    src_addr: int,
    ed_pub_bytes: bytes,
    dh_pub_bytes: bytes,
    ttl: int = 3,
) -> bytes:
    """
    公開鍵ブロードキャストパケットを生成する (72 bytes)。

    全ノードへ自分の Ed25519 公開鍵と X25519 公開鍵を通知する。
    受け取ったノードは peer_keys に保存し、以降のユニキャスト暗号化に使う。
    """
    seq = _next_seq()
    _seen.append((src_addr, seq))          # 自分が送ったので seen 登録
    header = struct.pack(
        HEADER_FORMAT, src_addr, BROADCAST_ADDR, seq, ttl, TYPE_ANNOUNCE
    )
    return header + ed_pub_bytes + dh_pub_bytes   # 8 + 32 + 32 = 72 bytes


def decode_announce(raw: bytes) -> dict | None:
    """
    ANNOUNCE パケットをパースして辞書を返す。

    Returns:
        {src_addr, dest_addr, msg_id, ttl, ed_pub(bytes), dh_pub(bytes)}
        パース失敗 / 種別不一致は None
    """
    if len(raw) < HEADER_SIZE + 64:
        return None
    src_addr, dest_addr, msg_id, ttl, ptype = struct.unpack(
        HEADER_FORMAT, raw[:HEADER_SIZE]
    )
    if ptype != TYPE_ANNOUNCE:
        return None
    payload = raw[HEADER_SIZE:]
    return {
        "src_addr":  src_addr,
        "dest_addr": dest_addr,
        "msg_id":    msg_id,
        "ttl":       ttl,
        "ed_pub":    payload[:32],
        "dh_pub":    payload[32:64],
    }


# ── DATA ─────────────────────────────────────────────────────

def encode_data(
    src_addr:  int,
    dest_addr: int,
    plaintext: bytes,
    shared_key: bytes,
    ed_priv,
    ttl: int = 3,
) -> bytes:
    """
    宛先指定の暗号化パケットを生成する。

    暗号化フロー:
        plaintext
          → AES-GCM 暗号化 (shared_key + random nonce)
          → Ed25519 署名 (暗号文に対して)
          → header + nonce + signature + ciphertext

    shared_key は encode 側が derive_shared_key() で事前に導出しておく。
    """
    seq        = _next_seq()
    _seen.append((src_addr, seq))
    nonce      = os.urandom(12)
    ciphertext = AESGCM(shared_key).encrypt(nonce, plaintext, None)
    signature  = ed_priv.sign(ciphertext)   # 暗号文に署名
    header = struct.pack(
        HEADER_FORMAT, src_addr, dest_addr, seq, ttl, TYPE_DATA
    )
    return header + nonce + signature + ciphertext


def decode_data(
    raw: bytes,
    shared_key: bytes,
    peer_ed_pub_bytes: bytes,
) -> bytes:
    """
    DATA パケットを署名検証してから復号し、平文を返す。

    宛先ノードだけが正しい shared_key を持つため、
    中継ノードはこの関数を呼んでも復号できない。

    Raises:
        cryptography.exceptions.InvalidSignature : 署名不正 / 改ざん検知
        cryptography.exceptions.InvalidTag       : 共通鍵不一致 / 破損
        ValueError                               : パケット短すぎ
    """
    min_size = HEADER_SIZE + _DATA_PL_SIZE + 16   # 16 = AES-GCM タグ最小
    if len(raw) < min_size:
        raise ValueError("packet too short: {} < {}".format(len(raw), min_size))
    payload    = raw[HEADER_SIZE:]
    nonce, sig = struct.unpack(_DATA_PL_FORMAT, payload[:_DATA_PL_SIZE])
    ciphertext = payload[_DATA_PL_SIZE:]

    # Ed25519 署名検証 (改ざん・なりすまし検知)
    peer_ed = ed25519.Ed25519PublicKey.from_public_bytes(peer_ed_pub_bytes)
    peer_ed.verify(sig, ciphertext)   # 失敗 → InvalidSignature

    # AES-GCM 復号
    return AESGCM(shared_key).decrypt(nonce, ciphertext, None)


# ── GROUP_DATA ────────────────────────────────────────────────

def encode_group_data(
    src_addr:  int,
    plaintext: bytes,
    group_key: bytes,
    key_id:    int,
    ed_priv,
    ttl: int = 3,
) -> bytes:
    """
    グループ鍵で暗号化したブロードキャストパケットを生成する。

    同じ group_key を持つ全ノードが復号できる。
    署名は送信者の Ed25519 秘密鍵で行うため、
    受信側は送信者の公開鍵（peer_keys）で検証する。

    payload = nonce(12) + signature(64) + key_id(1) + ciphertext(N)
    """
    seq        = _next_seq()
    _seen.append((src_addr, seq))
    nonce      = os.urandom(12)
    ciphertext = AESGCM(group_key).encrypt(nonce, plaintext, None)
    signature  = ed_priv.sign(ciphertext)
    header = struct.pack(
        HEADER_FORMAT, src_addr, BROADCAST_ADDR, seq, ttl, TYPE_GROUP_DATA
    )
    return header + nonce + signature + struct.pack("!B", key_id) + ciphertext


def decode_group_data(
    raw: bytes,
    group_key: bytes,
    peer_ed_pub_bytes: bytes,
    expected_key_id: int | None = None,
) -> tuple[bytes, int]:
    """
    GROUP_DATA パケットを署名検証・復号し、(平文, key_id) を返す。

    expected_key_id を指定すると key_id 不一致時に ValueError を送出する。
    None なら key_id チェックをスキップする（呼び出し側で判定可能）。

    Raises:
        cryptography.exceptions.InvalidSignature : 署名不正
        cryptography.exceptions.InvalidTag       : グループ鍵不一致
        ValueError : パケット短すぎ / key_id 不一致
    """
    min_size = HEADER_SIZE + _GROUP_PL_SIZE + 16
    if len(raw) < min_size:
        raise ValueError("packet too short: {} < {}".format(len(raw), min_size))

    payload = raw[HEADER_SIZE:]
    nonce, sig, key_id = struct.unpack(_GROUP_PL_FORMAT, payload[:_GROUP_PL_SIZE])
    ciphertext = payload[_GROUP_PL_SIZE:]

    if expected_key_id is not None and key_id != expected_key_id:
        raise ValueError(
            "key_id mismatch: got 0x{:02X}, expected 0x{:02X}".format(
                key_id, expected_key_id))

    peer_ed = ed25519.Ed25519PublicKey.from_public_bytes(peer_ed_pub_bytes)
    peer_ed.verify(sig, ciphertext)

    plaintext = AESGCM(group_key).decrypt(nonce, ciphertext, None)
    return plaintext, key_id


# ── ヘッダパース・重複検知・中継 ──────────────────────────────

def parse_header(raw: bytes) -> dict | None:
    """
    ヘッダ 8 bytes のみをパースする (中継ノードが宛先判定に使う)。

    Returns:
        {src_addr, dest_addr, msg_id, ttl, type} or None
    """
    if len(raw) < HEADER_SIZE:
        return None
    src_addr, dest_addr, msg_id, ttl, ptype = struct.unpack(
        HEADER_FORMAT, raw[:HEADER_SIZE]
    )
    return {
        "src_addr":  src_addr,
        "dest_addr": dest_addr,
        "msg_id":    msg_id,
        "ttl":       ttl,
        "type":      ptype,
    }


def is_seen(src_addr: int, msg_id: int) -> bool:
    """
    重複パケットかどうかを確認する。新規なら seen キャッシュに登録して False を返す。
    重複なら True を返す (呼び出し側はパケットを破棄する)。
    """
    key = (src_addr, msg_id)
    if key in _seen:
        return True
    _seen.append(key)
    return False


def make_relay(raw: bytes) -> bytes | None:
    """
    TTL を 1 減らした中継パケットを返す。

    TTL が既に 1 以下なら None (これ以上転送しない)。
    ペイロードは一切触らない (暗号文のまま転送)。
    """
    if len(raw) < HEADER_SIZE:
        return None
    src_addr, dest_addr, msg_id, ttl, ptype = struct.unpack(
        HEADER_FORMAT, raw[:HEADER_SIZE]
    )
    if ttl <= 1:
        return None
    new_header = struct.pack(
        HEADER_FORMAT, src_addr, dest_addr, msg_id, ttl - 1, ptype
    )
    return new_header + raw[HEADER_SIZE:]
