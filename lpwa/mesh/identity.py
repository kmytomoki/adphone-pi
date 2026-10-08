# -*- coding: utf-8 -*-
"""
mesh/identity.py  ―  ノードの鍵と暗号処理（ROUTING_PLAN.md 2.2・4 章）

鍵:
    Ed25519（署名）と X25519（鍵共有）の 2 組。ファイルに保存し、再起動しても変えない。
    鍵ファイル = Ed25519 秘密鍵 32B + X25519 秘密鍵 32B（パーミッション 600）

本文の形式:
    ANNOUNCE   : ed_pub(32) + dh_pub(32) + role(1) + name_len(1) + name(≤16) + sig(64)
                 sig = Ed25519(aad + 本文の sig 以外)。自分の ed 鍵で自己署名する
    DATA       : nonce(12) + AES-256-GCM(平文, AAD=aad)
                 鍵 = HKDF-SHA256(X25519(自分, 相手))。ペアの 2 者しか鍵を作れないので
                 送信者の認証も兼ねる（v1 の Ed25519 署名 64B は廃止）
    GROUP_DATA : key_id(1) + nonce(12) + AES-256-GCM(平文, AAD=aad) + sig(64)
                 グループ鍵だけでは送信者を区別できないので署名を残す
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROLES = ("CLIENT", "ROUTER", "CLIENT_MUTE")
_NAME_MAX = 16
_SIG = 64
_NONCE = 12
_TAG = 16
DATA_OVERHEAD = _NONCE + _TAG
GROUP_OVERHEAD = 1 + _NONCE + _TAG + _SIG

CryptoError = (InvalidSignature, InvalidTag, ValueError)


def _raw(key) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


@dataclass(frozen=True)
class AnnounceInfo:
    ed_pub: bytes
    dh_pub: bytes
    role: str
    name: str


class Identity:
    """自ノードの鍵ペア。"""

    def __init__(self, ed_priv: Ed25519PrivateKey, dh_priv: X25519PrivateKey):
        self._ed = ed_priv
        self._dh = dh_priv
        self.ed_pub = _raw(ed_priv.public_key())
        self.dh_pub = _raw(dh_priv.public_key())
        self._shared: dict[bytes, bytes] = {}

    # ── 生成・保存 ──────────────────────────────────────────
    @classmethod
    def generate(cls) -> "Identity":
        return cls(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "Identity":
        """64 バイトの種から作る（シミュレータで結果を再現するため）。"""
        return cls(Ed25519PrivateKey.from_private_bytes(seed[:32]),
                   X25519PrivateKey.from_private_bytes(seed[32:64]))

    @classmethod
    def load_or_create(cls, path: str) -> "Identity":
        if os.path.exists(path):
            with open(path, "rb") as f:
                data = f.read()
            if len(data) != 64:
                raise ValueError("鍵ファイルが壊れています: {}".format(path))
            return cls.from_seed(data)
        ident = cls.generate()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(ident._private_bytes())
        return ident

    def _private_bytes(self) -> bytes:
        enc, fmt = serialization.Encoding.Raw, serialization.PrivateFormat.Raw
        nop = serialization.NoEncryption()
        return self._ed.private_bytes(enc, fmt, nop) + self._dh.private_bytes(enc, fmt, nop)

    @property
    def fingerprint(self) -> str:
        """人が照合するための短い指紋（Ed25519 公開鍵の先頭 8 バイト）。"""
        return self.ed_pub[:8].hex()

    # ── ANNOUNCE ────────────────────────────────────────────
    def announce_body(self, aad: bytes, role: str, name: str) -> bytes:
        name_b = name.encode("utf-8")[:_NAME_MAX]
        unsigned = (self.ed_pub + self.dh_pub + bytes([ROLES.index(role), len(name_b)]) + name_b)
        return unsigned + self._ed.sign(aad + unsigned)

    @staticmethod
    def parse_announce(aad: bytes, body: bytes) -> AnnounceInfo:
        """署名を検証して中身を返す。不正なら CryptoError のいずれかを送出する。"""
        if len(body) < 66 + _SIG:
            raise ValueError("short announce")
        ed_pub, dh_pub = body[:32], body[32:64]
        role_i, name_len = body[64], body[65]
        if role_i >= len(ROLES) or name_len > _NAME_MAX or len(body) != 66 + name_len + _SIG:
            raise ValueError("bad announce")
        unsigned, sig = body[:-_SIG], body[-_SIG:]
        Ed25519PublicKey.from_public_bytes(ed_pub).verify(sig, aad + unsigned)
        name = body[66:66 + name_len].decode("utf-8", errors="replace")
        return AnnounceInfo(ed_pub, dh_pub, ROLES[role_i], name)

    # ── DATA（ペア鍵） ──────────────────────────────────────
    def _pair_key(self, peer_dh_pub: bytes) -> bytes:
        key = self._shared.get(peer_dh_pub)
        if key is None:
            secret = self._dh.exchange(X25519PublicKey.from_public_bytes(peer_dh_pub))
            # 両者で同じ値になるよう、公開鍵を順序づけて info に入れる
            info = b"ADREN v2 DATA" + b"".join(sorted([self.dh_pub, peer_dh_pub]))
            key = HKDF(hashes.SHA256(), 32, salt=None, info=info).derive(secret)
            self._shared[peer_dh_pub] = key
        return key

    def seal_data(self, aad: bytes, plaintext: bytes, peer_dh_pub: bytes) -> bytes:
        nonce = os.urandom(_NONCE)
        return nonce + AESGCM(self._pair_key(peer_dh_pub)).encrypt(nonce, plaintext, aad)

    def open_data(self, aad: bytes, body: bytes, peer_dh_pub: bytes) -> bytes:
        if len(body) < DATA_OVERHEAD:
            raise ValueError("short data")
        return AESGCM(self._pair_key(peer_dh_pub)).decrypt(body[:_NONCE], body[_NONCE:], aad)

    # ── GROUP_DATA（グループ鍵 + 署名） ─────────────────────
    def seal_group(self, aad: bytes, plaintext: bytes, group_key: bytes, key_id: int) -> bytes:
        nonce = os.urandom(_NONCE)
        head = bytes([key_id]) + nonce
        ct = AESGCM(group_key).encrypt(nonce, plaintext, aad + head[:1])
        unsigned = head + ct
        return unsigned + self._ed.sign(aad + unsigned)

    @staticmethod
    def group_key_id(body: bytes) -> int:
        if len(body) < GROUP_OVERHEAD:
            raise ValueError("short group data")
        return body[0]

    @staticmethod
    def open_group(aad: bytes, body: bytes, group_key: bytes, sender_ed_pub: bytes) -> bytes:
        if len(body) < GROUP_OVERHEAD:
            raise ValueError("short group data")
        unsigned, sig = body[:-_SIG], body[-_SIG:]
        Ed25519PublicKey.from_public_bytes(sender_ed_pub).verify(sig, aad + unsigned)
        key_id, nonce, ct = unsigned[:1], unsigned[1:1 + _NONCE], unsigned[1 + _NONCE:]
        return AESGCM(group_key).decrypt(nonce, ct, aad + key_id)


def load_group_key(hex_str: str, key_id: int) -> tuple[bytes, int] | None:
    hex_str = (hex_str or "").strip()
    if not hex_str:
        return None
    key = bytes.fromhex(hex_str)
    if len(key) != 32:
        raise ValueError("group_key_hex は 32 バイト (64 桁) 必要です")
    if not 0 <= key_id <= 255:
        raise ValueError("group_key_id は 0〜255")
    return key, key_id


__all__ = ["Identity", "AnnounceInfo", "ROLES", "DATA_OVERHEAD", "GROUP_OVERHEAD",
           "CryptoError", "load_group_key"]
