# -*- coding: utf-8 -*-
"""
node_b.py  -  RaspberryPi 4B (受信側) で実行
使い方:
    python3 node_b.py

暗号化方式:
    鍵交換  : X25519 (ECDH)    -> 共通鍵を安全に導出
    暗号化  : AES-GCM 256bit   -> メッセージを暗号化
    署名    : Ed25519          -> なりすまし対策
通信:
    E220-900JP (LoRa 920MHz)
    シリアルポート: /dev/ttyS0 (RasPi4B)
    IPアドレス不要 / ブロードキャスト受信
"""

import os
import struct

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

# RasPi4B 用 LoRa 通信モジュール (/dev/ttyS0)
from lora_e220_b import lora_send, lora_recv

# ── ノード設定 ────────────────────────────────────────
NODE_ID = b"B"
# ─────────────────────────────────────────────────────

HANDSHAKE_FORMAT   = "!1s32s32s"
HANDSHAKE_SIZE     = struct.calcsize(HANDSHAKE_FORMAT)
DATA_HEADER_FORMAT = "!1s12s64s"
DATA_HEADER_SIZE   = struct.calcsize(DATA_HEADER_FORMAT)


def main():

    # ── 1. 鍵ペア生成 ────────────────────────────────
    ed_priv  = ed25519.Ed25519PrivateKey.generate()
    ed_pub_b = ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    dh_priv  = X25519PrivateKey.generate()
    dh_pub_b = dh_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    print("[*] Node-B started.  (RasPi4B / /dev/ttyS0)")
    print("    Ed25519 pub : {}...".format(ed_pub_b.hex()[:16]))
    print("    X25519  pub : {}...".format(dh_pub_b.hex()[:16]))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Phase 1: ハンドシェイク
    #   B は A のハンドシェイクを待ってから自分の公開鍵を返す
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    print("[*] Waiting for Node-A's handshake...")
    raw_hs = lora_recv()
    if raw_hs is None:
        print("[!] Timeout: handshake failed.")
        return

    if len(raw_hs) < HANDSHAKE_SIZE:
        print("[!] Handshake packet too short: {} bytes".format(len(raw_hs)))
        return

    _, peer_ed_pub_b, peer_dh_pub_b = struct.unpack(
        HANDSHAKE_FORMAT, raw_hs[:HANDSHAKE_SIZE]
    )
    print("[*] Handshake received from Node-A.")

    # A の公開鍵を受け取ったので自分の公開鍵を返す
    hs_reply = struct.pack(HANDSHAKE_FORMAT, NODE_ID, ed_pub_b, dh_pub_b)
    lora_send(hs_reply)
    print("[*] Handshake replied.")

    # X25519 ECDH: 共通鍵を導出
    shared_key = dh_priv.exchange(
        X25519PublicKey.from_public_bytes(peer_dh_pub_b)
    )
    print("[*] Shared key derived: {}...  (never transmitted)".format(
        shared_key.hex()[:16]
    ))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Phase 2: 暗号化メッセージの受信 -> 返信
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    # 受信
    print("[*] Waiting for Node-A's encrypted message...")
    raw_data = lora_recv()
    if raw_data is None:
        print("[!] Timeout: no message from Node-A.")
        return

    if len(raw_data) < DATA_HEADER_SIZE:
        print("[!] Data packet too short: {} bytes".format(len(raw_data)))
        return

    sender, recv_nonce, recv_sig = struct.unpack(
        DATA_HEADER_FORMAT, raw_data[:DATA_HEADER_SIZE]
    )
    recv_encrypted = raw_data[DATA_HEADER_SIZE:]

    aesgcm = AESGCM(shared_key)

    try:
        # 署名検証: 改ざん検知 & なりすまし対策
        peer_ed = ed25519.Ed25519PublicKey.from_public_bytes(peer_ed_pub_b)
        peer_ed.verify(recv_sig, recv_encrypted)
        print("[OK] Signature verified.")

        # 復号
        plaintext = aesgcm.decrypt(recv_nonce, recv_encrypted, None)
        print("[OK] Decrypted message from {}: {}".format(
            sender.decode(), plaintext.decode()
        ))

    except Exception as e:
        print("[FAIL] {}".format(e))
        return

    # 返信送信
    message   = b"Hello from Node-B (encrypted)"
    nonce     = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, message, None)
    signature = ed_priv.sign(encrypted)

    data_pkt = struct.pack(DATA_HEADER_FORMAT, NODE_ID, nonce, signature) + encrypted
    lora_send(data_pkt)
    print("[*] Encrypted reply sent to Node-A.")


if __name__ == "__main__":
    main()
