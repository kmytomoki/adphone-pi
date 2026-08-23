# -*- coding: utf-8 -*-
"""
node_a.py  -  RaspberryPi 5 (送信側) で実行
使い方:
    python3 node_a.py

暗号化方式:
    鍵交換  : X25519 (ECDH)    -> 共通鍵を安全に導出
    暗号化  : AES-GCM 256bit   -> メッセージを暗号化
    署名    : Ed25519          -> なりすまし対策
通信:
    E220-900JP (LoRa 920MHz)
    シリアルポート: /dev/ttyAMA0 (RasPi5)
    IPアドレス不要 / ブロードキャスト送信
"""

import os
import struct
import time

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

# RasPi5 用 LoRa 通信モジュール (/dev/ttyAMA0)
from lora_e220_a import lora_send, lora_recv

# ── ノード設定 ────────────────────────────────────────
NODE_ID = b"A"
# ─────────────────────────────────────────────────────

# ハンドシェイクパケット: node_id(1) + ed_pub(32) + dh_pub(32) = 65 bytes
HANDSHAKE_FORMAT = "!1s32s32s"
HANDSHAKE_SIZE   = struct.calcsize(HANDSHAKE_FORMAT)

# データパケットヘッダ: node_id(1) + nonce(12) + sig(64) = 77 bytes
DATA_HEADER_FORMAT = "!1s12s64s"
DATA_HEADER_SIZE   = struct.calcsize(DATA_HEADER_FORMAT)


def main():

    # ── 1. 鍵ペア生成 ────────────────────────────────
    # Ed25519: 署名・なりすまし対策用
    ed_priv  = ed25519.Ed25519PrivateKey.generate()
    ed_pub_b = ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    # X25519: 鍵交換・暗号化用
    dh_priv  = X25519PrivateKey.generate()
    dh_pub_b = dh_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    print("[*] Node-A started.  (RasPi5 / /dev/ttyAMA0)")
    print("    Ed25519 pub : {}...".format(ed_pub_b.hex()[:16]))
    print("    X25519  pub : {}...".format(dh_pub_b.hex()[:16]))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Phase 1: ハンドシェイク (DH 公開鍵を交換)
    #
    #   A ──[node_id, ed_pub_A, dh_pub_A]──────────> B
    #   A <──────────[node_id, ed_pub_B, dh_pub_B]── B
    #
    #   両者が同じ shared_key を独立して導出する (X25519 の性質)
    #   shared_key は電波に一切乗らない
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    hs_pkt = struct.pack(HANDSHAKE_FORMAT, NODE_ID, ed_pub_b, dh_pub_b)
    time.sleep(0.5)   # Node-B の受信準備を待つ
    lora_send(hs_pkt)
    print("[*] Handshake sent. Waiting for Node-B...")

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

    # X25519 ECDH: 自分の秘密鍵 × 相手の公開鍵 -> 32 バイトの共通鍵
    shared_key = dh_priv.exchange(
        X25519PublicKey.from_public_bytes(peer_dh_pub_b)
    )
    print("[*] Shared key derived: {}...  (never transmitted)".format(
        shared_key.hex()[:16]
    ))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Phase 2: 暗号化メッセージの送受信
    #
    #  送信フロー:
    #    平文
    #     └─ AES-GCM 暗号化 (shared_key + nonce)
    #         └─ 暗号文に Ed25519 署名
    #             └─ LoRa 送信
    #
    #  受信フロー:
    #    LoRa 受信
    #     └─ Ed25519 署名検証  <- なりすまし・改ざん検知
    #         └─ AES-GCM 復号
    #             └─ 平文
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    # 送信
    message   = b"Hello from Node-A (encrypted)"
    aesgcm    = AESGCM(shared_key)
    nonce     = os.urandom(12)           # 毎回異なるランダム値
    encrypted = aesgcm.encrypt(nonce, message, None)
    signature = ed_priv.sign(encrypted)  # 平文ではなく暗号文に署名

    data_pkt = struct.pack(DATA_HEADER_FORMAT, NODE_ID, nonce, signature) + encrypted
    lora_send(data_pkt)
    print("[*] Encrypted message sent.")

    # 受信
    print("[*] Waiting for Node-B's encrypted message...")
    raw_data = lora_recv()
    if raw_data is None:
        print("[!] Timeout: no response from Node-B.")
        return

    if len(raw_data) < DATA_HEADER_SIZE:
        print("[!] Data packet too short: {} bytes".format(len(raw_data)))
        return

    sender, recv_nonce, recv_sig = struct.unpack(
        DATA_HEADER_FORMAT, raw_data[:DATA_HEADER_SIZE]
    )
    recv_encrypted = raw_data[DATA_HEADER_SIZE:]

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


if __name__ == "__main__":
    main()
