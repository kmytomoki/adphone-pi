# -*- coding: utf-8 -*-
from __future__ import annotations
"""
node_mesh.py  ―  アドホックメッシュ 公開鍵暗号ノード (RaspberryPi 4B)

起動方法:
    python3 node_mesh.py

動作フロー:
    Phase 1 (起動・鍵生成)
        自ノードの Ed25519 / X25519 鍵ペアを生成する。

    Phase 2 (ANNOUNCE ブロードキャスト & 鍵収集)
        自分の公開鍵を全ノードへブロードキャストし、
        他ノードの ANNOUNCE を announce_wait_sec 秒間受信して
        peer_keys に蓄積する。

    Phase 3 (メインループ)
        stdin 入力 → 宛先アドレスを指定して暗号化送信
        受信パケット:
            GROUP_DATA   → グループ鍵で署名検証 + 復号 → 平文表示 → 中継
            自分宛 DATA  → 署名検証 + AES-GCM 復号 → 平文表示
            他者宛 DATA  → 暗号文プレビューのみログ出力 → TTL-1 で中継
            ANNOUNCE     → peer_keys に追加 → TTL-1 で中継

前提:
    - 全ノード RaspberryPi 4B (/dev/ttyS0)
    - setting.ini の own_address を各ノードで個別に設定すること
    - cryptography ライブラリが pip install 済みであること

setting.ini 設定例:
    [E220-900JP]
    own_address       = 1     # このノードのアドレス (0〜65534, 65535=broadcast予約)
    ttl               = 3     # アドホック中継ホップ数
    announce_wait_sec = 10    # 起動後の鍵収集待機秒数
    group_key_hex     = <64桁hex>  # グループ鍵 (32 bytes, 全ノード共通)
    group_key_id      = 0          # 鍵ローテーション識別子 (0〜255)
"""

import argparse
import random
import select
import struct
import sys
import time
from collections import deque

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

from lora_e220_b import lora_send, lora_recv, CONFIG_PATH, RELAY_JITTER_SEC, load_config_parser
import adhoc_crypto as crypto

# ─────────────────────────────────────────────────────────────
#  設定読み込み
# ─────────────────────────────────────────────────────────────

_CONFIG_PATH = CONFIG_PATH   # lora_e220_b と同じ setting.ini を使う


def _load_config() -> tuple[int, int, int]:
    cfg = load_config_parser(_CONFIG_PATH)
    sec = "E220-900JP"
    own_addr  = int(cfg.get(sec, "own_address",       fallback="1"))
    ttl       = int(cfg.get(sec, "ttl",               fallback="3"))
    wait_sec  = int(cfg.get(sec, "announce_wait_sec", fallback="10"))
    return own_addr, ttl, wait_sec


def load_group_key(config_path: str = _CONFIG_PATH) -> tuple[bytes, int] | None:
    """setting.ini から group_key_hex / group_key_id を読み込む。

    未設定なら None を返す。形式不正時は ValueError を送出する。
    将来 bridge 側でも同じ関数を import して使えるよう独立させてある。
    """
    cfg = load_config_parser(config_path)
    sec = "E220-900JP"
    hex_str = cfg.get(sec, "group_key_hex", fallback="").strip()
    if not hex_str:
        return None
    try:
        key = bytes.fromhex(hex_str)
    except ValueError:
        raise ValueError(
            "group_key_hex が不正な16進数です: '{}'".format(hex_str))
    if len(key) != 32:
        raise ValueError(
            "group_key_hex は 32 バイト (64 桁) 必要です (現在 {} バイト)".format(len(key)))
    key_id = int(cfg.get(sec, "group_key_id", fallback="0"))
    if not (0 <= key_id <= 255):
        raise ValueError(
            "group_key_id は 0〜255 の範囲で指定してください (現在 {})".format(key_id))
    return key, key_id


SELF_ADDRESS, DEFAULT_TTL, ANNOUNCE_WAIT_SEC = _load_config()
_REANNOUNCE_INTERVAL = 30   # Phase 3 での自動再 ANNOUNCE 間隔 (秒)
_MAX_ACCEPT_TTL = min(255, DEFAULT_TTL + 2)
_ANNOUNCE_BACKOFF_MIN = 0.01
_ANNOUNCE_BACKOFF_MAX = 0.08
_GBCAST_QUEUE_DELAY_SEC = 0.05
_GROUP_RETRY_MAX = 1
_GROUP_RETRY_GAP_SEC = 0.08

# ─────────────────────────────────────────────────────────────
#  ピア公開鍵ストア
#  peer_keys[addr] = {"ed_pub": bytes(32), "dh_pub": bytes(32)}
# ─────────────────────────────────────────────────────────────

peer_keys: dict[int, dict[str, bytes]] = {}
drop_stats: dict[str, int] = {
    "dup": 0,
    "ttl_invalid": 0,
    "unknown_type": 0,
    "short_data": 0,
    "short_group": 0,
    "frame_like_noise": 0,
}
_announce_backoff_until: float = 0.0

# ─────────────────────────────────────────────────────────────
#  ユーティリティ
# ─────────────────────────────────────────────────────────────

def _addr(addr: int) -> str:
    return "0x{:04X}".format(addr)


def _hex_preview(data: bytes, n: int = 20) -> str:
    """先頭 n bytes を hex 表示し、それ以上あれば ... を付ける"""
    preview = data[:n].hex()
    return preview + ("..." if len(data) > n else "")


def _sep(char: str = "─", width: int = 60) -> str:
    return char * width


def _inc_drop(reason: str) -> None:
    drop_stats[reason] = drop_stats.get(reason, 0) + 1


def _set_announce_backoff() -> None:
    global _announce_backoff_until
    _announce_backoff_until = time.time() + random.uniform(
        _ANNOUNCE_BACKOFF_MIN, _ANNOUNCE_BACKOFF_MAX)


def _respect_announce_backoff() -> None:
    remain = _announce_backoff_until - time.time()
    if remain > 0:
        time.sleep(remain)


def _send_relay(relay: bytes) -> None:
    """中継パケットを 0〜relay_jitter_ms のランダム遅延を置いて送る。

    近くのノードが同時に再送して衝突するのを避けるため。
    待っている間に届いたパケットは lora_e220_b の受信バッファに溜まり、次の受信で読み出される。
    """
    time.sleep(random.uniform(0, RELAY_JITTER_SEC))
    _respect_announce_backoff()
    lora_send(relay)


def _print_drop_stats() -> None:
    total = sum(drop_stats.values())
    print("[STATS] drop summary: total={}".format(total))
    for key in sorted(drop_stats.keys()):
        print("        {:<14} {}".format(key, drop_stats[key]))


# TYPE_DATA: header(8) + nonce(12) + sig(64) + tag(16)
_MIN_DATA_PACKET_SIZE = crypto.HEADER_SIZE + 12 + 64 + 16
# TYPE_GROUP_DATA: header(8) + nonce(12) + sig(64) + key_id(1) + tag(16)
_MIN_GROUP_PACKET_SIZE = crypto.HEADER_SIZE + 12 + 64 + 1 + 16


# ─────────────────────────────────────────────────────────────
#  パケット処理
# ─────────────────────────────────────────────────────────────

def _handle_packet(raw: bytes, ed_priv, dh_priv,
                   allowed_peers: "set[int] | None" = None,
                   group_key: bytes | None = None,
                   group_key_id: int = 0) -> None:
    """
    受信パケットを種別・宛先で振り分ける。

    ┌─────────────────────────────────────────────────────────────┐
    │ GROUP_DATA (BCAST)   : グループ鍵で復号 → 平文表示 → 中継   │
    │ 自分宛 DATA         : 署名検証 → 復号 → 平文をログ表示     │
    │ BROADCAST DATA      : 復号を試みる（鍵なし時は暗号文表示）  │
    │ 他者宛 DATA         : 暗号文プレビューをログ表示 → 中継     │
    │ ANNOUNCE            : peer_keys に登録 → 中継              │
    │ ANNOUNCE(対象外)    : 中継のみ（保存しない）               │
    │ 重複 / 不正         : DROP                                  │
    └─────────────────────────────────────────────────────────────┘

    allowed_peers: None の場合はすべての ANNOUNCE を保存。
                   set 指定時はそのアドレスからの ANNOUNCE のみ保存する。
    group_key:     グループ鍵 (32 bytes)。None なら gbcast 復号をスキップ。
    group_key_id:  ローテーション識別子 (0〜255)。
    """
    # ── E220 ルーティングヘッダ自動除去 ──────────────────────────
    # 一部の E220 ファームウェアでは Fixed Mode 受信時にも送信元の
    # 3バイトルーティングヘッダ [ADDH][ADDL][CH] が UART 出力に含まれる。
    # 直接パースで ptype が不明かつ 3バイトオフセットで既知 ptype が得られる場合に除去する。
    if len(raw) >= crypto.HEADER_SIZE + 3:
        _KNOWN_TYPES = (crypto.TYPE_ANNOUNCE, crypto.TYPE_DATA, crypto.TYPE_GROUP_DATA)
        hdr_direct = crypto.parse_header(raw)
        hdr_shifted = crypto.parse_header(raw[3:])
        if (hdr_direct and hdr_direct["type"] not in _KNOWN_TYPES
                and hdr_shifted and hdr_shifted["type"] in _KNOWN_TYPES):
            print("[INFO ] E220 ルーティングヘッダを検出・除去 (3バイト)")
            raw = raw[3:]

    hdr = crypto.parse_header(raw)
    if hdr is None:
        return

    src   = hdr["src_addr"]
    dest  = hdr["dest_addr"]
    mid   = hdr["msg_id"]
    ttl   = hdr["ttl"]
    ptype = hdr["type"]
    _known_types = (crypto.TYPE_ANNOUNCE, crypto.TYPE_DATA, crypto.TYPE_GROUP_DATA)

    if ptype not in _known_types:
        _inc_drop("unknown_type")
        if len(raw) >= 8 and raw[:2] not in (b"\x00\x00", b"\xff\xff"):
            _inc_drop("frame_like_noise")
        print("[DROP-U] src={} msg_id={} type=0x{:02X} ttl={}".format(
            _addr(src), mid, ptype, ttl))
        return

    if ttl == 0 or ttl > _MAX_ACCEPT_TTL:
        _inc_drop("ttl_invalid")
        print("[DROP-TTL] src={} msg_id={} type=0x{:02X} ttl={} (allowed: 1..{})".format(
            _addr(src), mid, ptype, ttl, _MAX_ACCEPT_TTL))
        return

    # ── 重複チェック ──────────────────────────────────────────
    if crypto.is_seen(src, mid):
        _inc_drop("dup")
        print("[DROP ] src={} msg_id={} — 重複パケット".format(_addr(src), mid))
        return

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # ANNOUNCE 処理
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if ptype == crypto.TYPE_ANNOUNCE:
        _set_announce_backoff()
        if src == SELF_ADDRESS:
            # 自分の ANNOUNCE がエコーバックされた → 無視
            return

        info = crypto.decode_announce(raw)
        if info is None:
            print("[WARN ] ANNOUNCE パースエラー (src={})".format(_addr(src)))
            return

        # --peer フィルタ: 対象外アドレスは保存せず、中継のみ行う
        if allowed_peers is not None and src not in allowed_peers:
            print("[SKIP ] ANNOUNCE src={} → 鍵交換対象外（--peer 指定外）".format(_addr(src)))
        else:
            peer_keys[src] = {"ed_pub": info["ed_pub"], "dh_pub": info["dh_pub"]}
            print("[PEER ] src={} 公開鍵を登録".format(_addr(src)))
            print("        Ed25519 = {}".format(info["ed_pub"].hex()[:32] + "..."))
            print("        X25519  = {}".format(info["dh_pub"].hex()[:32] + "..."))

        # ブロードキャストを全ノードへ中継
        relay = crypto.make_relay(raw)
        if relay:
            _send_relay(relay)
            print("[RELAY-ANN] src={} ttl: {} → {}".format(
                _addr(src), ttl, ttl - 1
            ))
        else:
            print("[DROP-ANN ] src={} TTL=0 (中継なし)".format(_addr(src)))
        return

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # GROUP_DATA 処理 (グループ鍵ブロードキャスト)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if ptype == crypto.TYPE_GROUP_DATA:
        if len(raw) < _MIN_GROUP_PACKET_SIZE:
            _inc_drop("short_group")
            print("[DROP-G] src={} msg_id={} — short GROUP_DATA ({} < {})".format(
                _addr(src), mid, len(raw), _MIN_GROUP_PACKET_SIZE))
            return

        if src == SELF_ADDRESS:
            return

        peer = peer_keys.get(src)
        print(_sep())
        print("[RECV-G] src={} → BROADCAST msg_id={} ttl={}".format(
            _addr(src), mid, ttl))

        if group_key is None:
            ciphertext = raw[crypto.HEADER_SIZE + 77:]  # nonce(12)+sig(64)+key_id(1)
            print("        [SKIP] グループ鍵が未設定 — 復号不可")
            print("        raw bytes: {}".format(_hex_preview(ciphertext)))
        elif peer is None:
            ciphertext = raw[crypto.HEADER_SIZE + 77:]
            print("        [SKIP] src={} の Ed25519 公開鍵が未登録 — 署名検証不可".format(
                _addr(src)))
            print("        raw bytes: {}".format(_hex_preview(ciphertext)))
        else:
            try:
                plaintext, recv_kid = crypto.decode_group_data(
                    raw, group_key, peer["ed_pub"], expected_key_id=group_key_id)
                print("        [OK] 署名検証 完了 (Ed25519)")
                print("        [OK] グループ復号成功 (key_id=0x{:02X}): \"{}\"".format(
                    recv_kid, plaintext.decode()))
            except ValueError as e:
                if "key_id mismatch" in str(e):
                    print("        [WARN] {}".format(e))
                else:
                    print("        [FAIL] パースエラー: {}".format(e))
            except Exception as e:
                ciphertext = raw[crypto.HEADER_SIZE + 77:]
                print("        [FAIL] 復号失敗: {}".format(e))
                print("        raw bytes: {}".format(_hex_preview(ciphertext)))
        print(_sep())

        relay = crypto.make_relay(raw)
        if relay:
            _send_relay(relay)
            print("[RELAY-GBCAST] src={} ttl: {} → {}".format(
                _addr(src), ttl, ttl - 1))
        return

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # DATA 処理
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if ptype == crypto.TYPE_DATA:
        if len(raw) < _MIN_DATA_PACKET_SIZE:
            _inc_drop("short_data")
            print("[DROP-D] src={} msg_id={} — short DATA ({} < {})".format(
                _addr(src), mid, len(raw), _MIN_DATA_PACKET_SIZE))
            return


        # ── 自分宛 or ブロードキャスト: 復号を試みる ─────────
        if dest == SELF_ADDRESS or dest == crypto.BROADCAST_ADDR:
            dest_str = "me({})".format(_addr(SELF_ADDRESS)) \
                if dest == SELF_ADDRESS else "BROADCAST"
            print(_sep())
            print("[RECV ] src={} → {} msg_id={} ttl={}".format(
                _addr(src), dest_str, mid, ttl
            ))

            peer = peer_keys.get(src)
            if peer is None:
                # 鍵なし → デモでの「C ノード」挙動（暗号文をそのまま表示）
                ciphertext = raw[crypto.HEADER_SIZE:][76:]
                print("        [鍵なし] src={} の公開鍵が未登録".format(_addr(src)))
                print("        raw bytes: {}".format(_hex_preview(ciphertext)))
            else:
                try:
                    shared_key = crypto.derive_shared_key(dh_priv, peer["dh_pub"])
                    plaintext  = crypto.decode_data(raw, shared_key, peer["ed_pub"])
                    print("        [OK] 署名検証 完了")
                    print("        [OK] 復号成功: \"{}\"".format(plaintext.decode()))
                except Exception as e:
                    ciphertext = raw[crypto.HEADER_SIZE:][76:]
                    print("        [FAIL] 復号失敗: {}".format(e))
                    print("        raw bytes: {}".format(_hex_preview(ciphertext)))
            print(_sep())

            # BROADCAST の場合は TTL > 1 なら中継も行う
            if dest == crypto.BROADCAST_ADDR:
                relay = crypto.make_relay(raw)
                if relay:
                    _send_relay(relay)
                    print("[RELAY-BCAST] src={} ttl: {} → {}".format(
                        _addr(src), ttl, ttl - 1))

        # ── 他者宛ユニキャスト: 暗号文プレビュー表示 → 中継 ──
        else:
            # ペイロード = nonce(12) + sig(64) + ciphertext(N)
            payload_raw  = raw[crypto.HEADER_SIZE:]
            ciphertext   = payload_raw[76:]   # nonce + sig をスキップ

            print(_sep())
            print("[RELAY] src={} dst={} msg_id={} ttl={}".format(
                _addr(src), _addr(dest), mid, ttl
            ))
            print("        ペイロード全体 = {} bytes".format(len(payload_raw)))
            print("        暗号文プレビュー = {} (cannot decrypt — not addressed to me)".format(
                _hex_preview(ciphertext)
            ))

            relay = crypto.make_relay(raw)
            if relay:
                _send_relay(relay)
                print("        → 転送完了 (ttl: {} → {})".format(ttl, ttl - 1))
            else:
                print("        → TTL=0, 廃棄")
            print(_sep())
        return


# ─────────────────────────────────────────────────────────────
#  送信ヘルパー
# ─────────────────────────────────────────────────────────────

def _send_broadcast(peer_addr: int, text: str, dh_priv, ed_priv) -> None:
    """peer_addr の共通鍵で暗号化してブロードキャスト送信（デモ用）。

    dest_addr = BROADCAST_ADDR のため全ノードが物理的に受信するが、
    peer_addr と鍵交換済みのノードのみが復号できる。
    """
    peer = peer_keys.get(peer_addr)
    if peer is None:
        print("[!] peer={} の公開鍵が未登録です。"
              "ANNOUNCE を受信してから送信してください。".format(_addr(peer_addr)))
        return
    plaintext  = text.encode()
    shared_key = crypto.derive_shared_key(dh_priv, peer["dh_pub"])
    pkt = crypto.encode_data(
        SELF_ADDRESS, crypto.BROADCAST_ADDR, plaintext, shared_key, ed_priv,
        ttl=DEFAULT_TTL,
    )
    _respect_announce_backoff()
    lora_send(pkt)
    print("[BCAST] key_for={} dest=BROADCAST | \"{}\" | {} bytes (暗号化済み)".format(
        _addr(peer_addr), text, len(pkt)
    ))
    print("        ※ {} と鍵交換済みのノードのみ復号可能".format(_addr(peer_addr)))


def _send_group_broadcast(text: str, group_key: bytes, key_id: int, ed_priv) -> None:
    """グループ鍵で暗号化してブロードキャスト送信。全ノードが復号可能。"""
    plaintext = text.encode()
    pkt = crypto.encode_group_data(
        SELF_ADDRESS, plaintext, group_key, key_id, ed_priv, ttl=DEFAULT_TTL,
    )
    _respect_announce_backoff()
    lora_send(pkt)
    print("[GBCAST] dest=BROADCAST key_id=0x{:02X} | \"{}\" | {} bytes (グループ暗号化)".format(
        key_id, text, len(pkt)))
    if _GROUP_RETRY_MAX >= 1:
        time.sleep(_GROUP_RETRY_GAP_SEC)
        _respect_announce_backoff()
        lora_send(pkt)
        print("         └─ retry sent once (same msg_id)")


def _send_message(dest_addr: int, text: str, dh_priv, ed_priv) -> None:
    peer = peer_keys.get(dest_addr)
    if peer is None:
        print("[!] addr={} の公開鍵が未登録です。"
              "相手ノードの ANNOUNCE を受信してから送信してください。".format(
                  _addr(dest_addr)
              ))
        return

    plaintext  = text.encode()
    shared_key = crypto.derive_shared_key(dh_priv, peer["dh_pub"])
    pkt = crypto.encode_data(
        SELF_ADDRESS, dest_addr, plaintext, shared_key, ed_priv, ttl=DEFAULT_TTL
    )
    _respect_announce_backoff()
    lora_send(pkt)
    print("[SEND ] dst={} | \"{}\" | {} bytes (暗号化済み)".format(
        _addr(dest_addr), text, len(pkt)
    ))


# ─────────────────────────────────────────────────────────────
#  メイン
# ─────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Adphone Mesh Node — 公開鍵暗号メッシュノード")
    parser.add_argument("--peer", type=int, action="append", metavar="ADDR",
                        help="鍵交換する相手アドレス（省略: 受信した全 ANNOUNCE から交換）")
    parser.add_argument("--crypto", action="store_true",
                        help="暗号化モード（このノードは常に暗号化を使用するため後方互換オプション）")
    args = parser.parse_args()
    allowed_peers: "set[int] | None" = set(args.peer) if args.peer else None

    # ── グループ鍵ロード ────────────────────────────────────
    gk_result = load_group_key()
    if gk_result is not None:
        group_key, group_key_id = gk_result
    else:
        group_key, group_key_id = None, 0

    print(_sep("="))
    print("  Adphone Mesh Node")
    print("  addr={}  TTL={}  (RasPi4B / /dev/ttyS0)".format(
        _addr(SELF_ADDRESS), DEFAULT_TTL
    ))
    if allowed_peers is not None:
        print("  鍵交換相手: {}".format([_addr(a) for a in sorted(allowed_peers)]))
    else:
        print("  鍵交換相手: すべてのノード")
    if group_key is not None:
        print("  グループ鍵: 有効 (key_id=0x{:02X}, {}...{})".format(
            group_key_id, group_key.hex()[:8], group_key.hex()[-8:]))
    else:
        print("  グループ鍵: 未設定 (gbcast 使用不可)")
    print(_sep("="))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Phase 1: 鍵ペア生成
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ed_priv  = ed25519.Ed25519PrivateKey.generate()
    ed_pub_b = ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    dh_priv  = X25519PrivateKey.generate()
    dh_pub_b = dh_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    print("\n[INIT] 鍵ペア生成完了")
    print("       Ed25519 pub : {} ...".format(ed_pub_b.hex()[:32]))
    print("       X25519  pub : {} ...".format(dh_pub_b.hex()[:32]))
    print("       ※ 秘密鍵はこのノードの外に出ません")

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Phase 2: ANNOUNCE ブロードキャスト & 鍵収集
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    ann_pkt = crypto.encode_announce(
        SELF_ADDRESS, ed_pub_b, dh_pub_b, ttl=DEFAULT_TTL
    )
    lora_send(ann_pkt)
    print("\n[ANNOUNCE] 公開鍵をブロードキャスト送信 ({} bytes)".format(len(ann_pkt)))
    print("[ANNOUNCE] {}秒間 他ノードの公開鍵を受信待機中...\n".format(
        ANNOUNCE_WAIT_SEC
    ))

    announce_deadline = time.time() + ANNOUNCE_WAIT_SEC
    while time.time() < announce_deadline:
        remaining = max(1, int(announce_deadline - time.time()))
        raw = lora_recv(timeout_sec=min(2, remaining))
        if raw:
            _handle_packet(raw, ed_priv, dh_priv, allowed_peers=allowed_peers,
                           group_key=group_key, group_key_id=group_key_id)

    known = list(peer_keys.keys())
    print("\n[READY] 登録済みピア: {}".format(
        [_addr(a) for a in known] if known else "なし (自ノードのみ)"
    ))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Phase 3: メインループ (送受信)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print(_sep())
    print("送信コマンド:")
    print("  <宛先アドレス(10進)> <メッセージ>        — ユニキャスト暗号化送信")
    print("  gbcast <メッセージ>                      — グループ鍵 BROADCAST (全員復号可)")
    print("  bcast <peer_addr(10進)> <メッセージ>     — ペア鍵 BROADCAST (デモ/傍受検証用)")
    print("  reannounce                               — 公開鍵を再送（鍵交換が失敗した場合）")
    print("  peers                                    — 登録済みピア一覧を表示")
    print("  stats                                    — DROP統計を表示")
    print("  groupkey                                 — グループ鍵の状態を表示")
    print("  例: 2 こんにちは")
    print("  例: gbcast 全ノード向けメッセージ")
    print("  例: bcast 2 Hello from Node-A")
    print("終了: Ctrl+C")
    print(_sep())

    _last_announce_time = time.time()
    gbcast_queue: deque[tuple[float, str]] = deque()

    try:
        while True:
            # ── gbcast キュー処理（短時間遅延送信）────────────────
            now = time.time()
            while gbcast_queue and gbcast_queue[0][0] <= now:
                _, queued_msg = gbcast_queue.popleft()
                if group_key is None:
                    print("[!] グループ鍵が未設定です。gbcast を送信できません。")
                else:
                    _send_group_broadcast(queued_msg, group_key, group_key_id, ed_priv)

            # ── 定期再 ANNOUNCE (30秒ごと) ───────────────────
            if time.time() - _last_announce_time >= _REANNOUNCE_INTERVAL:
                ann_pkt = crypto.encode_announce(
                    SELF_ADDRESS, ed_pub_b, dh_pub_b, ttl=DEFAULT_TTL
                )
                _respect_announce_backoff()
                lora_send(ann_pkt)
                print("[RE-ANN] 公開鍵を自動再送 ({} bytes)".format(len(ann_pkt)))
                _last_announce_time = time.time()

            # ── stdin を非ブロッキングでチェック ─────────────
            r, _, _ = select.select([sys.stdin], [], [], 0)
            if r:
                line = sys.stdin.readline().strip()
                if line:
                    tokens = line.split(" ", 2)
                    if tokens[0] == "peers":
                        if peer_keys:
                            print("[PEERS] 登録済みピア ({} 件):".format(len(peer_keys)))
                            for addr, keys in sorted(peer_keys.items()):
                                print("        {} Ed25519={} X25519={}".format(
                                    _addr(addr),
                                    keys["ed_pub"].hex()[:16] + "...",
                                    keys["dh_pub"].hex()[:16] + "...",
                                ))
                        else:
                            print("[PEERS] 登録済みピア: なし")
                    elif tokens[0] == "reannounce":
                        ann_pkt = crypto.encode_announce(
                            SELF_ADDRESS, ed_pub_b, dh_pub_b, ttl=DEFAULT_TTL
                        )
                        _respect_announce_backoff()
                        lora_send(ann_pkt)
                        print("[ANNOUNCE] 公開鍵を手動再送 ({} bytes)".format(len(ann_pkt)))
                        _last_announce_time = time.time()
                    elif tokens[0] == "gbcast":
                        msg = line.split(" ", 1)
                        if len(msg) < 2 or not msg[1].strip():
                            print("[!] 形式: gbcast <メッセージ>")
                        elif group_key is None:
                            print("[!] グループ鍵が未設定です。"
                                  "setting.ini に group_key_hex を設定してください。")
                        else:
                            due = time.time() + _GBCAST_QUEUE_DELAY_SEC
                            gbcast_queue.append((due, msg[1]))
                            print("[GBCAST-QUEUE] queued (send in {:.0f}ms)".format(
                                _GBCAST_QUEUE_DELAY_SEC * 1000))
                    elif tokens[0] == "stats":
                        _print_drop_stats()
                    elif tokens[0] == "groupkey":
                        if group_key is not None:
                            print("[GROUP] グループ鍵: 有効")
                            print("        key_id = 0x{:02X}".format(group_key_id))
                            print("        key    = {}...{}".format(
                                group_key.hex()[:8], group_key.hex()[-8:]))
                        else:
                            print("[GROUP] グループ鍵: 未設定")
                    elif tokens[0] == "bcast":
                        # bcast <peer_addr> <message>
                        if len(tokens) < 3:
                            print("[!] 形式: bcast <peer_addr(10進)> <メッセージ>")
                        else:
                            try:
                                _send_broadcast(int(tokens[1]), tokens[2], dh_priv, ed_priv)
                            except ValueError:
                                print("[!] アドレスは整数で入力してください")
                    else:
                        # <dest_addr> <message>
                        parts = line.split(" ", 1)
                        if len(parts) < 2:
                            print("[!] 形式: <宛先アドレス(10進)> <メッセージ>  または  bcast <peer> <msg>")
                        else:
                            try:
                                dest_addr = int(parts[0])
                                if dest_addr == SELF_ADDRESS:
                                    print("[!] 宛先が自ノードです")
                                elif dest_addr == crypto.BROADCAST_ADDR:
                                    print("[!] 0xFFFF はブロードキャスト予約です。bcast コマンドを使用してください")
                                else:
                                    _send_message(dest_addr, parts[1], dh_priv, ed_priv)
                            except ValueError:
                                print("[!] アドレスは整数で入力してください")

            # ── 受信チェック (1秒タイムアウト) ──────────────
            raw = lora_recv(timeout_sec=1)
            if raw:
                _handle_packet(raw, ed_priv, dh_priv, allowed_peers=allowed_peers,
                               group_key=group_key, group_key_id=group_key_id)

    except KeyboardInterrupt:
        print("\n[EXIT] 停止しました")


if __name__ == "__main__":
    main()
