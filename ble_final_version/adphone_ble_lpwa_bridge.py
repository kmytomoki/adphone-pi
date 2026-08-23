#!/usr/bin/env python3
from __future__ import annotations
"""
adphone_ble_lpwa_bridge.py — Raspberry Pi 4 BLEサーバー

依存:
    pip install bless          # Raspberry Pi OS 64-bit + Python 3.11 で利用可能 (piwheels で 0.3.0 提供)

事前準備:
    通常は不要。接続が繰り返し失敗する場合のみ ble_reset.sh を実行すること。
    毎回実行するとボンディング不一致を引き起こす可能性がある。
        sudo ./ble_reset.sh

動作概要:
    - BLE Peripheral として "Adphone" という名前で広告
    - Android(Central) からの接続を複数同時受け付け
    - TX_CHAR_UUID への Write を受信 → 全接続クライアントへ RX_CHAR_UUID でエコーバック
    - 接続・切断のたびに META_CHAR_UUID へ接続台数(1バイト)を Notify

UUIDs (ble2.ts と完全一致):
    SERVICE_UUID   : ad000001-ad00-ad00-ad00-ad0000000001
    TX_CHAR_UUID   : ad000001-ad00-ad00-ad00-ad0000000002  (Write)
    RX_CHAR_UUID   : ad000001-ad00-ad00-ad00-ad0000000003  (Notify)
    META_CHAR_UUID : ad000001-ad00-ad00-ad00-ad0000000004  (Notify)
"""

import argparse
import asyncio
import logging
import os
import subprocess
import sys
from typing import Any

# ─── LPWA ヘルパーのインポート ─────────────────────────────────────────────────
# lora_e220_b.py : ~/work/ble/  (このスクリプトと同じディレクトリ)
# adhoc.py       : ~/work/lpwa/  または ~/work/lpwa/sample_code/
_LPWA_DIR = os.path.join(os.path.dirname(__file__), '..', 'lpwa')
sys.path.insert(0, os.path.dirname(__file__))          # lora_e220_b 用
sys.path.insert(0, _LPWA_DIR)                          # adhoc 用
sys.path.insert(0, os.path.join(_LPWA_DIR, 'sample_code'))  # 旧パス (後方互換)
try:
    import adhoc               # アドホック通信ヘルパー（平文モード用）
    import lora_e220_b         # モジュール参照（アドレスのオーバーライドに使用）
    from lora_e220_b import lora_send, lora_recv  # /dev/ttyS0, RasPi 4B
except ImportError as _lpwa_import_err:
    sys.exit(
        f"[ERROR] LPWA モジュールをインポートできません: {_lpwa_import_err}\n"
        "このスクリプトは lpwa/ と同じ Raspberry Pi 上で実行してください。"
    )

# 暗号化ライブラリ（--crypto 指定時のみ使用）
try:
    import adhoc_crypto as crypto
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

from bless import (  # type: ignore[import]
    BlessServer,
    GATTCharacteristicProperties as BlessGATTCharacteristicProperties,
    GATTAttributePermissions as BlessGATTCharacteristicPermissions,
)

# ─── ログ設定 ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ─── UUID 定義 ─────────────────────────────────────────────────────────────────
SERVICE_UUID   = "ad000001-ad00-ad00-ad00-ad0000000001"
TX_CHAR_UUID   = "ad000001-ad00-ad00-ad00-ad0000000002"
RX_CHAR_UUID   = "ad000001-ad00-ad00-ad00-ad0000000003"
META_CHAR_UUID = "ad000001-ad00-ad00-ad00-ad0000000004"

# ─── グローバル状態 ────────────────────────────────────────────────────────────
connected_devices: set[str] = set()
_notified_count: int = 0   # 最後に Notify した接続台数
server: BlessServer | None = None

# ─── LPWA 非同期連携用 ─────────────────────────────────────────────────────────
_lpwa_send_queue: asyncio.Queue | None = None
_loop: asyncio.AbstractEventLoop | None = None
_serial_lock: asyncio.Lock | None = None  # 送信・受信の同時シリアルアクセスを排他制御

# ─── 暗号化モード用グローバル状態 ──────────────────────────────────────────────
_CRYPTO_MODE: bool = False                       # --crypto で True になる
_ALLOWED_PEERS: "set[int] | None" = None         # None = 全ノードと鍵交換
_ed_priv = None                                  # Ed25519PrivateKey (main() で設定)
_dh_priv = None                                  # X25519PrivateKey  (main() で設定)
_peer_keys: "dict[int, dict[str, bytes]]" = {}   # addr → {ed_pub, dh_pub}


def _load_bridge_config() -> "tuple[int, int]":
    """setting.ini から ttl と announce_wait_sec を読み込む。"""
    import configparser as _cp
    cfg_path = os.path.join(
        os.path.dirname(__file__), '..', 'lpwa', 'config_code', 'setting.ini'
    )
    cfg = _cp.ConfigParser()
    cfg.read(cfg_path)
    sec = "E220-900JP"
    ttl          = int(cfg.get(sec, "ttl",               fallback="3"))
    announce_sec = int(cfg.get(sec, "announce_wait_sec", fallback="20"))
    return ttl, announce_sec


_DEFAULT_TTL, _ANNOUNCE_WAIT_SEC = _load_bridge_config()


# ─── BlueZ から BLE (LE) 接続数を非同期で取得 ────────────────────────────────
async def _get_le_connection_count() -> int:
    """hcitool con で LE 接続中のデバイス数を返す。
    Classic BT（キーボード・マウス・オーディオ等）は除外する。失敗時は 0。
    run_in_executor で実行することでイベントループのブロックを防ぐ。
    """
    loop = asyncio.get_running_loop()
    try:
        out = await loop.run_in_executor(
            None,
            lambda: subprocess.check_output(["hcitool", "con"], timeout=2).decode(),
        )
        # "> LE ..." 行のみカウント（Classic BT の "> ACL ..." 行を除外）
        return sum(
            1 for line in out.splitlines()
            if line.strip().startswith(">") and " LE " in line
        )
    except Exception:
        return 0


# ─── 接続台数ポーリング（2秒ごとに変化を検知して Notify） ─────────────────────
async def _poll_connections() -> None:
    last_count = -1
    while True:
        await asyncio.sleep(2)
        if server is None:
            continue
        count = await _get_le_connection_count()
        if count != last_count:
            last_count = count
            _notify_count(count)


# ─── 接続台数を全クライアントへ Notify ──────────────────────────────────────────
def _notify_count(count: int) -> None:
    """受け取った接続台数を META Characteristic で Notify し、_notified_count を更新する。"""
    global _notified_count
    if server is None:
        return
    _notified_count = count
    logger.info("[META] 接続台数通知: %d 台", count)
    char = server.get_characteristic(META_CHAR_UUID)
    if char is None:
        return
    char.value = bytearray([count & 0xFF])
    server.update_value(SERVICE_UUID, META_CHAR_UUID)


# ─── BlessServer の接続/切断コールバック ─────────────────────────────────────
def on_connect(client_address: str, _server: Any) -> None:
    connected_devices.add(client_address)
    count = len(connected_devices)
    logger.info("[CONNECT] %s (合計 %d 台)", client_address, count)
    _notify_count(count)


def on_disconnect(client_address: str, _server: Any) -> None:
    connected_devices.discard(client_address)
    count = len(connected_devices)
    logger.info("[DISCONNECT] %s (残 %d 台)", client_address, count)
    _notify_count(count)


# ─── Characteristic 読み取りリクエスト ────────────────────────────────────────
def read_request(characteristic: Any, **kwargs: Any) -> bytearray:
    uuid = str(characteristic.uuid).lower()

    if uuid == META_CHAR_UUID.lower():
        return bytearray([_notified_count & 0xFF])

    if uuid == RX_CHAR_UUID.lower():
        return characteristic.value or bytearray()

    return bytearray()


# ─── Characteristic 書き込みリクエスト（Android → ラズパイ） ─────────────────
def write_request(characteristic: Any, value: Any, **kwargs: Any) -> None:
    uuid = str(characteristic.uuid).lower()

    if uuid != TX_CHAR_UUID.lower():
        return

    # バイト列 → テキスト
    raw: bytes = bytes(value) if not isinstance(value, (bytes, bytearray)) else value
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")

    # 送信元アドレスの特定（bless が kwargs に渡す場合とそうでない場合がある）
    sender: str = kwargs.get("sender", "unknown")
    logger.info("[RECV] %s: %s", sender, text)

    # ── エコーバック: 全接続クライアントの RX_CHAR_UUID へ Notify ──────────────
    if server is None:
        return

    echo_char = server.get_characteristic(RX_CHAR_UUID)
    if echo_char is None:
        return

    echo_char.value = bytearray(text.encode("utf-8"))
    server.update_value(SERVICE_UUID, RX_CHAR_UUID)
    logger.info("[ECHO] → 全 %d 台へ送信: %s", _notified_count, text)

    # ── LPWA 送信キューへ追加 ────────────────────────────────────────────────
    if _lpwa_send_queue is not None and _loop is not None:
        kind = "crypto_send" if _CRYPTO_MODE else "send"
        _loop.call_soon_threadsafe(_lpwa_send_queue.put_nowait, (kind, raw))
        logger.info("[LPWA TX] キュー追加: %s", text)


# ─── LPWA 送信タスク ────────────────────────────────────────────────────────────
async def _lpwa_sender() -> None:
    """キューからデータを取り出して LPWA 送信（run_in_executor でブロッキングI/O分離）

    キュー要素は (kind, data) タプル:
      ("send",         raw) : BLE 生データ → adhoc.encode() して送信（平文モード）
      ("crypto_send",  raw) : BLE 生データ → crypto.encode_data() して送信（暗号モード）
      ("relay", adhoc_pkt)  : 中継パケット → そのまま送信（ヘッダ付き済み）
    """
    loop = asyncio.get_running_loop()
    while True:
        kind, data = await _lpwa_send_queue.get()

        if kind == "send":
            pkt = adhoc.encode(data, lora_e220_b.SELF_ADDRESS, ttl=adhoc.DEFAULT_TTL)
        elif kind == "crypto_send":
            target = lora_e220_b.TARGET_ADDRESS
            peer   = _peer_keys.get(target)
            if peer is None:
                logger.warning("[CRYPTO TX] 宛先 0x%04X の鍵が未登録。送信スキップ", target)
                continue
            try:
                shared_key = crypto.derive_shared_key(_dh_priv, peer["dh_pub"])
                pkt = crypto.encode_data(
                    lora_e220_b.SELF_ADDRESS, target, data,
                    shared_key, _ed_priv, ttl=_DEFAULT_TTL)
                logger.info("[CRYPTO TX] → 0x%04X  %d bytes (暗号化済み)", target, len(pkt))
            except Exception as e:
                logger.error("[CRYPTO TX] 暗号化失敗: %s", e)
                continue
        else:
            pkt = data   # relay: そのまま転送

        async with _serial_lock:
            try:
                await loop.run_in_executor(None, lora_send, pkt)
                logger.info("[ADHOC TX] kind=%s  %d bytes", kind, len(pkt))
            except Exception as e:
                logger.error("[LPWA TX] 送信失敗: %s", e)


# ─── LPWA 受信タスク ────────────────────────────────────────────────────────────
async def _lpwa_receiver() -> None:
    """LPWA 受信ループ — パケットを処理して BLE Notify + 中継"""
    loop = asyncio.get_running_loop()
    while True:
        async with _serial_lock:
            raw = await loop.run_in_executor(None, lora_recv, 2)

        if raw is None:
            await asyncio.sleep(0.05)
            continue

        # ── 平文モード ────────────────────────────────────────────────────────
        if not _CRYPTO_MODE:
            result = adhoc.decode(raw)
            if result is None:
                await asyncio.sleep(0.05)
                continue
            src_addr, msg_id, ttl, payload = result
            text = payload.decode("utf-8", errors="replace")
            logger.info("[ADHOC RX] src=0x%04X ttl=%d: %s", src_addr, ttl, text)
            _notify_ble_rx(text)
            relay_pkt = adhoc.make_relay(raw)
            if relay_pkt is not None and _lpwa_send_queue is not None:
                await _lpwa_send_queue.put(("relay", relay_pkt))
                logger.info("[ADHOC RELAY] src=0x%04X ttl %d → %d", src_addr, ttl, ttl - 1)
            await asyncio.sleep(0.05)
            continue

        # ── 暗号化モード ─────────────────────────────────────────────────────
        hdr = crypto.parse_header(raw)
        if hdr is None:
            await asyncio.sleep(0.05)
            continue

        src   = hdr["src_addr"]
        dest  = hdr["dest_addr"]
        mid   = hdr["msg_id"]
        ttl   = hdr["ttl"]
        ptype = hdr["type"]

        # 重複チェック
        if crypto.is_seen(src, mid):
            await asyncio.sleep(0.05)
            continue

        # ANNOUNCE パケット
        if ptype == crypto.TYPE_ANNOUNCE:
            _handle_announce_packet(raw)
            relay = crypto.make_relay(raw)
            if relay and _lpwa_send_queue is not None:
                await _lpwa_send_queue.put(("relay", relay))
                logger.info("[RELAY-ANN] src=0x%04X ttl %d → %d", src, ttl, ttl - 1)

        # DATA パケット
        elif ptype == crypto.TYPE_DATA:
            self_addr = lora_e220_b.SELF_ADDRESS
            is_for_me = (dest == self_addr or dest == crypto.BROADCAST_ADDR)

            if is_for_me:
                peer = _peer_keys.get(src)
                if peer is not None:
                    try:
                        shared_key = crypto.derive_shared_key(_dh_priv, peer["dh_pub"])
                        plaintext  = crypto.decode_data(raw, shared_key, peer["ed_pub"])
                        text = plaintext.decode("utf-8", errors="replace")
                        logger.info("=" * 60)
                        logger.info("[RECV ] src=0x%04X → 0x%04X msg_id=%d",
                                    src, self_addr, mid)
                        logger.info("        [OK] 署名検証 完了")
                        logger.info("        [OK] 復号成功: \"%s\"", text)
                        logger.info("=" * 60)
                        _notify_ble_rx(text)
                    except Exception as e:
                        logger.warning("[RECV ] 復号失敗 src=0x%04X: %s", src, e)
                        _log_ciphertext_preview(raw, src, dest, mid)
                else:
                    _log_ciphertext_preview(raw, src, dest, mid)

                # BROADCAST の場合は中継も行う
                if dest == crypto.BROADCAST_ADDR:
                    relay = crypto.make_relay(raw)
                    if relay and _lpwa_send_queue is not None:
                        await _lpwa_send_queue.put(("relay", relay))
            else:
                # 他者宛ユニキャスト → 中継のみ
                _log_ciphertext_preview(raw, src, dest, mid)
                relay = crypto.make_relay(raw)
                if relay and _lpwa_send_queue is not None:
                    await _lpwa_send_queue.put(("relay", relay))
                    logger.info("[RELAY] src=0x%04X dst=0x%04X ttl %d → %d",
                                src, dest, ttl, ttl - 1)

        await asyncio.sleep(0.05)


# ─── LPWA 受信データを BLE RX Characteristic で通知 ──────────────────────────
def _notify_ble_rx(text: str) -> None:
    """LPWA 受信データを RX Characteristic で全 BLE クライアントへ Notify"""
    if server is None:
        return
    rx_char = server.get_characteristic(RX_CHAR_UUID)
    if rx_char is None:
        return
    rx_char.value = bytearray(text.encode("utf-8"))
    server.update_value(SERVICE_UUID, RX_CHAR_UUID)
    logger.info("[LPWA RX→BLE] 全クライアントへ転送: %s", text)


# ─── 暗号化モード用ヘルパー ────────────────────────────────────────────────────

def _handle_announce_packet(raw: bytes) -> None:
    """ANNOUNCE パケットをパースして _peer_keys に保存する。
    _ALLOWED_PEERS が指定されている場合はフィルタリングする。"""
    info = crypto.decode_announce(raw)
    if info is None:
        return
    src = info["src_addr"]
    if src == lora_e220_b.SELF_ADDRESS:
        return  # 自分の ANNOUNCE エコーは無視
    if _ALLOWED_PEERS is not None and src not in _ALLOWED_PEERS:
        logger.info("[SKIP ] ANNOUNCE src=0x%04X → 鍵交換対象外（--peer 指定外）", src)
        return
    _peer_keys[src] = {"ed_pub": info["ed_pub"], "dh_pub": info["dh_pub"]}
    logger.info("[PEER ] 0x%04X の公開鍵を登録", src)
    logger.info("        Ed25519 = %s...", info["ed_pub"].hex()[:32])
    logger.info("        X25519  = %s...", info["dh_pub"].hex()[:32])


def _log_ciphertext_preview(raw: bytes, src: int, dest: int, mid: int) -> None:
    """デモ用: 復号できない場合に暗号文プレビューをログ出力する（C ノードの挙動）。"""
    ciphertext = raw[crypto.HEADER_SIZE:][76:]   # nonce(12) + sig(64) をスキップ
    preview    = ciphertext[:20].hex() + ("..." if len(ciphertext) > 20 else "")
    dest_str   = "BROADCAST" if dest == crypto.BROADCAST_ADDR else "0x{:04X}".format(dest)
    logger.info("[RECV ] src=0x%04X → %s msg_id=%d — 鍵なし / 復号不可", src, dest_str, mid)
    logger.info("        raw bytes: %s", preview)


async def _announce_phase() -> None:
    """Phase 2: ANNOUNCE ブロードキャスト送信 + _ANNOUNCE_WAIT_SEC 秒間受信待機。
    BLE タスク起動前に呼ぶため _serial_lock との競合なし。"""
    loop = asyncio.get_running_loop()

    ed_pub_b = _ed_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    dh_pub_b = _dh_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    ann_pkt = crypto.encode_announce(
        lora_e220_b.SELF_ADDRESS, ed_pub_b, dh_pub_b, ttl=_DEFAULT_TTL)
    await loop.run_in_executor(None, lora_send, ann_pkt)

    logger.info("=" * 60)
    logger.info("[ANNOUNCE] 公開鍵ブロードキャスト送信 (%d bytes)", len(ann_pkt))
    logger.info("[ANNOUNCE] Ed25519 pub: %s...", ed_pub_b.hex()[:32])
    logger.info("[ANNOUNCE] X25519  pub: %s...", dh_pub_b.hex()[:32])
    logger.info("[ANNOUNCE] %d 秒間 ピア公開鍵を受信待機...", _ANNOUNCE_WAIT_SEC)
    logger.info("[INIT] BLE 起動を %d 秒間延期 (ANNOUNCE 待機中)", _ANNOUNCE_WAIT_SEC)
    logger.info("=" * 60)

    deadline = loop.time() + _ANNOUNCE_WAIT_SEC
    while loop.time() < deadline:
        remaining = max(1, int(deadline - loop.time()))
        raw = await loop.run_in_executor(None, lora_recv, min(2, remaining))
        if raw is None:
            continue
        hdr = crypto.parse_header(raw)
        if hdr is None or crypto.is_seen(hdr["src_addr"], hdr["msg_id"]):
            continue
        if hdr["type"] == crypto.TYPE_ANNOUNCE:
            _handle_announce_packet(raw)
            relay = crypto.make_relay(raw)
            if relay:
                await loop.run_in_executor(None, lora_send, relay)

    known = list(_peer_keys.keys())
    logger.info("[READY] 鍵交換済みピア: %s",
                ["0x{:04X}".format(a) for a in known] if known else "なし")
    logger.info("=" * 60)


# ─── メイン ────────────────────────────────────────────────────────────────────
async def main() -> None:
    global server, _lpwa_send_queue, _loop, _serial_lock, _ed_priv, _dh_priv

    _loop = asyncio.get_running_loop()
    _lpwa_send_queue = asyncio.Queue()
    _serial_lock = asyncio.Lock()

    ttl_display = _DEFAULT_TTL if _CRYPTO_MODE else adhoc.DEFAULT_TTL
    logger.info("LPWA アドレス: SELF=0x%04X  TARGET=0x%04X  CH=0x%02X  TTL=%d",
                lora_e220_b.SELF_ADDRESS, lora_e220_b.TARGET_ADDRESS,
                lora_e220_b.TARGET_CHANNEL, ttl_display)

    if _CRYPTO_MODE:
        if not _CRYPTO_AVAILABLE:
            logger.error("[ERROR] --crypto が指定されましたが cryptography ライブラリが見つかりません。")
            logger.error("        pip install cryptography を実行してください。")
            return

        # ── Phase 1: 鍵ペア生成 ────────────────────────────────────────────
        _ed_priv = ed25519.Ed25519PrivateKey.generate()
        _dh_priv = X25519PrivateKey.generate()
        ed_pub_b = _ed_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        dh_pub_b = _dh_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        logger.info("=" * 60)
        logger.info("[INIT] 暗号化モード  self=0x%04X", lora_e220_b.SELF_ADDRESS)
        logger.info("       Ed25519 pub: %s...", ed_pub_b.hex()[:32])
        logger.info("       X25519  pub: %s...", dh_pub_b.hex()[:32])
        logger.info("       ※ 秘密鍵はこのノードの外に出ません")
        if _ALLOWED_PEERS is not None:
            logger.info("       鍵交換相手: %s",
                        ["0x{:04X}".format(a) for a in sorted(_ALLOWED_PEERS)])
        else:
            logger.info("       鍵交換相手: すべてのノード")
        logger.info("=" * 60)

        # ── Phase 2: ANNOUNCE ウィンドウ（BLE タスク起動前に完了させる）────
        await _announce_phase()
    else:
        logger.info("[INIT] 平文モード  self=0x%04X", lora_e220_b.SELF_ADDRESS)

    server = BlessServer(name="Adphone")
    server.read_request_func = read_request
    server.write_request_func = write_request

    # bless >= 0.2.7 では on_connect / on_disconnect をサポート
    if hasattr(server, "on_connect"):
        server.on_connect = on_connect      # type: ignore[assignment]
    if hasattr(server, "on_disconnect"):
        server.on_disconnect = on_disconnect  # type: ignore[assignment]

    # ── サービス追加 ────────────────────────────────────────────────────────────
    await server.add_new_service(SERVICE_UUID)

    # TX: Android → ラズパイ（Write / WriteWithoutResponse）
    await server.add_new_characteristic(
        SERVICE_UUID,
        TX_CHAR_UUID,
        BlessGATTCharacteristicProperties.write
        | BlessGATTCharacteristicProperties.write_without_response,
        None,
        BlessGATTCharacteristicPermissions.writeable,
    )

    # RX: ラズパイ → Android（Notify）
    await server.add_new_characteristic(
        SERVICE_UUID,
        RX_CHAR_UUID,
        BlessGATTCharacteristicProperties.notify
        | BlessGATTCharacteristicProperties.read,
        bytearray(b""),
        BlessGATTCharacteristicPermissions.readable,
    )

    # META: 接続台数通知（Notify + Read）
    await server.add_new_characteristic(
        SERVICE_UUID,
        META_CHAR_UUID,
        BlessGATTCharacteristicProperties.notify
        | BlessGATTCharacteristicProperties.read,
        bytearray([0]),
        BlessGATTCharacteristicPermissions.readable,
    )

    # ── 広告開始 ────────────────────────────────────────────────────────────────
    await server.start()
    await asyncio.sleep(1)
    logger.info("BLEサーバー起動: name=Adphone  service=%s", SERVICE_UUID)
    logger.info("Android からの接続待機中... (Ctrl+C で停止)")

    poll_task = asyncio.create_task(_poll_connections())

    tasks = [
        poll_task,
        asyncio.create_task(_lpwa_sender()),
        asyncio.create_task(_lpwa_receiver()),
    ]
    logger.info("LPWA統合モードで起動 (送信・受信タスク開始)")

    try:
        stop_event = asyncio.Event()
        await stop_event.wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        for t in tasks:
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass
        await server.stop()
        logger.info("BLEサーバー停止")


if __name__ == "__main__":
    _parser = argparse.ArgumentParser(description="Adphone BLE-LPWA ブリッジサーバー")
    _parser.add_argument(
        "--target-address",
        type=lambda x: int(x, 0),
        metavar="ADDR",
        help="LPWA 送信先アドレス（例: 0x0001, 1）。省略時は setting.ini の値を使用",
    )
    _parser.add_argument(
        "--self-address",
        type=lambda x: int(x, 0),
        metavar="ADDR",
        help="自ノードアドレス（例: 0x0002, 2）。省略時は setting.ini の値を使用",
    )
    _parser.add_argument(
        "--ttl",
        type=int,
        metavar="N",
        help="アドホック TTL（1〜255, デフォルト: setting.ini の値）",
    )
    _parser.add_argument(
        "--crypto",
        action="store_true",
        help="公開鍵暗号化を有効にする（ANNOUNCE + X25519 + AES-GCM + Ed25519）",
    )
    _parser.add_argument(
        "--peer",
        type=lambda x: int(x, 0),
        action="append",
        metavar="ADDR",
        help="鍵交換する相手アドレス（省略: 全ノード, 例: --peer 2 --peer 3）",
    )
    _args = _parser.parse_args()

    if _args.target_address is not None:
        lora_e220_b.TARGET_ADDRESS = _args.target_address
    if _args.self_address is not None:
        lora_e220_b.SELF_ADDRESS = _args.self_address
    if _args.ttl is not None:
        adhoc.DEFAULT_TTL = max(1, min(_args.ttl, 255))
        _DEFAULT_TTL = max(1, min(_args.ttl, 255))
    if _args.crypto:
        _CRYPTO_MODE = True
    if _args.peer:
        _ALLOWED_PEERS = set(_args.peer)

    if sys.platform.startswith("win"):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
