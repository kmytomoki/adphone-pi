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

LPWA:
    既定は v2（lpwa/mesh/ の管理型フラッディング。ROUTING_PLAN.md Phase 3）。
    設定は setting.ini（hop_limit / role / node_name / group_key_hex など。mesh/config.py 参照）。
    送信先 TARGET_ADDRESS が 0xFFFF ならグループ鍵でブロードキャスト、それ以外はその相手へ暗号化して送る。
    --legacy を付けると以下の v1（adhoc / adhoc_crypto）で動く。全ノードを同じ方式にそろえること。

LPWA 中継（v1 / --legacy）:
    - LoRa はモジュール層では常にブロードキャストで送り、宛先は上位ヘッダで判定する
    - 中継は 0〜relay_jitter_ms のランダム遅延を置いてから送る（同時再送による衝突を避ける）
    - 暗号モードでは BLE を起動してから ANNOUNCE を送り、以後も定期的に送り直す。
      鍵が届く前に BLE から来たメッセージは一定時間保留し、鍵が届いたら送る

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
import random
import subprocess
import sys
import threading
import time
from typing import Any

# ─── LPWA ヘルパーのインポート ─────────────────────────────────────────────────
# Pi 上の配置    : lora_e220_b.py は ~/work/ble/（このスクリプトと同じ）、adhoc.py 等は ~/work/lpwa/sample_code/
# リポジトリ構成 : すべて ../lpwa/
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
_relay_tasks: "set[asyncio.Task]" = set()  # 遅延中継の待機タスク

# ─── 暗号化モード用グローバル状態 ──────────────────────────────────────────────
_CRYPTO_MODE: bool = False                       # --crypto で True になる
_ALLOWED_PEERS: "set[int] | None" = None         # None = 全ノードと鍵交換
_ed_priv = None                                  # Ed25519PrivateKey (main() で設定)
_dh_priv = None                                  # X25519PrivateKey  (main() で設定)
_peer_keys: "dict[int, dict[str, bytes]]" = {}   # addr → {ed_pub, dh_pub}
_ann_pkt_body: "tuple[bytes, bytes] | None" = None  # (ed_pub, dh_pub) — ANNOUNCE 生成用
_reannounce_event: asyncio.Event | None = None    # 新しいピアを見つけたら set する
_last_announce_time: float = 0.0
_pending_crypto: "list[tuple[float, int, bytes]]" = []  # (受付時刻, 宛先, 平文) — 鍵待ち

# ─── v2（mesh/）用 ──────────────────────────────────────────────────────────────
_LEGACY: bool = False                            # --legacy で True（v1 で動かす）
_mesh_node = None                                # mesh.realtime.RealtimeNode
_mesh_stop = threading.Event()

_PENDING_MAX = 32               # 鍵待ちで保留するメッセージの上限
_PENDING_HOLD_SEC = 120         # 鍵待ちで保留する時間
_REANNOUNCE_MIN_GAP_SEC = 30    # 新ピア検出による再 ANNOUNCE の最短間隔


def _load_bridge_config() -> "tuple[int, int]":
    """setting.ini（lora_e220_b と同じファイル）から ttl と ANNOUNCE 間隔を読み込む。"""
    cfg = lora_e220_b.load_config_parser()
    sec = lora_e220_b.CONFIG_SECTION
    ttl          = int(cfg.get(sec, "ttl",                   fallback="3"))
    interval_sec = int(cfg.get(sec, "announce_interval_sec", fallback="300"))
    return ttl, max(30, interval_sec)


_DEFAULT_TTL, _ANNOUNCE_INTERVAL_SEC = _load_bridge_config()


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

    # ── v2: メッシュのスレッドに送信を頼む ──────────────────────────────────
    if _mesh_node is not None:
        dest = lora_e220_b.TARGET_ADDRESS
        _mesh_node.post(lambda: _mesh_send(dest, raw))
        return

    # ── LPWA 送信キューへ追加 ────────────────────────────────────────────────
    if _lpwa_send_queue is not None and _loop is not None:
        if _CRYPTO_MODE:
            item = ("crypto_send", (lora_e220_b.TARGET_ADDRESS, raw))
        else:
            item = ("send", raw)
        _loop.call_soon_threadsafe(_lpwa_send_queue.put_nowait, item)
        logger.info("[LPWA TX] キュー追加: %s", text)


def _schedule_relay(pkt: bytes) -> None:
    """中継パケットを 0〜relay_jitter_ms のランダム遅延の後に送信キューへ入れる。

    近くのノードが同じパケットを同時に再送して衝突するのを避けるため。
    """
    if _lpwa_send_queue is None:
        return
    delay = random.uniform(0, lora_e220_b.RELAY_JITTER_SEC)

    async def _delayed() -> None:
        await asyncio.sleep(delay)
        await _lpwa_send_queue.put(("relay", pkt))

    task = asyncio.get_running_loop().create_task(_delayed())
    _relay_tasks.add(task)               # 参照を保持しないと GC で消えることがある
    task.add_done_callback(_relay_tasks.discard)


def _hold_pending(target: int, data: bytes) -> None:
    """宛先の鍵が届くまでメッセージを保留する（古いものから捨てる）。"""
    now = time.monotonic()
    _pending_crypto[:] = [p for p in _pending_crypto if now - p[0] < _PENDING_HOLD_SEC]
    if len(_pending_crypto) >= _PENDING_MAX:
        dropped = _pending_crypto.pop(0)
        logger.warning("[CRYPTO TX] 保留数の上限。最も古い 0x%04X 宛てを破棄", dropped[1])
    _pending_crypto.append((now, target, data))


def _flush_pending(peer_addr: int) -> None:
    """peer_addr の鍵が届いたら、その宛先に保留していたメッセージを送信キューへ戻す。"""
    if _lpwa_send_queue is None:
        return
    now = time.monotonic()
    remaining = []
    for t, target, data in _pending_crypto:
        if now - t >= _PENDING_HOLD_SEC:
            logger.warning("[CRYPTO TX] 0x%04X 宛ての保留メッセージが期限切れ", target)
        elif target == peer_addr:
            _lpwa_send_queue.put_nowait(("crypto_send", (target, data)))
            logger.info("[CRYPTO TX] 0x%04X の鍵を受信。保留メッセージを送信", target)
        else:
            remaining.append((t, target, data))
    _pending_crypto[:] = remaining


def _build_announce() -> bytes:
    ed_pub_b, dh_pub_b = _ann_pkt_body
    return crypto.encode_announce(
        lora_e220_b.SELF_ADDRESS, ed_pub_b, dh_pub_b, ttl=_DEFAULT_TTL)


async def _announce_loop() -> None:
    """ANNOUNCE を起動直後・数秒後・以後 announce_interval_sec ごとに送る。

    新しいピアを見つけたとき（_reannounce_event）も、相手がこちらの鍵を
    知らない可能性があるので、少し待ってから送り直す。
    """
    global _last_announce_time
    # 同時に起動したノード同士が取りこぼさないよう、起動直後に 2 回送る
    schedule = [0.0, random.uniform(5, 15)]
    while True:
        if schedule:
            timeout = schedule.pop(0)
        else:
            timeout = _ANNOUNCE_INTERVAL_SEC * random.uniform(0.9, 1.1)
        try:
            await asyncio.wait_for(_reannounce_event.wait(), timeout=timeout)
            _reannounce_event.clear()
            # 新ピア起因: 直近に送っていれば間隔を空ける。多数のノードが一斉に返さないよう散らす
            since = time.monotonic() - _last_announce_time
            if since < _REANNOUNCE_MIN_GAP_SEC:
                await asyncio.sleep(_REANNOUNCE_MIN_GAP_SEC - since)
            await asyncio.sleep(random.uniform(0.5, 3.0))
        except asyncio.TimeoutError:
            pass
        _last_announce_time = time.monotonic()
        await _lpwa_send_queue.put(("announce", _build_announce()))
        logger.info("[ANNOUNCE] 公開鍵をブロードキャスト (既知ピア: %s)",
                    ["0x{:04X}".format(a) for a in sorted(_peer_keys)] or "なし")


# ─── LPWA 送信タスク ────────────────────────────────────────────────────────────
async def _lpwa_sender() -> None:
    """キューからデータを取り出して LPWA 送信（run_in_executor でブロッキングI/O分離）

    キュー要素は (kind, data) タプル:
      ("send",         raw)            : BLE 生データ → adhoc.encode() して送信（平文モード）
      ("crypto_send",  (target, raw))  : BLE 生データ → crypto.encode_data() して送信（暗号モード）
      ("relay",        pkt)            : 中継パケット → そのまま送信（ヘッダ付き済み）
      ("announce",     pkt)            : ANNOUNCE → そのまま送信
    """
    loop = asyncio.get_running_loop()
    while True:
        kind, data = await _lpwa_send_queue.get()

        if kind == "send":
            pkt = adhoc.encode(data, lora_e220_b.SELF_ADDRESS, ttl=adhoc.DEFAULT_TTL)
        elif kind == "crypto_send":
            target, plaintext = data
            if target == crypto.BROADCAST_ADDR:
                logger.error("[CRYPTO TX] 暗号モードの宛先がブロードキャスト(0xFFFF)です。"
                             "--target-address で相手ノードを指定してください。送信スキップ")
                continue
            peer = _peer_keys.get(target)
            if peer is None:
                _hold_pending(target, plaintext)
                logger.warning("[CRYPTO TX] 宛先 0x%04X の鍵が未登録。鍵が届くまで最大 %d 秒保留",
                               target, _PENDING_HOLD_SEC)
                continue
            try:
                shared_key = crypto.derive_shared_key(_dh_priv, peer["dh_pub"])
                pkt = crypto.encode_data(
                    lora_e220_b.SELF_ADDRESS, target, plaintext,
                    shared_key, _ed_priv, ttl=_DEFAULT_TTL)
                logger.info("[CRYPTO TX] → 0x%04X  %d bytes (暗号化済み)", target, len(pkt))
            except Exception as e:
                logger.error("[CRYPTO TX] 暗号化失敗: %s", e)
                continue
        else:
            pkt = data   # relay / announce: そのまま送信

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
            # 短めに区切って送信タスクにシリアルを譲る（受信途中のフレームは次回へ持ち越される）
            raw = await loop.run_in_executor(None, lora_recv, 0.5)

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
            if relay_pkt is not None:
                _schedule_relay(relay_pkt)
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
            if relay:
                _schedule_relay(relay)
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
                    if relay:
                        _schedule_relay(relay)
            else:
                # 他者宛ユニキャスト → 中継のみ
                _log_ciphertext_preview(raw, src, dest, mid)
                relay = crypto.make_relay(raw)
                if relay:
                    _schedule_relay(relay)
                    logger.info("[RELAY] src=0x%04X dst=0x%04X ttl %d → %d",
                                src, dest, ttl, ttl - 1)

        # GROUP_DATA パケット（ブリッジは復号しないが、メッシュを切らないよう中継する）
        elif ptype == crypto.TYPE_GROUP_DATA:
            if src != lora_e220_b.SELF_ADDRESS:
                relay = crypto.make_relay(raw)
                if relay:
                    _schedule_relay(relay)
                    logger.info("[RELAY-GBCAST] src=0x%04X ttl %d → %d", src, ttl, ttl - 1)

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
    new_keys = {"ed_pub": info["ed_pub"], "dh_pub": info["dh_pub"]}
    if _peer_keys.get(src) == new_keys:
        return  # 定期 ANNOUNCE — 既知の鍵
    _peer_keys[src] = new_keys
    logger.info("[PEER ] 0x%04X の公開鍵を登録", src)
    logger.info("        Ed25519 = %s...", info["ed_pub"].hex()[:32])
    logger.info("        X25519  = %s...", info["dh_pub"].hex()[:32])
    # 新しい（または再起動した）ピアはこちらの鍵を知らないかもしれないので ANNOUNCE を返す
    if _reannounce_event is not None:
        _reannounce_event.set()
    _flush_pending(src)


def _log_ciphertext_preview(raw: bytes, src: int, dest: int, mid: int) -> None:
    """デモ用: 復号できない場合に暗号文プレビューをログ出力する（C ノードの挙動）。"""
    ciphertext = raw[crypto.HEADER_SIZE:][76:]   # nonce(12) + sig(64) をスキップ
    preview    = ciphertext[:20].hex() + ("..." if len(ciphertext) > 20 else "")
    dest_str   = "BROADCAST" if dest == crypto.BROADCAST_ADDR else "0x{:04X}".format(dest)
    logger.info("[RECV ] src=0x%04X → %s msg_id=%d — 鍵なし / 復号不可", src, dest_str, mid)
    logger.info("        raw bytes: %s", preview)


# ─── v2（mesh/）────────────────────────────────────────────────────────────────
def _mesh_send(dest: int, raw: bytes) -> None:
    """メッシュのスレッドで呼ばれる。"""
    from mesh import packet as P
    try:
        key = _mesh_node.router.send(dest, raw)
        logger.info("[MESH TX] → %s msg_id=%08X %d bytes",
                    "全体" if dest == P.BROADCAST_ADDR else "0x{:04X}".format(dest),
                    key.msg_id, len(raw))
    except (ValueError, P.PacketError) as e:
        logger.error("[MESH TX] 送れません: %s", e)


def _mesh_on_deliver(d) -> None:
    """メッシュのスレッドで呼ばれる。BLE への通知はイベントループに渡す。"""
    text = d.payload.decode("utf-8", errors="replace")
    logger.info("[MESH RX] 0x%04X（%s ホップ）: %s", d.src, d.hops, text)
    if _loop is not None:
        _loop.call_soon_threadsafe(_notify_ble_rx, text)


def _mesh_on_event(event: str, info: dict) -> None:
    # delivered / send_failed は Phase 5 で BLE の配送状態（STATUS）として通知する
    if event == "delivered":
        logger.info("[MESH] 届いた → 0x%04X msg_id=%08X（%d ホップ, %d 回目）",
                    info["dest"], info["msg_id"], info["hops"], info["attempts"])
    elif event == "send_failed":
        logger.warning("[MESH] 届かず → 0x%04X msg_id=%08X", info["dest"], info["msg_id"])
    elif event == "key_conflict":
        logger.warning("[MESH] 0x%04X が登録済みと違う鍵で名乗っています（指紋 %s）。"
                       "ノードを入れ替えたなら python3 -m mesh.nodedb <nodedb.json> forget %d",
                       info["addr"], info["fingerprint"], info["addr"])
    elif event == "peer":
        logger.info("[MESH] ピア 0x%04X %s %s（指紋 %s）", info["addr"], info["role"],
                    info["name"], info["fingerprint"])
    else:
        logger.info("[MESH] %s %s", event, info)


def _start_mesh() -> threading.Thread:
    global _mesh_node
    from mesh.config import load_mesh_config, make_router_factory
    from mesh.realtime import E220Port, RealtimeNode

    mc = load_mesh_config(lora_e220_b.load_config_parser(), lora_e220_b.CONFIG_PATH)
    mc.address = lora_e220_b.SELF_ADDRESS          # --self-address を反映
    factory, identity, _ = make_router_factory(mc, on_event=_mesh_on_event)
    _mesh_node = RealtimeNode(E220Port(), factory, address=mc.address, on_deliver=_mesh_on_deliver)
    logger.info("[INIT] v2 メッシュ  self=0x%04X  役割=%s  経路=%s  hop_limit=%d  指紋=%s  グループ鍵=%s",
                mc.address, mc.role, mc.routing, mc.hop_limit, identity.fingerprint,
                "あり" if mc.group_key else "なし")
    if lora_e220_b.TARGET_ADDRESS == 0xFFFF and mc.group_key is None:
        logger.error("[INIT] 送信先がブロードキャストですが group_key_hex が未設定です。"
                     "BLE からのメッセージは送れません")
    thread = threading.Thread(
        target=_mesh_node.run_forever, args=(_mesh_stop,),
        kwargs={"on_error": lambda e: logger.exception("[MESH] ループでエラー: %s", e)},
        name="mesh", daemon=True)
    thread.start()
    return thread


# ─── メイン ────────────────────────────────────────────────────────────────────
async def main() -> None:
    global server, _lpwa_send_queue, _loop, _serial_lock, _ed_priv, _dh_priv
    global _ann_pkt_body, _reannounce_event

    _loop = asyncio.get_running_loop()
    _lpwa_send_queue = asyncio.Queue()
    _serial_lock = asyncio.Lock()

    ttl_display = _DEFAULT_TTL if _CRYPTO_MODE else adhoc.DEFAULT_TTL
    logger.info("LPWA アドレス: SELF=0x%04X  TARGET=0x%04X  CH=0x%02X%s",
                lora_e220_b.SELF_ADDRESS, lora_e220_b.TARGET_ADDRESS,
                lora_e220_b.TARGET_CHANNEL, "  TTL=%d (v1)" % ttl_display if _LEGACY else "")

    mesh_thread = None
    if not _LEGACY:
        mesh_thread = _start_mesh()
    elif _CRYPTO_MODE:
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
        if lora_e220_b.TARGET_ADDRESS == crypto.BROADCAST_ADDR:
            logger.error("[INIT] 暗号モードの送信先がブロードキャスト(0xFFFF)のため、"
                         "BLE からのメッセージは送信されません。--target-address を指定してください")
        _ann_pkt_body = (ed_pub_b, dh_pub_b)
        _reannounce_event = asyncio.Event()
        # ANNOUNCE は BLE 起動後に _announce_loop() が送る（鍵収集のために BLE を止めない）
    else:
        logger.info("[INIT] 平文モード (v1)  self=0x%04X", lora_e220_b.SELF_ADDRESS)

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

    tasks = [poll_task]
    if _LEGACY:
        tasks += [
            asyncio.create_task(_lpwa_sender()),
            asyncio.create_task(_lpwa_receiver()),
        ]
        if _CRYPTO_MODE:
            tasks.append(asyncio.create_task(_announce_loop()))
        logger.info("LPWA統合モード (v1) で起動 (送信・受信タスク開始)")
    else:
        logger.info("LPWA統合モード (v2 メッシュ) で起動")

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
        if mesh_thread is not None:
            _mesh_stop.set()
            await asyncio.get_running_loop().run_in_executor(None, mesh_thread.join, 2)
        await server.stop()
        logger.info("BLEサーバー停止")


if __name__ == "__main__":
    _parser = argparse.ArgumentParser(description="ADREN BLE-LPWA ブリッジサーバー")
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
        help="[v1] アドホック TTL（1〜255, デフォルト: setting.ini の値）",
    )
    _parser.add_argument(
        "--crypto",
        action="store_true",
        help="[v1] 公開鍵暗号化を有効にする（ANNOUNCE + X25519 + AES-GCM + Ed25519）",
    )
    _parser.add_argument(
        "--peer",
        type=lambda x: int(x, 0),
        action="append",
        metavar="ADDR",
        help="[v1] 鍵交換する相手アドレス（省略: 全ノード, 例: --peer 2 --peer 3）",
    )
    _parser.add_argument(
        "--legacy",
        action="store_true",
        help="v1（adhoc / adhoc_crypto）で動かす。--ttl / --crypto / --peer は v1 専用",
    )
    _args = _parser.parse_args()
    _LEGACY = _args.legacy
    if not _LEGACY and (_args.ttl is not None or _args.crypto or _args.peer):
        logger.warning("--ttl / --crypto / --peer は v1（--legacy）専用のため無視します。"
                       "v2 は setting.ini の hop_limit を使い、常に暗号化します")

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
