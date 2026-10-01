# -*- coding: utf-8 -*-
from __future__ import annotations
"""
lora_e220.py (node_b 用 / RaspberryPi 4B)

pi2_receiver.py と同じ受信ロジックを使用
シリアルポート: /dev/ttyS0  (RasPi4B)

配線:
    VCC  -> Pin 4  (5V)
    GND  -> Pin 6  (GND)
    TXD  -> Pin 10 (RXD / GPIO15)  ※クロス接続
    RXD  -> Pin 8  (TXD / GPIO14)  ※クロス接続
    M0   -> GND に直結 (Low固定)
    M1   -> GND に直結 (Low固定)
    AUX  -> 未接続でも動作可

E220 層のアドレッシング:
    Fixed Mode のヘッダには常に 0xFFFF（ブロードキャスト）を入れて送信する。
    特定アドレス宛てに送ると、途中のノードのモジュールがパケットを捨ててしまい
    メッシュ中継が成立しないため。宛先の判定は上位ヘッダ（adhoc_crypto の dest_addr）で行う。
    TARGET_ADDRESS は「上位ヘッダに入れる既定の宛先」としてのみ使う。

受信:
    外層フレーム（magic + version + len + CRC16）の len を使ってストリームから
    1 パケットずつ切り出す。連続して届いた複数パケットが 1 回の読み取りに
    入っていても分解でき、読み取りの途中で切れたフレームは次回に持ち越す。
"""

import configparser
import os
import struct
import time
from binascii import crc_hqx
from collections import deque

import serial

# ── setting.ini の場所 ─────────────────────────────────
# 環境変数 ADREN_LPWA_CONFIG > 下記の候補（上から順に存在するもの）
#   リポジトリ構成: Raspberry/lpwa/config_code/setting.ini
#   Pi 上の配置   : ~/work/lpwa/sample_code/config_code/setting.ini（~/work/ble/ から参照）
_CONFIG_ENV = "ADREN_LPWA_CONFIG"
_HERE = os.path.dirname(os.path.abspath(__file__))
_CONFIG_CANDIDATES = (
    os.path.join(_HERE, "config_code", "setting.ini"),
    os.path.join(_HERE, "..", "lpwa", "config_code", "setting.ini"),
    os.path.join(_HERE, "..", "lpwa", "sample_code", "config_code", "setting.ini"),
)
CONFIG_SECTION = "E220-900JP"


def _resolve_config_path() -> str:
    """setting.ini のパスを決める。見つからなければ起動を止める。

    既定値（own=1）で黙って動くと、全ノードが同じアドレスになり
    互いのパケットを重複として捨ててしまうため、フォールバックしない。
    """
    env = os.environ.get(_CONFIG_ENV)
    if env:
        if not os.path.isfile(env):
            raise SystemExit("[ERROR] {} が指す setting.ini がありません: {}".format(
                _CONFIG_ENV, env))
        return env
    for path in _CONFIG_CANDIDATES:
        if os.path.isfile(path):
            return os.path.normpath(path)
    raise SystemExit(
        "[ERROR] setting.ini が見つかりません。次のいずれかに配置するか、"
        "環境変数 {} でパスを指定してください:\n  {}".format(
            _CONFIG_ENV, "\n  ".join(os.path.normpath(p) for p in _CONFIG_CANDIDATES)))


def load_config_parser(path: str | None = None) -> configparser.ConfigParser:
    """setting.ini を読み込む。行末の「# コメント」は値から除く。"""
    cfg = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    cfg.read(path or CONFIG_PATH, encoding="utf-8")
    return cfg


CONFIG_PATH = _resolve_config_path()


def _load_config() -> tuple[int, int, int, float, int, int, float]:
    cfg = load_config_parser(CONFIG_PATH)
    section = CONFIG_SECTION

    if not cfg.has_option(section, "own_address"):
        raise SystemExit("[ERROR] {} に [{}] own_address がありません".format(
            CONFIG_PATH, section))
    own = int(cfg.get(section, "own_address"))
    target = int(cfg.get(section, "target_address", fallback="65535"))

    rssi_flag = int(cfg.get(section, "rssi_byte_flag", fallback="1"))
    packet_gap_sec = float(cfg.get(section, "packet_gap_sec", fallback="0.2"))
    frame_enabled = int(cfg.get(section, "transport_frame_enabled", fallback="1"))
    legacy_fallback = int(cfg.get(section, "transport_legacy_fallback", fallback="0"))
    relay_jitter_ms = int(cfg.get(section, "relay_jitter_ms", fallback="500"))

    return (target, own, rssi_flag, packet_gap_sec, frame_enabled, legacy_fallback,
            max(0, relay_jitter_ms) / 1000.0)


# ── E220-900JP 設定 ──────────────────────────────────
SERIAL_PORT    = "/dev/ttyS0"   # RasPi4B のシリアルポート
BAUD_RATE      = 9600
FIXED_MODE     = True
BROADCAST_ADDRESS = 0xFFFF
(TARGET_ADDRESS, SELF_ADDRESS, RSSI_BYTE_FLAG, _PACKET_GAP, TRANSPORT_FRAME_ENABLED,
 TRANSPORT_LEGACY_FALLBACK, RELAY_JITTER_SEC) = _load_config()
TARGET_CHANNEL = 0x00
RECV_TIMEOUT   = 10             # 受信タイムアウト(秒)
_PACKET_GAP    = max(0.02, _PACKET_GAP)  # 最終受信から何秒無音ならバッファを解析するか
_STALE_PARTIAL_SEC = 1.0        # 未完成フレームをこの秒数以上持ち越したら捨てる
# ─────────────────────────────────────────────────────

print("[LoRa Init] SELF=0x{:04X}  TARGET=0x{:04X}  CH=0x{:02X}  config={}".format(
    SELF_ADDRESS, TARGET_ADDRESS, TARGET_CHANNEL, CONFIG_PATH))

# ── 外層トランスポートフレーム ─────────────────────────────
# frame = magic(2) + version(1) + len(2) + payload + crc16(2)
_FRAME_MAGIC = b"AD"
_FRAME_VERSION = 1
_FRAME_HEADER_FMT = "!2sBH"
_FRAME_HEADER_SIZE = struct.calcsize(_FRAME_HEADER_FMT)
_FRAME_CRC_SIZE = 2
_FRAME_MIN_SIZE = _FRAME_HEADER_SIZE + _FRAME_CRC_SIZE
_FRAME_MAX_PAYLOAD = 512        # これより長い len は誤検出した magic とみなす


def _frame_crc(frame_wo_crc: bytes) -> int:
    return crc_hqx(frame_wo_crc, 0xFFFF)


def _wrap_frame(payload: bytes) -> bytes:
    header = struct.pack(_FRAME_HEADER_FMT, _FRAME_MAGIC, _FRAME_VERSION, len(payload))
    crc = _frame_crc(header + payload)
    return header + payload + struct.pack("!H", crc)


def _extract_frames(buf: bytearray, rssi_byte: bool) -> list[tuple[bytes, int | None]]:
    """buf の先頭から完成したフレームを切り出し、(payload, rssi) のリストを返す。

    切り出した分とノイズは buf から削除する。末尾の未完成フレームは buf に残す。
    E220 は RSSI 有効時、受信パケットごとに末尾へ 1 バイト付加する。
    """
    frames: list[tuple[bytes, int | None]] = []
    while buf:
        idx = buf.find(_FRAME_MAGIC)
        if idx < 0:
            # 末尾 1 バイトが magic の前半かもしれないので残す
            keep = 1 if buf[-1:] == _FRAME_MAGIC[:1] else 0
            if len(buf) > keep:
                print("[DROP-FRAME] noise {} bytes".format(len(buf) - keep))
            del buf[:len(buf) - keep]
            break
        if idx > 0:
            print("[DROP-FRAME] noise {} bytes before magic".format(idx))
            del buf[:idx]
        if len(buf) < _FRAME_HEADER_SIZE:
            break

        _, ver, payload_len = struct.unpack(_FRAME_HEADER_FMT, bytes(buf[:_FRAME_HEADER_SIZE]))
        if ver != _FRAME_VERSION or payload_len > _FRAME_MAX_PAYLOAD:
            del buf[:1]   # 偶然の "AD" — 1 バイト進めて探し直す
            continue

        frame_len = _FRAME_HEADER_SIZE + payload_len + _FRAME_CRC_SIZE
        total = frame_len + (1 if rssi_byte else 0)
        if len(buf) < total:
            break

        body = bytes(buf[:frame_len - _FRAME_CRC_SIZE])
        recv_crc = struct.unpack("!H", bytes(buf[frame_len - _FRAME_CRC_SIZE:frame_len]))[0]
        if recv_crc != _frame_crc(body):
            print("[DROP-FRAME] crc mismatch (len={})".format(payload_len))
            del buf[:1]
            continue

        rssi = buf[frame_len] - 256 if rssi_byte else None
        frames.append((body[_FRAME_HEADER_SIZE:], rssi))
        del buf[:total]
    return frames


# ── シリアルポートのシングルトン ──────────────────────
# ポートを開きっぱなしにすることで、ポーリング間にパケットを取りこぼさない
_serial_instance: serial.Serial | None = None

# 受信バッファ（呼び出しをまたいで保持する）
_rx_buf = bytearray()
_rx_last_byte_time = 0.0
_rx_ready: deque[tuple[bytes, int | None]] = deque()
LAST_RSSI: int | None = None    # 直近に返したパケットの RSSI (dBm)


def _get_serial() -> serial.Serial:
    global _serial_instance
    if _serial_instance is None or not _serial_instance.is_open:
        _serial_instance = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.1)
    return _serial_instance


def _build_header() -> bytes:
    """Fixed Mode 用 3 バイトヘッダを生成（常にブロードキャスト）"""
    addr_h = (BROADCAST_ADDRESS >> 8) & 0xFF
    addr_l = BROADCAST_ADDRESS & 0xFF
    ch     = int(TARGET_CHANNEL) & 0xFF
    return bytes([addr_h, addr_l, ch])


def lora_send(raw: bytes):
    """
    パケットを E220-900JP でブロードキャスト送信する

    Args:
        raw: 送信するバイナリ（上位ヘッダ付き）
    """
    tx_raw = _wrap_frame(raw) if TRANSPORT_FRAME_ENABLED else raw
    payload = _build_header() + tx_raw

    try:
        ser = _get_serial()
        while ser.out_waiting != 0:
            time.sleep(0.01)
        ser.write(payload)
        ser.flush()
        if TRANSPORT_FRAME_ENABLED:
            print("[LoRa Send] {} bytes (+ frame {}B + 3B header)".format(
                len(raw), len(tx_raw) - len(raw)))
        else:
            print("[LoRa Send] {} bytes (+ 3B header)".format(len(raw)))

    except serial.SerialException as e:
        print("[Error] Serial Device access failed: {}".format(e))


def _parse_rx_buffer(gap_elapsed: bool) -> None:
    """_rx_buf を解析し、完成したパケットを (payload, rssi) で _rx_ready に積む。"""
    if not _rx_buf:
        return

    if not TRANSPORT_FRAME_ENABLED:
        # フレームなし: 無音区間までを 1 パケットとみなす（従来どおり）
        if not gap_elapsed:
            return
        payload = bytes(_rx_buf)
        _rx_buf.clear()
        rssi = None
        if RSSI_BYTE_FLAG and len(payload) > 1:
            rssi = payload[-1] - 256
            payload = payload[:-1]
        _rx_ready.append((payload, rssi))
        return

    if gap_elapsed and TRANSPORT_LEGACY_FALLBACK and _FRAME_MAGIC not in _rx_buf:
        payload = bytes(_rx_buf)
        _rx_buf.clear()
        rssi = None
        if RSSI_BYTE_FLAG and len(payload) > 1:
            rssi = payload[-1] - 256
            payload = payload[:-1]
        print("[WARN] legacy fallback enabled, passing raw payload")
        _rx_ready.append((payload, rssi))
        return

    _rx_ready.extend(_extract_frames(_rx_buf, bool(RSSI_BYTE_FLAG)))


def lora_recv(timeout_sec: float = RECV_TIMEOUT):
    """
    E220-900JP からパケットを 1 つ受信する

    E220 の Fixed Mode では受信側のモジュールが 3 バイトヘッダを
    自動除去するため、シリアルにはペイロードのみが届く。
    1 回の読み取りに複数パケットが入っていた場合、2 つ目以降は次回の呼び出しで返す。

    Args:
        timeout_sec: 受信タイムアウト秒数
    Returns:
        受信したバイナリ / タイムアウト時は None
    """
    global _rx_last_byte_time
    if _rx_ready:
        return _pop_ready()

    try:
        ser = _get_serial()
        deadline = time.time() + timeout_sec

        while True:
            now = time.time()
            n = ser.in_waiting
            if n > 0:
                _rx_buf.extend(ser.read(n))
                _rx_last_byte_time = now
            elif _rx_buf and now - _rx_last_byte_time >= _PACKET_GAP:
                _parse_rx_buffer(gap_elapsed=True)
                if _rx_ready:
                    return _pop_ready()
                if _rx_buf and now - _rx_last_byte_time >= _STALE_PARTIAL_SEC:
                    print("[DROP-FRAME] stale partial frame {} bytes".format(len(_rx_buf)))
                    _rx_buf.clear()
            if now >= deadline:
                break
            time.sleep(0.01)

        # 期限切れ: 完成しているフレームだけ返し、未完成分は次回へ持ち越す
        _parse_rx_buffer(gap_elapsed=False)
        return _pop_ready() if _rx_ready else None

    except serial.SerialException as e:
        print("[Error] Serial Device access failed: {}".format(e))
        return None


def _pop_ready() -> bytes:
    global LAST_RSSI
    payload, LAST_RSSI = _rx_ready.popleft()
    if LAST_RSSI is not None:
        print("[LoRa Recv] RSSI: {} dBm".format(LAST_RSSI))
    print("[LoRa Recv] {} bytes: {}".format(len(payload), payload.hex()[:60]))
    return payload
