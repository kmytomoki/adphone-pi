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
"""

import configparser
import struct
import os
import serial
import time
from binascii import crc_hqx

# ── setting.ini からアドレスをロード ──────────────────
# lora_e220_b.py は ~/work/ble/ にあり、setting.ini は ~/work/lpwa/sample_code/config_code/ にある
_CONFIG_PATH = os.path.join(
    os.path.dirname(__file__), '..', 'lpwa', 'sample_code', 'config_code', 'setting.ini'
)


def _load_config(
    target_address_override: int | None = None,
    self_address_override: int | None = None,
) -> tuple[int, int, int, float, int, int]:
    """setting.ini から TARGET_ADDRESS と SELF_ADDRESS を読み込む。
    引数が指定された場合はそちらを優先する。"""
    cfg = configparser.ConfigParser()
    cfg.read(_CONFIG_PATH)
    section = "E220-900JP"

    target = target_address_override
    if target is None and cfg.has_option(section, "target_address"):
        target = int(cfg.get(section, "target_address"))
    if target is None:
        target = 0xFFFF  # デフォルト: ブロードキャスト

    own = self_address_override
    if own is None and cfg.has_option(section, "own_address"):
        own = int(cfg.get(section, "own_address"))
    if own is None:
        own = 0x0001  # デフォルト: ノード1

    rssi_flag = int(cfg.get(section, "rssi_byte_flag", fallback="1"))
    packet_gap_sec = float(cfg.get(section, "packet_gap_sec", fallback="0.2"))
    frame_enabled = int(cfg.get(section, "transport_frame_enabled", fallback="1"))
    legacy_fallback = int(cfg.get(section, "transport_legacy_fallback", fallback="0"))

    return target, own, rssi_flag, packet_gap_sec, frame_enabled, legacy_fallback


# ── E220-900JP 設定 ──────────────────────────────────
SERIAL_PORT    = "/dev/ttyS0"   # RasPi4B のシリアルポート
BAUD_RATE      = 9600
FIXED_MODE     = True
TARGET_ADDRESS, SELF_ADDRESS, RSSI_BYTE_FLAG, _PACKET_GAP, TRANSPORT_FRAME_ENABLED, TRANSPORT_LEGACY_FALLBACK = _load_config()  # setting.ini から読み込む
TARGET_CHANNEL = 0x00
RECV_TIMEOUT   = 10             # 受信タイムアウト(秒)
_PACKET_GAP    = max(0.02, _PACKET_GAP)  # パケット終端判定: 最終受信から何秒待つか
# ─────────────────────────────────────────────────────

print("[LoRa Init] SELF=0x{:04X}  TARGET=0x{:04X}  CH=0x{:02X}".format(
    SELF_ADDRESS, TARGET_ADDRESS, TARGET_CHANNEL))

# ── 外層トランスポートフレーム ─────────────────────────────
# frame = magic(2) + version(1) + len(2) + payload + crc16(2)
_FRAME_MAGIC = b"AD"
_FRAME_VERSION = 1
_FRAME_HEADER_FMT = "!2sBH"
_FRAME_HEADER_SIZE = struct.calcsize(_FRAME_HEADER_FMT)
_FRAME_CRC_SIZE = 2
_FRAME_MIN_SIZE = _FRAME_HEADER_SIZE + _FRAME_CRC_SIZE


def _frame_crc(frame_wo_crc: bytes) -> int:
    return crc_hqx(frame_wo_crc, 0xFFFF)


def _wrap_frame(payload: bytes) -> bytes:
    header = struct.pack(_FRAME_HEADER_FMT, _FRAME_MAGIC, _FRAME_VERSION, len(payload))
    crc = _frame_crc(header + payload)
    return header + payload + struct.pack("!H", crc)


def _unwrap_frame(frame: bytes) -> bytes | None:
    if len(frame) < _FRAME_MIN_SIZE:
        print("[DROP-FRAME] too short: {} < {}".format(len(frame), _FRAME_MIN_SIZE))
        return None

    magic, ver, payload_len = struct.unpack(_FRAME_HEADER_FMT, frame[:_FRAME_HEADER_SIZE])
    if magic != _FRAME_MAGIC:
        print("[DROP-FRAME] bad magic: {}".format(frame[:2].hex()))
        return None
    if ver != _FRAME_VERSION:
        print("[DROP-FRAME] bad version: {}".format(ver))
        return None

    expected_len = _FRAME_HEADER_SIZE + payload_len + _FRAME_CRC_SIZE
    if len(frame) != expected_len:
        print("[DROP-FRAME] length mismatch: got={}, expected={}".format(
            len(frame), expected_len))
        return None

    body = frame[:-_FRAME_CRC_SIZE]
    recv_crc = struct.unpack("!H", frame[-_FRAME_CRC_SIZE:])[0]
    calc_crc = _frame_crc(body)
    if recv_crc != calc_crc:
        print("[DROP-FRAME] crc mismatch: got=0x{:04X}, expected=0x{:04X}".format(
            recv_crc, calc_crc))
        return None

    return frame[_FRAME_HEADER_SIZE:-_FRAME_CRC_SIZE]

# ── シリアルポートのシングルトン ──────────────────────
# ポートを開きっぱなしにすることで、ポーリング間にパケットを取りこぼさない
_serial_instance: serial.Serial | None = None


def _get_serial() -> serial.Serial:
    global _serial_instance
    if _serial_instance is None or not _serial_instance.is_open:
        _serial_instance = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.1)
    return _serial_instance


def _build_header() -> bytes:
    """Fixed Mode 用 3 バイトヘッダを生成"""
    t_addr = int(TARGET_ADDRESS)
    addr_h = (t_addr >> 8) & 0xFF
    addr_l = t_addr & 0xFF
    ch     = int(TARGET_CHANNEL) & 0xFF
    return bytes([addr_h, addr_l, ch])


def lora_send(raw: bytes):
    """
    暗号化済みパケットを E220-900JP で送信する

    Args:
        raw: 送信するバイナリ (暗号文)
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


def lora_recv(timeout_sec: int = RECV_TIMEOUT):
    """
    E220-900JP からパケットを受信する
 
    E220 の Fixed Mode では受信側のモジュールが 3 バイトヘッダを
    自動除去するため、シリアルにはペイロードのみが届く。
 
    Args:
        timeout_sec: 受信タイムアウト秒数
    Returns:
        受信したバイナリ / タイムアウト時は None
    """
    try:
        ser = _get_serial()
        deadline = time.time() + timeout_sec
        buf = bytearray()
        last_recv_time = None
 
        while time.time() < deadline:
            n = ser.in_waiting
            if n > 0:
                chunk = ser.read(n)
                buf.extend(chunk)
                last_recv_time = time.time()
            elif last_recv_time is not None:
                if time.time() - last_recv_time >= _PACKET_GAP:
                    break
            time.sleep(0.01)
 
        if not buf:
            return None
 
        payload = bytes(buf)

        # E220-900JP は RSSI 有効設定時、末尾に 1 バイト付加する
        if RSSI_BYTE_FLAG and len(payload) > 1:
            rssi_val = payload[-1] - 256
            payload = payload[:-1]
            print("[LoRa Recv] RSSI: {} dBm".format(rssi_val))

        if TRANSPORT_FRAME_ENABLED:
            unwrapped = _unwrap_frame(payload)
            if unwrapped is None:
                if TRANSPORT_LEGACY_FALLBACK:
                    print("[WARN] legacy fallback enabled, passing raw payload")
                    print("[LoRa Recv] {} bytes(legacy): {}".format(
                        len(payload), payload.hex()[:60]))
                    return payload
                return None
            payload = unwrapped

        print("[LoRa Recv] {} bytes: {}".format(len(payload), payload.hex()[:60]))
        return payload
 
    except serial.SerialException as e:
        print("[Error] Serial Device access failed: {}".format(e))
        return None