# -*- coding: utf-8 -*-
"""
lora_e220.py (node_a 用 / RaspberryPi 5)

pi1_bridge.py の send_via_lpwa() と同じ送信ロジックを使用
シリアルポート: /dev/ttyAMA0  (RasPi5)

配線:
    VCC  -> Pin 4  (5V)
    GND  -> Pin 6  (GND)
    TXD  -> Pin 10 (RXD / GPIO15)  ※クロス接続
    RXD  -> Pin 8  (TXD / GPIO14)  ※クロス接続
    M0   -> GND に直結 (Low固定)
    M1   -> GND に直結 (Low固定)
    AUX  -> 未接続でも動作可
"""

import serial
import time

# ── E220-900JP 設定 (pi1_bridge.py と同じ値) ────────
SERIAL_PORT    = "/dev/ttyAMA0"   # RasPi5 のシリアルポート
BAUD_RATE      = 9600
FIXED_MODE     = True
TARGET_ADDRESS = 0xFFFF           # ブロードキャスト
TARGET_CHANNEL = 0x00
RECV_TIMEOUT   = 10               # 受信タイムアウト(秒)
# ─────────────────────────────────────────────────────


def _build_header() -> bytes:
    """Fixed Mode 用 3 バイトヘッダを生成 (pi1_bridge.py と同じロジック)"""
    t_addr   = int(TARGET_ADDRESS)
    addr_h   = (t_addr >> 8) & 0xFF
    addr_l   = t_addr & 0xFF
    ch       = int(TARGET_CHANNEL) & 0xFF
    return bytes([addr_h, addr_l, ch])


def lora_send(raw: bytes):
    """
    暗号化済みパケットを E220-900JP で送信する
    pi1_bridge.py の send_via_lpwa() と同じ送信処理

    Args:
        raw: 送信するバイナリ (暗号文)
    """
    payload = _build_header() + raw   # 3バイトヘッダ + 暗号文

    try:
        with serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=None) as ser:
            # 送信バッファが空くまで待つ (pi1_bridge.py と同じロジック)
            while True:
                if ser.out_waiting == 0:
                    break
            ser.write(payload)
            ser.flush()
        print("[LoRa Send] {} bytes (+ 3B header)".format(len(raw)))

    except serial.SerialException as e:
        print("[Error] Serial Device access failed: {}".format(e))


def lora_recv(timeout_sec: int = RECV_TIMEOUT):
    """
    E220-900JP からパケットを受信する
    pi2_receiver.py と同じ in_waiting ポーリング方式

    - Fixed Mode: 受信データの先頭 3 バイト (ヘッダ) を除去
    - RSSI バイト付きの場合は末尾 1 バイトを除去

    Args:
        timeout_sec: 受信タイムアウト秒数
    Returns:
        受信した暗号文バイナリ / タイムアウト時は None
    """
    try:
        with serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=0.1) as ser:
            deadline = time.time() + timeout_sec
            while time.time() < deadline:
                if ser.in_waiting > 0:
                    # pi2_receiver.py と同じ: 少し待ってパケットをまとめて読む
                    time.sleep(0.05)
                    data = ser.read(ser.in_waiting)
                    if not data:
                        continue

                    # Fixed Mode: 先頭 3 バイト (ヘッダ) を除去
                    if len(data) <= 3:
                        continue
                    payload = data[3:]

                    # RSSI バイト付きの場合は末尾 1 バイトを除去
                    # (UTF-8 としてデコードできない末尾バイト = RSSI)
                    try:
                        payload.decode('utf-8')
                        # デコード成功 = RSSI なし (そのまま返す)
                    except UnicodeDecodeError:
                        if len(payload) > 1:
                            rssi_val = payload[-1] - 256
                            payload  = payload[:-1]
                            print("[LoRa Recv] RSSI: {} dBm".format(rssi_val))

                    print("[LoRa Recv] {} bytes".format(len(payload)))
                    return payload

    except serial.SerialException as e:
        print("[Error] Serial Device access failed: {}".format(e))
        return None

    return None   # タイムアウト
