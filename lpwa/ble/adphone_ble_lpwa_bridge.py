#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Adphone BLE ←→ LPWA Bridge (Raspberry Pi 4)
===========================================

目的:
  - Android アプリ (AdphoneSettingsScreen) から BLE 経由で受信した文字列を、
    既存の LPWA 送信ロジック（E220-900JP 等）でそのまま送信するブリッジスクリプト。

役割:
  - Raspberry Pi を BLE ペリフェラル (ADPHONE) として動作させる
  - BLE Write (Android → Pi) で受信した UTF-8 文字列を `pi1_bridge.send_via_lpwa` に渡して送信
  - BLE Notify (Pi → Android) では、LPWA 送信実行後のステータスを簡易メッセージとして返す

Android 側仕様（必ず一致させること）:
  - Service UUID: 12345678-1234-5678-1234-56789abcdef0
  - Write Characteristic (Android → Pi):
      abcd1234-5678-1234-5678-abcdef123456
  - Notify Characteristic (Pi → Android):
      abcd1234-5678-1234-5678-abcdef123457
  - デバイス名（広告名）: ADPHONE

--------------------------------------------------
依存パッケージのインストール（Raspberry Pi 上）
--------------------------------------------------

このフォルダ（本ファイルと `requirements.txt` がある場所）で:

    python3 -m venv .venv
    source .venv/bin/activate          # Windows PowerShell: .venv\\Scripts\\Activate.ps1
    pip install -r requirements.txt

※ すでに `.venv` を作っている場合は `pip install -r requirements.txt` のみで OK です。

--------------------------------------------------
実行方法（Raspberry Pi 上）
--------------------------------------------------

    cd /path/to/this/folder
    source .venv/bin/activate
    sudo -E "$(which python)" adphone_ble_lpwa_bridge.py

起動後、Android アプリの「アドフォン連携（Bluetooth）」画面で
周辺デバイスをスキャンすると、`ADPHONE` という名前のデバイスが
表示されます。接続後、

- アプリ → Pi:
    - 「送信」欄に入力した文字列が BLE Write 経由で Pi に届き、
      その文字列がそのまま LPWA モジュールから送信されます。
- Pi → アプリ:
    - LPWA 送信実行後に、簡単なステータスメッセージ
      （例: "LPWA sent: <text>"）を Notify で返します。

--------------------------------------------------
LPWA 側の設定について
--------------------------------------------------

本スクリプトは、同じフォルダ内の `pi1_bridge.py` に定義された
`send_via_lpwa(text_data: str)` をそのまま利用します。

従って、LPWA モジュールのシリアルポート・宛先アドレス・チャンネル等は
`pi1_bridge.py` 側の定数:

  - SERIAL_PORT
  - BAUD_RATE
  - FIXED_MODE
  - TARGET_ADDRESS
  - TARGET_CHANNEL

を編集して調整してください。
"""

import logging
import sys
from typing import List, Optional

import dbus.exceptions
import serial
import hexdump
from bluezero import peripheral, adapter


# --- LPWA (E220-900JP) 設定 ---
SERIAL_PORT = "/dev/ttyAMA0"
BAUD_RATE = 9600
FIXED_MODE = True
TARGET_ADDRESS = 0xFFFF  # 0xFFFF はブロードキャスト
TARGET_CHANNEL = 0x00


def send_via_lpwa(text_data: str) -> None:
    payload = bytes([])

    if FIXED_MODE:
        t_addr = int(TARGET_ADDRESS)
        t_addr_H = t_addr >> 8
        t_addr_L = t_addr & 0xFF
        t_ch = int(TARGET_CHANNEL)
        payload = bytes([t_addr_H, t_addr_L, t_ch])

    if isinstance(text_data, str):
        payload = payload + text_data.encode("utf-8")
    elif isinstance(text_data, bytes):
        payload = payload + text_data

    print("\n--- LPWA Sending ---")
    print(f"Serial Port: {SERIAL_PORT}")
    print("Hex Dump:")
    hexdump.hexdump(payload)

    with serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=None) as ser:
        while ser.out_waiting != 0:
            pass
        ser.write(payload)
        ser.flush()
        print("SENDED via LPWA")


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("adphone-ble-lpwa-bridge")


SERVICE_UUID = "12345678-1234-5678-1234-56789abcdef0"
WRITE_CHAR_UUID = "abcd1234-5678-1234-5678-abcdef123456"
NOTIFY_CHAR_UUID = "abcd1234-5678-1234-5678-abcdef123457"
ADPHONE_DISPLAY_NAME = "ADPHONE"


class AdphoneBleLpwaBridge:
    """
    BLE (Android) ←→ LPWA (E220 等) ブリッジ

    - Service 1つ: SERVICE_UUID
    - Characteristic:
        * WRITE_CHAR_UUID  : Android → Pi（write, write-without-response）
        * NOTIFY_CHAR_UUID : Pi → Android（read, notify）
    - Write 受信時に LPWA 送信を実行し、結果を Notify で返す。
    """

    def __init__(self, adapter_addr: Optional[str] = None) -> None:
        # Bluetooth アダプタの初期化
        self._adapter = adapter.Adapter(adapter_addr)
        self._adapter.powered = True

        # Android 側のスキャン時に「ADPHONE」と見えるようにする
        self._adapter.alias = ADPHONE_DISPLAY_NAME
        # BLE アドバタイズに任せるためクラシック側 discoverable/pairable は OFF
        self._adapter.discoverable = False
        self._adapter.pairable = False

        # Notify 用のバッファ（直近のメッセージを List[int] で保持）
        self._last_notify_value: List[int] = list(b"ready")
        self._notify_char = None  # type: ignore[assignment]

        # Peripheral (GATT Server) 本体
        self.peripheral = peripheral.Peripheral(
            adapter_address=self._adapter.address,
            local_name=ADPHONE_DISPLAY_NAME,
        )

        # Service を追加
        srv_id = 1
        self.peripheral.add_service(
            srv_id=srv_id,
            uuid=SERVICE_UUID,
            primary=True,
        )

        # Write Characteristic: Android → Pi → LPWA
        self.peripheral.add_characteristic(
            srv_id=srv_id,
            chr_id=1,
            uuid=WRITE_CHAR_UUID,
            value=[],
            notifying=False,
            flags=["write", "write-without-response"],
            read_callback=None,
            write_callback=self._on_write,
            notify_callback=None,
        )

        # Notify Characteristic: Pi → Android
        self.peripheral.add_characteristic(
            srv_id=srv_id,
            chr_id=2,
            uuid=NOTIFY_CHAR_UUID,
            value=self._last_notify_value,
            notifying=False,
            flags=["read", "notify"],
            read_callback=self._on_read,
            write_callback=None,
            notify_callback=self._on_notify_state_change,
        )

        # 追加済み Characteristic 一覧から Notify 用のインスタンスを保持
        for ch in self.peripheral.characteristics:
            try:
                uuid = ch.props["org.bluez.GattCharacteristic1"]["UUID"]
            except Exception:
                continue
            if uuid == NOTIFY_CHAR_UUID:
                self._notify_char = ch
                break

        # 接続・切断時ログ
        self.peripheral.on_connect = self._on_connect
        self.peripheral.on_disconnect = self._on_disconnect

    # --------------------------------------------------------------
    # 接続・切断ログ
    # --------------------------------------------------------------
    def _on_connect(self, device=None) -> None:
        if device is not None:
            try:
                addr = getattr(device, "address", device)
            except Exception:
                addr = device
        else:
            addr = "(unknown)"
        logger.info("Device connected: %s", addr)

    def _on_disconnect(self, device=None) -> None:
        if device is not None:
            try:
                addr = getattr(device, "address", device)
            except Exception:
                addr = device
        else:
            addr = "(unknown)"
        logger.info("Device disconnected: %s", addr)

    # --------------------------------------------------------------
    # Characteristic コールバック
    # --------------------------------------------------------------
    def _on_write(self, value, options) -> None:
        """
        Android アプリから Write されたときに呼ばれるコールバック。

        - 受信文字列を LPWA で送信
        - 送信結果メッセージを Notify キャラにセット
        """
        try:
            text = bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            text = "<invalid utf-8>"

        logger.info("Received from Android (write): %r", text)

        # LPWA 送信（例外は握りつぶさずログに出す）
        lpwa_ok = False
        try:
            send_via_lpwa(text)
            lpwa_ok = True
        except Exception as e:  # noqa: BLE001
            logger.error("LPWA send failed: %s", e)

        # Notify 用メッセージを生成
        if lpwa_ok:
            notify_text = f"LPWA sent: {text}"
        else:
            notify_text = f"LPWA send failed: {text}"

        self._last_notify_value = list(notify_text.encode("utf-8"))

        if self._notify_char is not None:
            self._notify_char.set_value(self._last_notify_value)
            logger.info("Updated notify value: %r", notify_text)

    def _on_read(self, options) -> List[int]:
        """
        Android アプリから Notify キャラを Read されたときに返す値。
        """
        logger.info("Android read NOTIFY characteristic (value=%r)", self._last_notify_value)
        return self._last_notify_value

    def _on_notify_state_change(self, notifying: bool, characteristic) -> None:
        """
        Notify 開始/停止時のコールバック。
        """
        logger.info("Notify state changed: notifying=%s", notifying)

    # --------------------------------------------------------------
    # 公開 API
    # --------------------------------------------------------------
    def run(self) -> None:
        """
        BLE GATT サーバーを起動し、Android からの接続を待ち受ける。
        """
        logger.info("Starting Adphone BLE ↔ LPWA bridge (bluezero)...")
        logger.info("Service UUID: %s", SERVICE_UUID)
        logger.info("Write Char UUID: %s", WRITE_CHAR_UUID)
        logger.info("Notify Char UUID: %s", NOTIFY_CHAR_UUID)
        logger.info("Advertising as '%s'", ADPHONE_DISPLAY_NAME)
        logger.info("Waiting for Android app to connect...")

        self.peripheral.publish()


def main() -> None:
    dev = AdphoneBleLpwaBridge(adapter_addr=None)
    try:
        dev.run()
    except KeyboardInterrupt:
        logger.info("Ctrl+C received. Shutting down...")
        sys.exit(0)
    except dbus.exceptions.DBusException as e:
        if "ServiceUnknown" in str(e) or "name" in str(e).lower():
            logger.info("Shutting down (advertisement unregistered).")
            sys.exit(0)
        raise


if __name__ == "__main__":
    main()

