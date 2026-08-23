#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Adphone BLE GATT Server (Raspberry Pi 4, bluezero 版)
====================================================

React Native 側の `AdphoneSettingsScreen` と
**UUID / サービス構成 / データフォーマットを完全に合わせた**
Raspberry Pi 4 用 BLE GATT サーバー実装です。

このファイルは BlueZ D-Bus を直接触るのではなく、
Raspberry Pi 向けの高レベルラッパーライブラリ **bluezero** を使っています。

--------------------------------------------------
UUID / 名前（Android 側コードと完全一致）
--------------------------------------------------

- Service UUID: 12345678-1234-5678-1234-56789abcdef0
- Write Characteristic (Android → Pi):
    abcd1234-5678-1234-5678-abcdef123456
- Notify Characteristic (Pi → Android):
    abcd1234-5678-1234-5678-abcdef123457
- デバイス名（広告名）: ADPHONE

Android アプリ側では `react-native-ble-plx` を利用しており、
write / notify のペイロードは **UTF-8 文字列** として扱われます。
（ライブラリ内部で Base64 ⇄ バイト列変換されるため、
  Raspberry Pi 側では単純な UTF-8 文字列として送受信すれば問題ありません。）

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
    sudo -E "$(which python)" adphone_ble_server_bluezero.py

起動後、Android アプリの「アドフォン連携（Bluetooth）」画面で
周辺デバイスをスキャンすると、`ADPHONE` という名前のデバイスが
表示されます。接続後、

- アプリ → Pi: 「送信」欄に入力した文字列が Write キャラクタリスティック経由で Pi に届きます。
- Pi → アプリ: Pi 側から送った文字列は Notify キャラクタリスティックとして
  Android アプリの受信ログに表示されます。

--------------------------------------------------
Pi 側の挙動概要
--------------------------------------------------

- Android から Write されたテキストをコンソールに表示
- そのテキストに対して簡単なエコー応答を Notify で返す
  例: Android から "hello adphone" を受信 → "echo from pi: hello adphone" を Notify 送信

--------------------------------------------------
接続がタイムアウトする場合（Operation timed out）
--------------------------------------------------

Raspberry Pi の BlueZ で GATT サーバー（ペリフェラル）を使うには、
実験的機能の有効化が必要な場合があります。

1. 設定を編集:
     sudo nano /etc/bluetooth/main.conf

2. [General] セクションで以下を確認・変更:
     [General]
     Experimental = true

   （すでに Experimental = true の場合はそのままで OK）

3. Bluetooth サービスを再起動:
     sudo systemctl restart bluetooth

4. 本スクリプトを再実行:
     sudo -E "$(which python)" adphone_ble_server_bluezero.py

5. 再度アプリから接続を試す。

※ 起動後、アプリで connect を押したときにラズパイコンソールに
  "Device connected: ..." が出るかどうかで、接続要求が届いているか確認できます。
  出ない場合は上記の Experimental 有効化と bluetooth 再起動を試してください。
"""

import logging
import sys
from typing import List, Optional

import dbus.exceptions
from bluezero import peripheral, adapter


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("adphone-ble-bluezero")


# UUID / 名前は React Native 側コードと完全一致させる
SERVICE_UUID = "12345678-1234-5678-1234-56789abcdef0"
WRITE_CHAR_UUID = "abcd1234-5678-1234-5678-abcdef123456"
NOTIFY_CHAR_UUID = "abcd1234-5678-1234-5678-abcdef123457"
ADPHONE_DISPLAY_NAME = "ADPHONE"


class AdphonePeripheral:
    """
    Adphone 用 GATT サーバー（bluezero ベース）

    - Service 1つ: SERVICE_UUID
    - Characteristic:
        * WRITE_CHAR_UUID  : Android → Pi（write, write-without-response）
        * NOTIFY_CHAR_UUID : Pi → Android（read, notify）
    """

    def __init__(self, adapter_addr: Optional[str] = None) -> None:
        """
        :param adapter_addr: Bluetooth アダプタの MAC アドレス。
                             None の場合は最初のアダプタが自動選択されます。
        """
        # bluezero の Adapter でアドレスを取得（未指定なら自動的に 1つ目）
        self._adapter = adapter.Adapter(adapter_addr)
        self._adapter.powered = True

        # アダプタの表示名（Android のスキャン結果で「ADPHONE」と出るようにする）
        self._adapter.alias = ADPHONE_DISPLAY_NAME
        # BLE ペリフェラルでは discoverable は LE アドバタイズで行う。True にすると
        # クラシック BT の discoverable になり、接続が不安定になることがあるため False にしておく。
        self._adapter.discoverable = False
        # pairable=True にすると Android がペアリングを試み、ラズパイ側にエージェントが無いと
        # 接続がタイムアウトする。GATT の読み書きのみならペアリング不要のため False 推奨。
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

        # Write Characteristic: Android → Pi
        #  - flags: write, write-without-response
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
        #  - flags: read, notify
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
        # peripheral.characteristics は {srv_id: {chr_id: Characteristic}} の辞書
        try:
            self._notify_char = self.peripheral.characteristics[srv_id][2]
        except (KeyError, TypeError):
            self._notify_char = None
            logger.warning("Could not get notify characteristic reference")

        # 接続・切断時にログを出す（ラズパイ側で「接続要求が届いているか」の確認に使う）
        self.peripheral.on_connect = self._on_connect
        self.peripheral.on_disconnect = self._on_disconnect

    def _on_connect(self, device=None) -> None:
        """Android などが接続してきたときに呼ばれる（bluezero の dongle.on_connect）"""
        if device is not None:
            try:
                addr = getattr(device, "address", device)
            except Exception:
                addr = device
        else:
            addr = "(unknown)"
        logger.info("Device connected: %s", addr)

    def _on_disconnect(self, device=None) -> None:
        """接続が切れたときに呼ばれる"""
        if device is not None:
            try:
                addr = getattr(device, "address", device)
            except Exception:
                addr = device
        else:
            addr = "(unknown)"
        logger.info("Device disconnected: %s", addr)
    # --------------------------------------------------------------
    def _on_write(self, value, options) -> None:
        """
        Android アプリから Write されたときに呼ばれるコールバック。

        :param value: 書き込まれた値（List[int]）
        :param options: BlueZ から渡されるオプション（未使用）
        """
        try:
            text = bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            text = "<invalid utf-8>"

        logger.info("Received from Android (write): %r", text)

        # エコー用のメッセージを準備して Notify キャラクタリスティックにセット
        echo_text = f"echo from pi: {text}"
        new_val = list(echo_text.encode("utf-8"))
        self._last_notify_value = new_val

        if self._notify_char is not None:
            # set_value に List[int] を渡すと、Notify 購読中なら通知が飛ぶ
            self._notify_char.set_value(new_val)
            logger.info("Updated notify value: %r", echo_text)
        else:
            logger.warning("notify_char is None, cannot send echo")

    def _on_read(self, options) -> List[int]:
        """
        Android アプリから Read されたときに返す値。
        bluezero/localGATT の仕様により、List[int] を返す。
        """
        logger.info("Android read NOTIFY characteristic (value=%r)", self._last_notify_value)
        return self._last_notify_value

    def _on_notify_state_change(self, notifying: bool, characteristic) -> None:
        """
        Notify 開始/停止時のコールバック。
        現状はログ出力のみ。
        """
        logger.info("Notify state changed: notifying=%s", notifying)

    # --------------------------------------------------------------
    # 公開 API
    # --------------------------------------------------------------
    def run(self) -> None:
        """
        GATT サーバーを起動し、永続的に待ち受ける。
        `Peripheral.publish()` はブロッキングで動作します。
        """
        logger.info("Starting Adphone BLE GATT server (bluezero)...")
        logger.info("Service UUID: %s", SERVICE_UUID)
        logger.info("Write Char UUID: %s", WRITE_CHAR_UUID)
        logger.info("Notify Char UUID: %s", NOTIFY_CHAR_UUID)
        logger.info("Advertising as '%s'", ADPHONE_DISPLAY_NAME)
        logger.info("Waiting for Android app to connect...")

        # この呼び出しでアドバタイズ + GATT サービス公開が行われる
        self.peripheral.publish()


def main() -> None:
    # adapter_addr=None で、bluezero にアダプタ自動検出を任せる
    # 特定の MAC アドレスを指定したい場合は、ここを文字列に書き換えてください。
    dev = AdphonePeripheral(adapter_addr=None)
    try:
        dev.run()
    except KeyboardInterrupt:
        logger.info("Ctrl+C received. Shutting down...")
        sys.exit(0)
    except dbus.exceptions.DBusException as e:
        # Ctrl+C 後に bluezero がアドバタイズ解除で失敗することがある（D-Bus セッション終了のため）
        if "ServiceUnknown" in str(e) or "name" in str(e).lower():
            logger.info("Shutting down (advertisement unregistered).")
            sys.exit(0)
        raise


if __name__ == "__main__":
    main()

