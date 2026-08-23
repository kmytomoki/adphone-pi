#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Adphone BLE GATT Server (Raspberry Pi 4)
=======================================

このスクリプトは、React Native アプリ側の `AdphoneSettingsScreen` と
**UUID / サービス構成 / データフォーマットを完全に合わせた**
Raspberry Pi 4 用 BLE GATT サーバー実装です。

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
実行前の準備（Raspberry Pi 上）
--------------------------------------------------

1. BlueZ が 5.50 以降でインストールされていることを確認
   - Raspberry Pi OS (Bullseye / Bookworm) 標準で OK なケースが多いです。

2. Python パッケージをインストール
   このリポジトリ直下（本ファイルと同じフォルダ）で:

       python3 -m venv .venv
       source .venv/bin/activate       # Windows PowerShell の場合: .venv\\Scripts\\Activate.ps1
       pip install -r requirements.txt

3. Bluetooth 権限
   GATT サーバー登録とアドバタイズには管理者権限が必要になるため、
   通常は `sudo` 付きで実行します。

--------------------------------------------------
実行方法（Raspberry Pi 上）
--------------------------------------------------

このファイルと `requirements.txt` を Raspberry Pi にコピーした後、
Raspberry Pi 上で以下を実行してください。

   # 仮想環境を作っていない場合は省略可
   cd /path/to/this/folder
   python3 -m venv .venv
   source .venv/bin/activate          # Windows PowerShell: .venv\\Scripts\\Activate.ps1
   pip install -r requirements.txt

   # BLE GATT サーバー起動（管理者権限が必要な場合が多い）
   sudo -E python3 adphone_ble_server.py

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
- さらに、Pi 側コンソールから任意の文字列を入力すると、
  現在接続中の Android へ Notify 送信できます。
"""

import asyncio
import logging
import sys
from typing import Optional

from dbus_next.aio import MessageBus
from dbus_next.service import ServiceInterface, method, dbus_property, signal
from dbus_next import Variant, BusType


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("adphone-ble")


# UUID / 名前は React Native 側コードと完全一致させる
SERVICE_UUID = "12345678-1234-5678-1234-56789abcdef0"
WRITE_CHAR_UUID = "abcd1234-5678-1234-5678-abcdef123456"
NOTIFY_CHAR_UUID = "abcd1234-5678-1234-5678-abcdef123457"
ADPHONE_DISPLAY_NAME = "ADPHONE"


BLUEZ_SERVICE_NAME = "org.bluez"
ADAPTER_IFACE = "org.bluez.Adapter1"
GATT_MANAGER_IFACE = "org.bluez.GattManager1"
LE_ADVERTISING_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"
GATT_SERVICE_IFACE = "org.bluez.GattService1"
GATT_CHAR_IFACE = "org.bluez.GattCharacteristic1"
LE_ADVERTISEMENT_IFACE = "org.bluez.LEAdvertisement1"

MAIN_LOOP = asyncio.get_event_loop()


def find_adapter_path(objects: dict) -> Optional[str]:
    """BlueZ ObjectManager の戻り値から最初のアダプタパスを取得."""
    for path, ifaces in objects.items():
        if ADAPTER_IFACE in ifaces:
            return path
    return None


class AdphoneService(ServiceInterface):
    """GATT Service: 12345678-1234-5678-1234-56789abcdef0"""

    def __init__(self, bus, index: int, adapter_path: str):
        self.path = f"{adapter_path}/service{index}"
        super().__init__(GATT_SERVICE_IFACE)
        self._uuid = SERVICE_UUID
        self._primary = True
        self.bus = bus

    def get_path(self) -> str:
        return self.path

    @dbus_property()
    def UUID(self) -> "s":
        return self._uuid

    @UUID.setter
    def UUID(self, value: "s") -> None:
        self._uuid = str(value)

    @UUID.setter
    def UUID(self, value: "s") -> None:
        self._uuid = str(value)

    @UUID.setter
    def UUID(self, value: "s") -> None:
        # BlueZ 側から書き換えられることは通常ありませんが、
        # dbus-next の仕様上 setter を定義しておきます。
        self._uuid = str(value)

    @dbus_property()
    def Primary(self) -> "b":
        return self._primary

    @Primary.setter
    def Primary(self, value: "b") -> None:
        # BlueZ 側から書き換えられることは通常ありませんが、
        # dbus-next の仕様上 setter を定義しておきます。
        self._primary = bool(value)


class AdphoneWriteChar(ServiceInterface):
    """
    Write Characteristic (Android → Pi)

    - UUID: abcd1234-5678-1234-5678-abcdef123456
    - Properties: Write, WriteWithoutResponse
    - 挙動:
        * Android から UTF-8 テキストを受信
        * コンソールに出力
        * 必要に応じて Notify キャラクタリスティックにエコーを送る
    """

    def __init__(self, bus, index: int, service: AdphoneService):
        self.path = f"{service.get_path()}/char{index}"
        super().__init__(GATT_CHAR_IFACE)
        self._uuid = WRITE_CHAR_UUID
        self._service = service
        self._value = bytearray()
        self._flags = ["write", "write-without-response"]
        self.bus = bus
        self.notify_char: Optional["AdphoneNotifyChar"] = None

    def get_path(self) -> str:
        return self.path

    @dbus_property()
    def UUID(self) -> "s":
        return self._uuid

    @UUID.setter
    def UUID(self, value: "s") -> None:
        self._uuid = str(value)

    @dbus_property()
    def Service(self) -> "o":
        return self._service.get_path()

    @Service.setter
    def Service(self, value: "o") -> None:
        # 実際には書き換えられない想定だが、dbus-next の要求に合わせて定義
        pass

    @Service.setter
    def Service(self, value: "o") -> None:
        # 実際には書き換えられない想定だが、dbus-next の要求に合わせて定義
        pass

    @dbus_property()
    def Flags(self) -> "as":
        return self._flags

    @Flags.setter
    def Flags(self, value: "as") -> None:
        self._flags = list(value)

    @Flags.setter
    def Flags(self, value: "as") -> None:
        self._flags = list(value)

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":  # type: ignore[override]
        # クライアントから Read されるケースは少ない想定だが、最後に受信した値を返す
        logger.info("ReadValue on WRITE char (returning last written bytes)")
        return self._value

    @method()
    def WriteValue(self, value: "ay", options: "a{sv}") -> None:  # type: ignore[override]
        # Android アプリからの書き込みを受け取る
        try:
            text = bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            text = "<invalid utf-8>"

        self._value = bytearray(value)
        logger.info("Received from Android (write): %r", text)

        # シンプルなエコー応答を Notify キャラクタリスティック経由で返す
        if self.notify_char is not None:
            echo = f"echo from pi: {text}"
            MAIN_LOOP.create_task(self.notify_char.send_text(echo))


class AdphoneNotifyChar(ServiceInterface):
    """
    Notify Characteristic (Pi → Android)

    - UUID: abcd1234-5678-1234-5678-abcdef123457
    - Properties: Read, Notify
    - 挙動:
        * Pi 側から UTF-8 テキストをセットし、Notify を発火
        * Android アプリの `Ble.startNotifyText` により文字列として受信される
    """

    def __init__(self, bus, index: int, service: AdphoneService):
        self.path = f"{service.get_path()}/char{index}"
        super().__init__(GATT_CHAR_IFACE)
        self._uuid = NOTIFY_CHAR_UUID
        self._service = service
        self._value = bytearray(b"ready")
        self._flags = ["read", "notify"]
        self.bus = bus
        self._subscribed = False

    def get_path(self) -> str:
        return self.path

    @dbus_property()
    def UUID(self) -> "s":
        return self._uuid

    @UUID.setter
    def UUID(self, value: "s") -> None:
        self._uuid = str(value)

    @dbus_property()
    def Service(self) -> "o":
        return self._service.get_path()

    @Service.setter
    def Service(self, value: "o") -> None:
        # 実際には書き換えられない想定だが、dbus-next の要求に合わせて定義
        pass

    @dbus_property()
    def Flags(self) -> "as":
        return self._flags

    @Flags.setter
    def Flags(self, value: "as") -> None:
        self._flags = list(value)

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":  # type: ignore[override]
        logger.info("ReadValue on NOTIFY char (current value=%r)", self._value)
        return self._value

    @method()
    def StartNotify(self) -> None:  # type: ignore[override]
        logger.info("Android subscribed to notifications")
        self._subscribed = True

    @method()
    def StopNotify(self) -> None:  # type: ignore[override]
        logger.info("Android unsubscribed from notifications")
        self._subscribed = False

    async def send_text(self, text: str) -> None:
        """Android へ UTF-8 テキストを Notify 送信."""
        if not self._subscribed:
            logger.warning("Cannot send notify: not subscribed (yet)")
            return

        self._value = bytearray(text.encode("utf-8"))
        logger.info("Send notify to Android: %r", text)

        # GATT Characteristic の PropertiesChanged シグナルを飛ばす
        # （BlueZ がクライアントへ Notify を送るトリガーになる）
        iface = GATT_CHAR_IFACE
        props = {"Value": Variant("ay", self._value)}
        changed = {iface: props}
        await self.bus.emit_properties_changed(self.path, changed)  # type: ignore[attr-defined]


class AdphoneAdvertisement(ServiceInterface):
    """
    LE Advertisement

    - LocalName: ADPHONE
    - ServiceUUIDs: [SERVICE_UUID]
    """

    def __init__(self, index: int, adapter_path: str):
        self.path = f"{adapter_path}/advertisement{index}"
        super().__init__(LE_ADVERTISEMENT_IFACE)
        self._service_uuids = [SERVICE_UUID]
        self._local_name = ADPHONE_DISPLAY_NAME
        self._appearance = 0
        self._timeout = 0
        self._discoverable = True

    def get_path(self) -> str:
        return self.path

    @dbus_property()
    def Type(self) -> "s":
        # "peripheral" としてアドバタイズ
        return "peripheral"

    @dbus_property()
    def ServiceUUIDs(self) -> "as":
        return self._service_uuids

    @dbus_property()
    def LocalName(self) -> "s":
        return self._local_name

    @dbus_property()
    def Appearance(self) -> "q":
        return self._appearance

    @dbus_property()
    def Timeout(self) -> "q":
        return self._timeout

    @dbus_property()
    def Discoverable(self) -> "b":
        return self._discoverable

    @method()
    def Release(self) -> None:  # type: ignore[override]
        logger.info("Advertisement released by BlueZ")


async def register_app_and_advertisement(bus: MessageBus):
    """GATT サービス & キャラクタリスティック & アドバタイズを BlueZ に登録."""
    obj = await bus.introspect(BLUEZ_SERVICE_NAME, "/")
    manager = bus.get_proxy_object(BLUEZ_SERVICE_NAME, "/", obj)
    om = manager.get_interface("org.freedesktop.DBus.ObjectManager")
    objects = await om.call_get_managed_objects()

    adapter_path = find_adapter_path(objects)
    if adapter_path is None:
        raise RuntimeError("Bluetooth adapter not found. Is Bluetooth enabled?")

    logger.info("Using adapter: %s", adapter_path)

    # GATT Manager
    obj_adapter = await bus.introspect(BLUEZ_SERVICE_NAME, adapter_path)
    adapter = bus.get_proxy_object(BLUEZ_SERVICE_NAME, adapter_path, obj_adapter)

    gatt_manager = adapter.get_interface(GATT_MANAGER_IFACE)
    adv_manager = adapter.get_interface(LE_ADVERTISING_MANAGER_IFACE)

    # GATT Service / Characteristics を作成
    service = AdphoneService(bus, index=0, adapter_path=adapter_path)
    write_char = AdphoneWriteChar(bus, index=0, service=service)
    notify_char = AdphoneNotifyChar(bus, index=1, service=service)
    write_char.notify_char = notify_char

    # DBus にエクスポート
    bus.export(service.get_path(), service)
    bus.export(write_char.get_path(), write_char)
    bus.export(notify_char.get_path(), notify_char)

    # GATT アプリとして登録
    app_path = "/org/adphone/app"
    app_iface = ServiceInterface("org.bluez.GattApplication1")
    bus.export(app_path, app_iface)

    logger.info("Registering GATT application ...")
    await gatt_manager.call_register_application(
        app_path,
        {},
    )
    logger.info("GATT application registered")

    # アドバタイズを登録
    advertisement = AdphoneAdvertisement(index=0, adapter_path=adapter_path)
    bus.export(advertisement.get_path(), advertisement)

    logger.info("Registering LE advertisement ...")
    await adv_manager.call_register_advertisement(
        advertisement.get_path(),
        {},
    )
    logger.info("LE advertisement registered (ADPHONE)")

    return service, write_char, notify_char, advertisement


async def console_sender_loop(notify_char: AdphoneNotifyChar):
    """
    Pi コンソールからの入力を Android 側へ Notify 送信するループ.

    - 何か文字列を入力して Enter → Android の受信ログに表示される
    - 空行だけ入力した場合はスキップ
    - Ctrl+C でプログラム終了
    """
    loop = asyncio.get_event_loop()
    logger.info("You can type messages here to send to Android via Notify.")
    logger.info("Press Ctrl+C to exit.")

    while True:
        try:
            line = await loop.run_in_executor(None, sys.stdin.readline)
        except (KeyboardInterrupt, EOFError):
            break

        if not line:
            # EOF
            break

        text = line.rstrip("\r\n")
        if not text:
            continue

        await notify_char.send_text(text)


async def main_async():
    # BlueZ は system bus 上で動作するため、BusType.SYSTEM を明示的に指定する
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    service, write_char, notify_char, advertisement = await register_app_and_advertisement(bus)

    # 起動メッセージ
    logger.info("Adphone BLE GATT server is running.")
    logger.info("Service UUID: %s", SERVICE_UUID)
    logger.info("Write Char UUID: %s", WRITE_CHAR_UUID)
    logger.info("Notify Char UUID: %s", NOTIFY_CHAR_UUID)
    logger.info("Advertising as '%s' with service UUID in advertisement.", ADPHONE_DISPLAY_NAME)

    try:
        await console_sender_loop(notify_char)
    finally:
        # 終了時にアプリケーション / アドバタイズを解除
        logger.info("Shutting down GATT server...")
        try:
            # BlueZ に明示的な Unregister を呼んでも良いが、
            # プロセス終了時にも自動でクリーンアップされる。
            pass
        except Exception as e:
            logger.warning("Error during shutdown: %s", e)


def main():
    try:
        MAIN_LOOP.run_until_complete(main_async())
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt: exiting...")
    finally:
        # 念のため停止
        pending = asyncio.all_tasks(loop=MAIN_LOOP)
        for task in pending:
            task.cancel()
        try:
            MAIN_LOOP.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        except Exception:
            pass
        MAIN_LOOP.close()


if __name__ == "__main__":
    main()

