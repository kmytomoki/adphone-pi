# アドフォン — Raspberry Pi 側（BLE ペリフェラル / LPWA メッシュ）

災害時オフライン通信アプリ **アドフォン** のハードウェア側。
スマートフォンとは **BLE** で、拠点間は **LPWA（LoRa E220-900JP）** でつなぎ、
セルラー回線が落ちた状況でも災害情報を中継しつづける。

- アプリ本体（React Native）: `Okinawa-Rewave/adphone`
- 製品サイト: https://adphone-lp.vercel.app

---

## 全体像

```
   スマートフォン                Raspberry Pi 4B              別拠点の Pi
  ┌──────────────┐            ┌──────────────────┐          ┌──────────┐
  │  Expo App    │◀── BLE ───▶│ BLE Peripheral   │          │          │
  │  (Central)   │   GATT     │  "Adphone"       │          │          │
  └──────────────┘            │        ↕         │          │          │
                              │  LPWA ブリッジ    │◀ LoRa ──▶│  中継     │
                              │  (署名/暗号/TTL)  │  920MHz  │          │
                              └──────────────────┘          └──────────┘
```

スマホは BLE の Central、Pi は Peripheral。Pi が受け取ったメッセージを LoRa に流し、
別拠点の Pi が受けて、そこに繋がっているスマホへ配る。

---

## リポジトリ構成

```
ble_final_version/                 # 本番用 BLE-LPWA ブリッジ
  adphone_ble_lpwa_bridge.py       #   BLE GATT サーバー本体（622行）
  ble_reset.sh                     #   BlueZ の状態が壊れたときの復旧スクリプト
  requirements.txt

lpwa/                              # LPWA（LoRa）通信レイヤ
  lpwa.sh                          #   ワンコマンド CLI（起動・設定・テスト・systemd 登録）
  node_mesh.py                     #   公開鍵暗号メッシュノード（677行）
  adhoc_crypto.py                  #   暗号化アドホック通信ヘルパー（326行）
  adhoc.py                         #   平文アドホック通信（TTL 中継・重複排除）
  lora_e220_a.py / lora_e220_b.py  #   E220-900JP のシリアル制御
  node_a.py / node_b.py            #   1対1 通信の実装（メッシュの前段）
  rpi1_relay.py                    #   中継専用ノード
  config_code/                     #   E220 のレジスタ設定（モード切替・CUI/GUI 設定ツール）
  operation_code/                  #   送受信の動作確認コード
  tools/mesh_drop_summary.py       #   パケットロス集計
  ble/                             #   ブリッジの配置先（Pi 上のデプロイ用）

adphone_ble_server.py              # 旧: BLE サーバー単体（bless）
adphone_ble_server_bluezero.py     # 旧: bluezero 版の実装
pi1_bridge.py                      # 旧: ブリッジのプロトタイプ
```

---

## 1. BLE GATT サーバー

`ble_final_version/adphone_ble_lpwa_bridge.py`

`bless`（BlueZ / DBus バックエンド）で Pi を BLE ペリフェラル化し、`"Adphone"` として広告する。

- Android / iOS の Central から**複数同時接続**を受け付ける
- TX への Write を受信 → 全接続クライアントへ RX で配信（BLE 側のブロードキャスト）
- 接続・切断のたびに META へ接続台数（1 バイト）を Notify し、
  アプリ側が「いま何台つながっているか」を表示できるようにしている

### Characteristic 定義

UUID はアプリ側 `lib/ble2.ts` と**完全一致**させており、プロトコルの単一情報源としている。

| Characteristic | UUID | 方向 |
|---|---|---|
| Service | `ad000001-ad00-ad00-ad00-ad0000000001` | — |
| TX (Write) | `ad000001-ad00-ad00-ad00-ad0000000002` | App → Pi |
| RX (Notify) | `ad000001-ad00-ad00-ad00-ad0000000003` | Pi → App |
| META (Notify) | `ad000001-ad00-ad00-ad00-ad0000000004` | Pi → 全クライアント（接続数） |

---

## 2. LPWA メッシュ（公開鍵暗号つき）

`lpwa/node_mesh.py` / `lpwa/adhoc_crypto.py`

LoRa は誰でも受信できる。かつ帯域が細くパケット長も限られる。
そこで **「短いヘッダ + 認証つき暗号」** を自前で設計している。

### パケットフォーマット

```
  ┌──────────┬──────────┬──────────┬──────┬──────┐
  │ src_addr │ dest_addr│  msg_id  │ ttl  │ type │
  │  2 bytes │  2 bytes │  2 bytes │ 1 B  │ 1 B  │   = 8 bytes
  └──────────┴──────────┴──────────┴──────┴──────┘
```

| type | 内容 | サイズ |
|---|---|---|
| `ANNOUNCE` (0x01) | 自ノードの公開鍵を配る | header(8) + Ed25519 公開鍵(32) + X25519 公開鍵(32) = 72 B |
| `DATA` (0x02) | ユニキャスト（相手だけが読める） | header(8) + nonce(12) + 署名(64) + 暗号文(N) |
| `GROUP_DATA` (0x03) | グループ鍵ブロードキャスト（全員が読める） | 同上 + key_id |

- **署名**: Ed25519 — 誰が出した情報かを保証する（災害情報では発信者の真正性が決定的に重要）
- **鍵共有**: X25519 ECDH — 事前共有鍵を配らずにペアごとの共通鍵を導出する
- **暗号化**: AES-GCM — 暗号化と改ざん検知を同時に行う
- **中継**: TTL を 1 ずつ減らして転送。`src_addr + msg_id` で重複排除し、ループを止める。
  同時再送による衝突を避けるため、中継前に 0〜`relay_jitter_ms` のランダム遅延を置く
- **E220 層**: モジュールのヘッダは常にブロードキャスト(0xFFFF)で送る。宛先は上記ヘッダの `dest_addr` で判定する
  （特定アドレス宛てにすると途中のノードのモジュールがパケットを捨て、中継できないため）
- 自分宛でないパケットも**復号せずそのまま中継**する（中継ノードに内容を読ませない）

### 動作フロー

1. **起動** — Ed25519 / X25519 の鍵ペアを生成
2. **ANNOUNCE** — 自分の公開鍵をブロードキャストし、一定時間（既定 10 秒）他ノードの公開鍵を収集
3. **メインループ** — 宛先を指定して暗号化送信。受信パケットは署名検証 → 復号 → 表示 → TTL-1 で中継

---

## セットアップ

### 必要なもの

- Raspberry Pi 4B（Raspberry Pi OS 64-bit / Python 3.11）
- LoRa モジュール E220-900JP（シリアル接続 `/dev/ttyS0`）

### インストール

```bash
# 1. BLE ブリッジ側
cd ble_final_version
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. LPWA 側（暗号処理に cryptography が必要）
cd ../lpwa
python3 -m venv .venv
source .venv/bin/activate
pip install pyserial cryptography

# 3. ノード設定
cp config_code/setting.ini.example config_code/setting.ini
# own_address を各ノードで別の値にする。group_key_hex を生成して設定する:
#   python3 -c "import os; print(os.urandom(32).hex())"
```

### 起動

`lpwa/lpwa.sh` がすべての操作をまとめている。

```bash
chmod +x lpwa.sh          # 初回のみ

./lpwa.sh status                       # 現在の設定を表示
./lpwa.sh config --own 1               # ノードアドレスを E220 に書き込む
./lpwa.sh bridge --crypto              # BLE-LPWA 暗号ブリッジを起動
./lpwa.sh mesh --own 1 --ttl 3         # 公開鍵暗号メッシュノードとして起動
./lpwa.sh test                         # 通信ロジックのテストを実行
```

メッシュ起動後は標準入力から操作する。

```
2 こちら避難所A、物資不足        # ノード2へユニキャスト暗号送信
gbcast 全体連絡：断水しています   # グループ鍵ブロードキャスト（全員が復号可）
```

### 自動起動（電源 ON でブリッジを立ち上げる）

```bash
./lpwa.sh service install   # systemd ユニットを生成して有効化
./lpwa.sh service log       # ログを追う
```

### BLE がつながらないとき

```bash
sudo bash ble_final_version/ble_reset.sh
```

BlueZ の状態が壊れた場合のみ実行する。**毎回実行するとボンディング不一致を起こす**ため常用しない。

---

## テスト

`./lpwa.sh test` に通信ロジックの検証を組み込んでいる。

- **平文アドホック（`adhoc.py`）** — ヘッダ生成、重複破棄、自分の送信パケットのループ防止、
  TTL 3→2 の中継、TTL 1 での中継停止
- **暗号メッシュ（`adhoc_crypto.py`）** — グループ鍵での暗復号、`key_id` 不一致の検出、
  誤ったグループ鍵での `InvalidTag`、別人の署名での `InvalidSignature`、
  GROUP_DATA の中継時に TTL と type が保たれること、X25519 ECDH によるユニキャストの往復

---

## 既知の課題

- ルーティングは TTL つきフラッディングのまま（中継前のランダム遅延のみ）。
  管理型フラッディング・経路学習・ACK は [ROUTING_PLAN.md](ROUTING_PLAN.md) の Phase 3 以降で対応する
- `lpwa/` と `work3/`（旧作業コピー）に重複したコードがある。`lpwa/` が最新版で、`work3/` は
  `.gitignore` で除外している
- 旧実装（`adphone_ble_server.py` など）がリポジトリ直下に残っている
