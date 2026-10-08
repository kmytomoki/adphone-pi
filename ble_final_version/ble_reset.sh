#!/usr/bin/env bash
# ble_reset.sh — Raspberry Pi BLEスタックリセットスクリプト
#
# ⚠️  通常は不要。以下の状況でのみ実行すること:
#     - スキャンで Adphone が見つかるのに接続が繰り返し失敗する
#     - python スクリプトの再起動でも改善しない
#
# 毎回実行すると、Pi のボンド情報が消えて Android 側と不一致になる場合がある。
# 通常の再起動手順: python3 adphone_ble_lpwa_bridge.py を再実行するだけでよい。
#
# 使い方:
#   chmod +x ble_reset.sh
#   sudo ./ble_reset.sh

set -euo pipefail

echo "[1/6] bluetoothd 停止..."
sudo systemctl stop bluetooth

echo "[2/6] ボンディング情報クリア (/var/lib/bluetooth/*)..."
sudo rm -rf /var/lib/bluetooth/*

echo "[3/6] BlueZ 設定 (/etc/bluetooth/main.conf)..."
MAIN_CONF="/etc/bluetooth/main.conf"

# ── [Policy] セクションに JustWorksRepairing = always を設定 ──────────────
# Android が旧ボンドキーで接続を試みた際に Pi 側が自動で再ペアリングを承認する
if grep -q "^\[Policy\]" "$MAIN_CONF" 2>/dev/null; then
  if grep -q "^JustWorksRepairing" "$MAIN_CONF"; then
    sudo sed -i 's/^JustWorksRepairing\s*=.*/JustWorksRepairing = always/' "$MAIN_CONF"
  else
    sudo sed -i '/^\[Policy\]/a JustWorksRepairing = always' "$MAIN_CONF"
  fi
else
  printf '\n[Policy]\nJustWorksRepairing = always\n' | sudo tee -a "$MAIN_CONF" > /dev/null
fi
echo "  → JustWorksRepairing = always を設定しました"

# ── [LE] セクションの MaxConnections を設定 ───────────────────────────────
if grep -q "^\[LE\]" "$MAIN_CONF" 2>/dev/null; then
  if grep -q "^MaxConnections" "$MAIN_CONF"; then
    sudo sed -i 's/^MaxConnections\s*=.*/MaxConnections = 10/' "$MAIN_CONF"
  else
    sudo sed -i '/^\[LE\]/a MaxConnections = 10' "$MAIN_CONF"
  fi
else
  printf '\n[LE]\nMaxConnections = 10\n' | sudo tee -a "$MAIN_CONF" > /dev/null
fi
echo "  → MaxConnections = 10 を設定しました"

echo "[4/6] hci0 down..."
sudo hciconfig hci0 down

echo "[5/6] hci0 up..."
sudo hciconfig hci0 up

echo "[6/6] bluetoothd 再起動..."
sudo systemctl start bluetooth

# bluetoothd が起動するまで少し待つ
sleep 2

echo ""
echo "=== hci0 状態確認 ==="
hciconfig hci0
