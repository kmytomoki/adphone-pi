#!/bin/bash
# =============================================================
#  setup_raspi4B.sh  ―  Node-B / 攻撃者ノード (RaspberryPi 4B) セットアップ
#
#  使い方:
#    chmod +x setup_raspi4B.sh   # 初回のみ
#    ./setup_raspi4B.sh
#
#  実行内容:
#    1. プロジェクトディレクトリへ移動
#    2. 仮想環境を毎回クリーン作成
#    3. 必要ライブラリのインストール
#       - pyserial / hexdump
#       - cryptography==3.4.8  (Python3.7対応の最終版)
#       - RPi.GPIO
#    4. config_code/ で mode3_2.py → config_cui.py --apply
#    5. operation_code/ で mode0_2.py
#    6. lpwa/ ディレクトリへ戻る
# =============================================================

set -e  # エラーが出たら即終了

# ── 色付きログ ───────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m';   CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $1"; }
success() { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

echo ""
echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}  Node-B セットアップ  (RasPi4B / /dev/ttyS0)${NC}"
echo -e "${CYAN}================================================${NC}"
echo ""

# ── 1. プロジェクトディレクトリへ移動 ─────────────────────
PROJECT_DIR="$HOME/work/lpwa"
info "移動: $PROJECT_DIR"
cd "$PROJECT_DIR" || error "ディレクトリが見つかりません: $PROJECT_DIR"
success "$(pwd)"

# ── 2. 仮想環境をクリーン作成 ──────────────────────────────
info "仮想環境を作成中 (.venv)..."
rm -rf .venv
python3 -m venv .venv || error "仮想環境の作成に失敗しました"
source .venv/bin/activate || error "アクティベートに失敗しました"
success "仮想環境アクティベート完了"

# pip 自体を最新化
info "pip をアップグレード中..."
pip install --quiet --upgrade pip
success "pip アップグレード完了"

# ── 3. ライブラリのインストール ────────────────────────────
info "pyserial / hexdump をインストール中..."
pip install --quiet pyserial hexdump
success "pyserial / hexdump インストール完了"

# cryptography: Python3.7 対応の最終版を指定
info "cryptography をインストール中..."
PYTHON_VERSION=$(python3 -c "import sys; print(sys.version_info.minor)")
if [ "$PYTHON_VERSION" -le 7 ]; then
    warn "Python 3.7 を検出: cryptography==3.4.8 をインストールします"
    pip install --quiet "cryptography==3.4.8" || error "cryptography のインストールに失敗しました"
else
    info "Python 3.8+ を検出: cryptography 最新版をインストールします"
    pip install --quiet cryptography || error "cryptography のインストールに失敗しました"
fi
success "cryptography インストール完了"

info "RPi.GPIO をインストール中..."
pip install --quiet RPi.GPIO || warn "RPi.GPIO のインストールに失敗しました（動作に影響なし）"
success "RPi.GPIO インストール完了"

# ── インストール確認 ───────────────────────────────────────
info "インストール確認中..."
python3 -c "import serial; print('  pyserial:', serial.__version__)"
python3 -c "from cryptography.hazmat.primitives.asymmetric import ed25519; print('  cryptography: OK')" \
    || error "cryptography のインポートに失敗しました"
success "全ライブラリ確認完了"

# ── 4. モード設定 & apply (config_code/) ──────────────────
info "config_code/ へ移動"
cd "$PROJECT_DIR/config_code" || error "config_code/ が見つかりません"

info "mode3_2.py を実行中..."
python3 mode3_2.py || error "mode3_2.py の実行に失敗しました"
success "mode3_2.py 完了"

info "config_cui.py --apply を実行中 (/dev/ttyS0)..."
python3 config_cui.py /dev/ttyS0 --apply || error "config_cui.py の実行に失敗しました"
success "config_cui.py 完了"

# ── 5. 通常モードへ復帰 (operation_code/) ─────────────────
info "operation_code/ へ移動"
cd "$PROJECT_DIR/operation_code" || error "operation_code/ が見つかりません"

info "mode0_2.py を実行中..."
python3 mode0_2.py || error "mode0_2.py の実行に失敗しました"
success "mode0_2.py 完了"

# ── 6. lpwa/ へ戻る ───────────────────────────────────────
cd "$PROJECT_DIR"
success "lpwa/ へ戻りました: $(pwd)"

# ── 完了 ───────────────────────────────────────────────────
echo ""
echo -e "${GREEN}================================================${NC}"
echo -e "${GREEN}  セットアップ完了！LoRa 通信の準備ができました${NC}"
echo -e "${GREEN}================================================${NC}"
echo -e "  初回のみ: 鍵ペアを生成してください"
echo -e "  ${YELLOW}python3 keygen.py generate --node B${NC}"
echo ""
echo -e "  通信を開始するには:"
echo -e "  ${YELLOW}python3 node_b.py${NC}"
echo ""
echo -e "  攻撃テストを行うには:"
echo -e "  ${YELLOW}python3 attacker.py${NC}"
echo ""
