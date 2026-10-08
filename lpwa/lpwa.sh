#!/bin/bash
# =============================================================
#  lpwa.sh  ―  LPWA 通信ワンコマンドラッパー
#
#  使い方:
#    chmod +x lpwa.sh                              # 初回のみ
#    ./lpwa.sh status                              # 現在の setting.ini の設定を表示
#    ./lpwa.sh config --own 1                      # アドレスを設定して E220 に書き込む
#    ./lpwa.sh bridge                              # BLE-LPWA ブリッジ起動（v2 メッシュ）
#    ./lpwa.sh bridge --own 2 --target 1           # アドレスを上書きしてブリッジ起動
#    ./lpwa.sh mesh                                # v2 メッシュノード起動（mesh_node.py）
#    ./lpwa.sh mesh --own 2                        # アドレスを上書きして起動
#
#  v2（既定）: 管理型フラッディング・常に暗号化・鍵は state/ に保存（ROUTING_PLAN.md Phase 3）
#    setting.ini: hop_limit / role（CLIENT・ROUTER・CLIENT_MUTE）/ node_name / group_key_hex
#    mesh 対話コマンド: <宛先> <本文> / all <本文> / nodes / forget <addr> / announce / stats
#
#  v1（--legacy）: 旧方式。全ノードを同じ方式にそろえること
#    ./lpwa.sh bridge --legacy --crypto [--peer 2]  # v1 暗号化ブリッジ
#    ./lpwa.sh mesh --legacy --ttl 3 [--peer 2]     # v1 メッシュノード（node_mesh.py）
#    v1 mesh 対話コマンド: <宛先> <本文> / gbcast <本文> / bcast <peer> <本文>
#
#  グループ鍵設定 (setting.ini):
#    group_key_hex = <64桁hex>                      # 32バイト AES-256 グループ鍵
#    group_key_id  = 0                              # 鍵ローテーション識別子 (0〜255)
#    packet_gap_sec = 0.2                            # 受信フレーム終端判定ギャップ(秒)
#    transport_frame_enabled = 1                     # magic/len/crc 外層フレーム有効化
#    transport_legacy_fallback = 0                   # フレーム不一致時に生ペイロード許容
#    ./lpwa.sh service install                     # 自動起動サービスを登録（電源 ON で起動）
#    ./lpwa.sh service status                      # サービスの状態確認
#    ./lpwa.sh service log                         # リアルタイムログ表示
#    ./lpwa.sh test                                # adhoc.py の動作確認テスト
#    ./lpwa.sh receive                             # 生受信モード（デバッグ用）
#    ./lpwa.sh send                                # 生送信モード（デバッグ用）
#
#  オプション:
#    --own    ADDR   自ノードアドレス（0〜65534, 例: 1）
#    --target ADDR   送信先アドレス（0〜65535, 65535=ブロードキャスト）
#    --port   PATH   シリアルポート（デフォルト: /dev/ttyS0）
#    --legacy        v1 で動かす（以下は v1 専用）
#    --ttl    N      [v1] アドホック TTL（1〜255, デフォルト: setting.ini の値）
#    --crypto        [v1] 暗号化モードを有効にする（bridge / mesh 共通）
#    --peer   ADDR   [v1] 鍵交換する相手アドレス（複数指定可: --peer 2 --peer 3）
# =============================================================

set -e

# ── スクリプトのあるディレクトリを自動検出 ───────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/config_code"
OP_DIR="$SCRIPT_DIR/operation_code"
SETTING_INI="$CONFIG_DIR/setting.ini"

# ── ブリッジ本体の場所 ─────────────────────────────────────
# リポジトリ構成: Raspberry/ble_final_version/、Pi 上の配置: ~/work/ble/（このスクリプトは ~/work/lpwa/sample_code/）
find_bridge_dir() {
    local d
    for d in "$SCRIPT_DIR/../ble_final_version" "$SCRIPT_DIR/../../ble"; do
        if [[ -f "$d/adphone_ble_lpwa_bridge.py" ]]; then
            (cd "$d" && pwd)
            return 0
        fi
    done
    return 1
}

# ── デフォルト設定 ──────────────────────────────────────────
PORT="/dev/ttyS0"
OWN_ADDRESS=""
TARGET_ADDRESS_ARG=""
TTL_ARG=""
CRYPTO_MODE=""      # --crypto が指定された場合 "1"
LEGACY=""           # --legacy が指定された場合 "1"（v1 で動かす）
PEER_ADDRS=()       # --peer で指定されたアドレス（配列）

# ── 色付きログ ───────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m';   CYAN='\033[0;36m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $1"; }
success() { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# ── setting.ini から値を読む ─────────────────────────────────
ini_get() {
    python3 -c "
import configparser, sys
cfg = configparser.ConfigParser()
cfg.read('$SETTING_INI')
print(cfg.get('E220-900JP', sys.argv[1], fallback=sys.argv[2]))
" "$1" "$2"
}

# ── setting.ini の値を更新する ───────────────────────────────
ini_set() {
    python3 -c "
import configparser, sys
cfg = configparser.ConfigParser()
cfg.read('$SETTING_INI')
cfg.set('E220-900JP', sys.argv[1], sys.argv[2])
with open('$SETTING_INI', 'w') as f:
    cfg.write(f)
" "$1" "$2"
}

# ── 引数パース ───────────────────────────────────────────────
SUBCOMMAND=""
SERVICE_ACTION="status"  # service サブコマンドのアクション（デフォルト: status）
while [[ $# -gt 0 ]]; do
    case "$1" in
        config|receive|send|status|bridge|mesh|test|service)
            SUBCOMMAND="$1"; shift ;;
        install|start|stop|restart|enable|disable|log|uninstall)
            SERVICE_ACTION="$1"; shift ;;
        --own)
            OWN_ADDRESS="$2"; shift 2 ;;
        --target)
            TARGET_ADDRESS_ARG="$2"; shift 2 ;;
        --ttl)
            TTL_ARG="$2"; shift 2 ;;
        --port)
            PORT="$2"; shift 2 ;;
        --crypto)
            CRYPTO_MODE="1"; shift ;;
        --legacy)
            LEGACY="1"; shift ;;
        --peer)
            PEER_ADDRS+=("$2"); shift 2 ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^#  *//'
            exit 0 ;;
        *)
            error "不明な引数: $1\n使い方: $0 {status|config|bridge|service|test|receive|send} [オプション]" ;;
    esac
done

[[ -z "$SUBCOMMAND" ]] && {
    echo "使い方: $0 {status|config|bridge|service|test|receive|send} [--own ADDR] [--target ADDR] [--port PATH]"
    exit 1
}

# ── サブコマンド実行 ─────────────────────────────────────────
case "$SUBCOMMAND" in

    status)
        echo -e "\n${CYAN}=== 現在のアドレス設定 (setting.ini) ===${NC}"
        OWN=$(ini_get own_address 0)
        TGT=$(ini_get target_address 65535)
        TTL=$(ini_get ttl 3)
        printf "  %-20s %d  (0x%04X)\n" "自ノードアドレス:"  "$OWN" "$OWN"
        if [[ "$TGT" -eq 65535 ]]; then
            printf "  %-20s %d  (0xFFFF = ブロードキャスト)\n" "送信先アドレス:" "$TGT"
        else
            printf "  %-20s %d  (0x%04X)\n" "送信先アドレス:" "$TGT" "$TGT"
        fi
        printf "  %-20s %d\n" "TTL:" "$TTL"

        GK=$(ini_get group_key_hex "")
        GK_ID=$(ini_get group_key_id 0)
        if [[ -n "$GK" ]]; then
            GK_HEAD="${GK:0:8}"
            GK_TAIL="${GK: -8}"
            printf "  %-20s key_id=%s  (%s...%s)\n" "グループ鍵:" "$GK_ID" "$GK_HEAD" "$GK_TAIL"
        else
            printf "  %-20s 未設定\n" "グループ鍵:"
        fi
        GAP=$(ini_get packet_gap_sec 0.2)
        FRAME_ON=$(ini_get transport_frame_enabled 1)
        FRAME_FALLBACK=$(ini_get transport_legacy_fallback 0)
        printf "  %-20s %s sec\n" "packet_gap_sec:" "$GAP"
        printf "  %-20s %s\n" "frame_enabled:" "$FRAME_ON"
        printf "  %-20s %s\n" "legacy_fallback:" "$FRAME_FALLBACK"
        echo ""
        ;;

    config)
        echo -e "\n${CYAN}=== モード設定 & Apply ===${NC}"

        # アドレスが指定されていれば setting.ini を更新
        if [[ -n "$OWN_ADDRESS" ]]; then
            info "自ノードアドレスを $OWN_ADDRESS に設定..."
            ini_set own_address "$OWN_ADDRESS"
            success "own_address = $OWN_ADDRESS"
        fi
        if [[ -n "$TARGET_ADDRESS_ARG" ]]; then
            info "送信先アドレスを $TARGET_ADDRESS_ARG に設定..."
            ini_set target_address "$TARGET_ADDRESS_ARG"
            success "target_address = $TARGET_ADDRESS_ARG"
        fi
        if [[ -n "$TTL_ARG" ]]; then
            info "TTL を $TTL_ARG に設定..."
            ini_set ttl "$TTL_ARG"
            success "ttl = $TTL_ARG"
        fi

        # 現在の設定を表示
        OWN=$(ini_get own_address 0)
        TGT=$(ini_get target_address 65535)
        TTL=$(ini_get ttl 3)
        info "適用する設定: 自ノード=0x$(printf '%04X' $OWN)  送信先=0x$(printf '%04X' $TGT)  TTL=$TTL"

        cd "$CONFIG_DIR" || error "config_code/ が見つかりません: $CONFIG_DIR"

        info "mode3.py を実行中 (E220 を設定モードに切り替え)..."
        python3 mode3.py || error "mode3.py の実行に失敗しました"
        success "mode3.py 完了"

        info "config_cui.py --apply を実行中 ($PORT)..."
        python3 config_cui.py "$PORT" --apply || error "config_cui.py の実行に失敗しました"
        success "設定 Apply 完了"
        ;;

    receive)
        echo -e "\n${CYAN}=== 受信モード ===${NC}"
        OWN=$(ini_get own_address 0)
        info "自ノードアドレス: 0x$(printf '%04X' $OWN)"

        cd "$OP_DIR" || error "operation_code/ が見つかりません: $OP_DIR"

        info "mode0.py を実行中 (通常モードに切り替え)..."
        python3 mode0.py || error "mode0.py の実行に失敗しました"
        success "mode0.py 完了"

        info "receive.py を起動中 ($PORT --rssi)..."
        python3 receive.py "$PORT" --rssi
        ;;

    send)
        echo -e "\n${CYAN}=== 送信モード ===${NC}"

        # CLI 引数 > setting.ini の順で送信先アドレスを決定
        if [[ -n "$TARGET_ADDRESS_ARG" ]]; then
            SEND_TARGET="$TARGET_ADDRESS_ARG"
        else
            SEND_TARGET=$(ini_get target_address 65535)
        fi
        info "送信先アドレス: 0x$(printf '%04X' $SEND_TARGET)"

        cd "$OP_DIR" || error "operation_code/ が見つかりません: $OP_DIR"

        info "mode0.py を実行中 (通常モードに切り替え)..."
        python3 mode0.py || error "mode0.py の実行に失敗しました"
        success "mode0.py 完了"

        info "send.py を起動中 ($PORT, target=$SEND_TARGET)..."
        python3 send.py "$PORT" -f --target_address "$SEND_TARGET" --target_channel 0 < ascii_data.txt
        ;;

    bridge)
        echo -e "\n${CYAN}=== BLE-LPWA アドホックブリッジ ===${NC}"
        BRIDGE_DIR="$(find_bridge_dir)" || error "ブリッジスクリプトが見つかりません（../ble_final_version または ../../ble）"
        BRIDGE="$BRIDGE_DIR/adphone_ble_lpwa_bridge.py"

        # 仮想環境の python3 を優先使用（bless 等が venv にインストールされているため）
        VENV_PY="$BRIDGE_DIR/.venv/bin/python3"
        if [[ -x "$VENV_PY" ]]; then
            PY="$VENV_PY"
            info "Python: $PY (venv)"
        else
            PY="python3"
            warn ".venv が見つかりません。システム python3 を使用します: $BRIDGE_DIR/.venv"
        fi

        OWN=$(ini_get own_address 0)
        TGT=$(ini_get target_address 65535)
        info "自ノード: 0x$(printf '%04X' $OWN)  送信先: 0x$(printf '%04X' $TGT)"
        if [[ -n "$CRYPTO_MODE" ]]; then
            info "暗号化モード: 有効 (X25519 + AES-GCM + Ed25519)"
            [[ ${#PEER_ADDRS[@]} -gt 0 ]] && info "鍵交換相手: ${PEER_ADDRS[*]}"
        else
            info "暗号化モード: 無効 (平文)"
        fi

        # E220 を通常モードに切り替え
        info "mode0.py を実行中 (E220 を通常モードに切り替え)..."
        python3 "$SCRIPT_DIR/config_code/mode0.py" 2>/dev/null || \
            warn "mode0.py スキップ (wiringpi 未インストールの場合は無視してください)"

        # setting.ini の値を読み、CLI 引数で上書き（常にブリッジスクリプトへ渡す）
        EFF_OWN="${OWN_ADDRESS:-$(ini_get own_address 0)}"
        EFF_TGT="${TARGET_ADDRESS_ARG:-$(ini_get target_address 65535)}"
        EFF_TTL="${TTL_ARG:-$(ini_get ttl 3)}"
        BRIDGE_ARGS="--self-address $EFF_OWN --target-address $EFF_TGT"
        if [[ -n "$LEGACY" ]]; then
            BRIDGE_ARGS="$BRIDGE_ARGS --legacy --ttl $EFF_TTL"
            [[ -n "$CRYPTO_MODE" ]] && BRIDGE_ARGS="$BRIDGE_ARGS --crypto"
            for P in "${PEER_ADDRS[@]}"; do
                BRIDGE_ARGS="$BRIDGE_ARGS --peer $P"
            done
        elif [[ -n "$CRYPTO_MODE$TTL_ARG" || ${#PEER_ADDRS[@]} -gt 0 ]]; then
            warn "--crypto / --ttl / --peer は v1（--legacy）専用です。v2 は setting.ini を使い、常に暗号化します"
        fi

        info "ブリッジ起動中... (Ctrl+C で停止)"
        sudo "$PY" -B "$BRIDGE" $BRIDGE_ARGS
        ;;

    mesh)
        echo -e "\n${CYAN}=== メッシュノード${LEGACY:+ (v1)} ===${NC}"
        if [[ -n "$LEGACY" ]]; then
            MESH="$SCRIPT_DIR/node_mesh.py"
        else
            MESH="$SCRIPT_DIR/mesh_node.py"
        fi
        [[ -f "$MESH" ]] || error "メッシュノードが見つかりません: $MESH"

        # venv の python3 を優先使用（cryptography 等が venv に入っているため）
        VENV_PY="$SCRIPT_DIR/.venv/bin/python3"
        if [[ -x "$VENV_PY" ]]; then
            PY="$VENV_PY"
            info "Python: $PY (venv)"
        else
            PY="python3"
            warn ".venv が見つかりません。システム python3 を使用します: $SCRIPT_DIR/.venv"
        fi

        # アドレス・TTL を setting.ini から読み、CLI 引数で上書き
        if [[ -n "$OWN_ADDRESS" ]]; then
            info "自ノードアドレスを $OWN_ADDRESS に設定..."
            ini_set own_address "$OWN_ADDRESS"
            success "own_address = $OWN_ADDRESS"
        fi
        if [[ -n "$TTL_ARG" ]]; then
            info "TTL を $TTL_ARG に設定..."
            ini_set ttl "$TTL_ARG"
            success "ttl = $TTL_ARG"
        fi

        OWN=$(ini_get own_address 0)
        TTL=$(ini_get ttl 3)
        info "自ノード: 0x$(printf '%04X' $OWN)  TTL=$TTL"
        [[ ${#PEER_ADDRS[@]} -gt 0 ]] && info "鍵交換相手: ${PEER_ADDRS[*]}"

        # E220 を通常モードに切り替え
        info "mode0.py を実行中 (E220 を通常モードに切り替え)..."
        python3 "$SCRIPT_DIR/config_code/mode0.py" 2>/dev/null || \
            warn "mode0.py スキップ (wiringpi 未インストールの場合は無視してください)"

        MESH_ARGS=""
        for P in "${PEER_ADDRS[@]}"; do
            MESH_ARGS="$MESH_ARGS --peer $P"
        done

        info "メッシュノード起動中... (Ctrl+C で停止)"
        if [[ -n "$LEGACY" ]]; then
            "$PY" -B "$MESH" $MESH_ARGS
        else
            # v2 は鍵ファイル（state/、パーミッション 600）をブリッジと共有するため root で動かす
            sudo "$PY" -B "$MESH"
        fi
        ;;

    test)
        echo -e "\n${CYAN}=== ルーティング Phase 1 テスト (tests/) ===${NC}"
        (cd "$SCRIPT_DIR" && python3 -m unittest discover -s tests) || warn "tests/ に失敗あり"

        echo -e "\n${CYAN}=== adhoc.py 動作確認テスト ===${NC}"
        python3 - <<'PYEOF'
import sys, struct
sys.path.insert(0, '.')
import adhoc

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"

def check(label, cond):
    print(f"  [{PASS if cond else FAIL}] {label}")
    return cond

def make_pkt(src, mid, ttl, body):
    """他ノードから届いたパケットを simulate（encode を経由しない）"""
    return struct.pack("!HHB", src, mid, ttl) + body

ok = True

# ① encode の基本（送信パケット生成）
adhoc._seen.clear(); adhoc._seq = 0
pkt = adhoc.encode(b"hello", src_addr=1, ttl=3)
ok &= check("encode: 5バイトヘッダ付き (len=10)", len(pkt) == 10)
src, mid, ttl, payload = struct.unpack("!HHB", pkt[:5]) + (pkt[5:],)
ok &= check("encode: src_addr=1", src == 1)
ok &= check("encode: ttl=3", ttl == 3)
ok &= check("encode: payload=b'hello'", payload == b"hello")

# ② decode（他ノードからの受信を simulate）
adhoc._seen.clear()
recv = make_pkt(src=2, mid=10, ttl=3, body=b"world")
result = adhoc.decode(recv)
ok &= check("decode: 初回は値を返す", result is not None)
ok &= check("decode: src_addr=2", result[0] == 2)
ok &= check("decode: ttl=3", result[2] == 3)
ok &= check("decode: payload=b'world'", result[3] == b"world")

# ③ 重複破棄（同じパケットを2回受け取った場合）
dup = adhoc.decode(recv)
ok &= check("decode: 2回目は None (重複破棄)", dup is None)

# ④ 自ノードが送信したパケットを受信しても破棄（ハーフエコー防止）
adhoc._seen.clear(); adhoc._seq = 0
own_pkt = adhoc.encode(b"mine", src_addr=1, ttl=3)  # encode で seen 登録済み
ok &= check("decode: 自分が送ったパケットは None (ループ防止)", adhoc.decode(own_pkt) is None)

# ⑤ make_relay: TTL=3 → 2
adhoc._seen.clear()
pkt3 = make_pkt(src=3, mid=20, ttl=3, body=b"relay")
adhoc.decode(pkt3)  # seen 登録
relay = adhoc.make_relay(pkt3)
ok &= check("make_relay: TTL=3 → 中継パケットあり", relay is not None)
_, _, ttl2 = struct.unpack("!HHB", relay[:5])
ok &= check("make_relay: TTL が 3→2 に減っている", ttl2 == 2)
ok &= check("make_relay: payload が保持されている", relay[5:] == b"relay")

# ⑥ make_relay: TTL=1 → 中継しない
adhoc._seen.clear()
pkt1 = make_pkt(src=4, mid=30, ttl=1, body=b"end")
adhoc.decode(pkt1)
ok &= check("make_relay: TTL=1 → None (中継なし)", adhoc.make_relay(pkt1) is None)

# ⑦ 中継パケットの重複破棄（src+msg_id が同じなら破棄）
adhoc._seen.clear()
orig = make_pkt(src=5, mid=40, ttl=3, body=b"dup2")
adhoc.decode(orig)           # (5, 40) を seen に登録
relay2 = adhoc.make_relay(orig)   # TTL=2 のパケット
ok &= check("中継パケット (src+msg_id 同一) も重複破棄", adhoc.decode(relay2) is None)

print()
print("  結果:", "全テスト通過 ✓" if ok else "失敗あり ✗")
PYEOF

        echo -e "\n${CYAN}=== adhoc_crypto.py GROUP_DATA テスト ===${NC}"
        python3 - <<'PYEOF'
import sys, os
sys.path.insert(0, '.')
import adhoc_crypto as crypto
from cryptography.hazmat.primitives.asymmetric import ed25519

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"

def check(label, cond):
    print(f"  [{PASS if cond else FAIL}] {label}")
    return cond

ok = True

# テスト用鍵の準備
ed_priv_a = ed25519.Ed25519PrivateKey.generate()
ed_pub_a  = ed_priv_a.public_key().public_bytes_raw()
ed_priv_b = ed25519.Ed25519PrivateKey.generate()
ed_pub_b  = ed_priv_b.public_key().public_bytes_raw()
group_key = os.urandom(32)

# ⑧ encode_group_data + decode_group_data 基本
crypto._seen.clear(); crypto._seq = 0
pkt = crypto.encode_group_data(1, b"group hello", group_key, key_id=5, ed_priv=ed_priv_a, ttl=3)
ok &= check("encode_group_data: パケットサイズ > HEADER+77", len(pkt) > crypto.HEADER_SIZE + 77)

hdr = crypto.parse_header(pkt)
ok &= check("encode_group_data: type == TYPE_GROUP_DATA", hdr["type"] == crypto.TYPE_GROUP_DATA)
ok &= check("encode_group_data: dest == BROADCAST", hdr["dest_addr"] == crypto.BROADCAST_ADDR)

crypto._seen.clear()
plaintext, kid = crypto.decode_group_data(pkt, group_key, ed_pub_a, expected_key_id=5)
ok &= check("decode_group_data: 復号成功", plaintext == b"group hello")
ok &= check("decode_group_data: key_id 一致", kid == 5)

# ⑨ key_id 不一致でエラー
crypto._seen.clear()
try:
    crypto.decode_group_data(pkt, group_key, ed_pub_a, expected_key_id=99)
    ok &= check("decode_group_data: key_id 不一致で ValueError", False)
except ValueError as e:
    ok &= check("decode_group_data: key_id 不一致で ValueError", "key_id mismatch" in str(e))

# ⑩ 異なるグループ鍵で復号失敗
crypto._seen.clear()
wrong_key = os.urandom(32)
try:
    crypto.decode_group_data(pkt, wrong_key, ed_pub_a)
    ok &= check("decode_group_data: 異なるグループ鍵で InvalidTag", False)
except Exception as e:
    ok &= check("decode_group_data: 異なるグループ鍵で InvalidTag", "InvalidTag" in type(e).__name__ or "tag" in str(e).lower())

# ⑪ 異なる送信者の署名で検証失敗
crypto._seen.clear()
try:
    crypto.decode_group_data(pkt, group_key, ed_pub_b)
    ok &= check("decode_group_data: 署名不一致で InvalidSignature", False)
except Exception as e:
    ok &= check("decode_group_data: 署名不一致で InvalidSignature", "Signature" in type(e).__name__)

# ⑫ make_relay は TYPE_GROUP_DATA でも動作する
crypto._seen.clear()
crypto.is_seen(hdr["src_addr"], hdr["msg_id"])
relay = crypto.make_relay(pkt)
ok &= check("make_relay: GROUP_DATA で中継パケット生成", relay is not None)
rhdr = crypto.parse_header(relay)
ok &= check("make_relay: TTL が 3→2", rhdr["ttl"] == 2)
ok &= check("make_relay: type 維持", rhdr["type"] == crypto.TYPE_GROUP_DATA)

# ⑬ 既存 TYPE_DATA が壊れていないことの確認
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
dh_a = X25519PrivateKey.generate()
dh_b = X25519PrivateKey.generate()
from cryptography.hazmat.primitives import serialization
dh_pub_b = dh_b.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
shared = crypto.derive_shared_key(dh_a, dh_pub_b)

crypto._seen.clear(); crypto._seq = 0
data_pkt = crypto.encode_data(1, 2, b"unicast msg", shared, ed_priv_a, ttl=3)
dhdr = crypto.parse_header(data_pkt)
ok &= check("既存 TYPE_DATA: type == 0x02", dhdr["type"] == crypto.TYPE_DATA)

crypto._seen.clear()
dh_pub_a = dh_a.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
shared_b = crypto.derive_shared_key(dh_b, dh_pub_a)
pt = crypto.decode_data(data_pkt, shared_b, ed_pub_a)
ok &= check("既存 TYPE_DATA: 復号成功", pt == b"unicast msg")

print()
print("  結果:", "全テスト通過 ✓" if ok else "失敗あり ✗")
PYEOF
        ;;

    service)
        ACTION="$SERVICE_ACTION"
        SVC="adphone-bridge"
        SVC_FILE="/etc/systemd/system/$SVC.service"
        BRIDGE_DIR="$(find_bridge_dir || echo "")"
        BRIDGE="$BRIDGE_DIR/adphone_ble_lpwa_bridge.py"
        VENV_PY="$BRIDGE_DIR/.venv/bin/python3"
        [[ -x "$VENV_PY" ]] || VENV_PY="python3"

        case "$ACTION" in
            install)
                [[ -f "$BRIDGE" ]] || error "ブリッジスクリプトが見つかりません: $BRIDGE"
                info "サービスファイルを生成中..."
                info "  Python  : $VENV_PY"
                info "  Bridge  : $BRIDGE"
                sudo tee "$SVC_FILE" > /dev/null << EOF
[Unit]
Description=Adphone BLE-LPWA Ad-hoc Bridge
After=bluetooth.target
Wants=bluetooth.target

[Service]
Type=simple
User=root
WorkingDirectory=$SCRIPT_DIR
ExecStart=$VENV_PY -B $BRIDGE
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
                sudo systemctl daemon-reload
                sudo systemctl enable "$SVC"
                sudo systemctl start  "$SVC"
                success "サービス登録完了 → 電源 ON で自動起動します"
                echo ""
                sudo systemctl status "$SVC" --no-pager
                ;;
            start)     sudo systemctl start   "$SVC" && success "起動しました" ;;
            stop)      sudo systemctl stop    "$SVC" && success "停止しました" ;;
            restart)   sudo systemctl restart "$SVC" && success "再起動しました" ;;
            enable)    sudo systemctl enable  "$SVC" && success "自動起動を有効化しました" ;;
            disable)   sudo systemctl disable "$SVC" && success "自動起動を無効化しました" ;;
            status)    sudo systemctl status  "$SVC" --no-pager ;;
            log)       sudo journalctl -u "$SVC" -f ;;
            uninstall)
                sudo systemctl stop    "$SVC" 2>/dev/null || true
                sudo systemctl disable "$SVC" 2>/dev/null || true
                sudo rm -f "$SVC_FILE"
                sudo systemctl daemon-reload
                success "サービスを削除しました"
                ;;
            *)
                error "不明なアクション: $ACTION\n使い方: $0 service {install|start|stop|restart|enable|disable|status|log|uninstall}"
                ;;
        esac
        ;;
esac

success "完了: $SUBCOMMAND"
