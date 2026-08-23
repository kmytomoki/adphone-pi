import socket
import serial
import hexdump
import sys

# --- LPWA (E220-900JP) 設定 ---
SERIAL_PORT = "/dev/ttyAMA0" # 接続されているポートに合わせて変更
BAUD_RATE = 9600

# Fixed Mode (1対N通信) を使う場合は True にして宛先を設定
FIXED_MODE = True
TARGET_ADDRESS = 0xFFFF # 0xFFFFはブロードキャスト（または特定の相手のアドレス）
TARGET_CHANNEL = 0x00   # 相手のチャンネル

# --- Wi-Fi (Server) 設定 ---
WIFI_PORT = 50000
BUFFER_SIZE = 1024

def send_via_lpwa(text_data):
    """
    Wi-Fiで受け取ったデータをLPWAモジュールへ送信する関数
    (ご提示のコードロジックを流用・適合)
    """
    payload = bytes([])

    # 1. ヘッダーの構築 (Fixed Modeの場合)
    if FIXED_MODE:
        if TARGET_ADDRESS is not None and TARGET_CHANNEL is not None:
            t_addr = int(TARGET_ADDRESS)
            t_addr_H = t_addr >> 8
            t_addr_L = t_addr & 0xFF
            t_ch = int(TARGET_CHANNEL)
            # アドレスH + アドレスL + チャンネル をヘッダとして付与
            payload = bytes([t_addr_H, t_addr_L, t_ch])
        else:
            print("[LPWA] Invalid Target Address/Channel")
            return

    # 2. ペイロード（本文）の結合
    if isinstance(text_data, str):
        payload = payload + text_data.encode('utf-8')
    elif isinstance(text_data, bytes):
        payload = payload + text_data
    
    print("\n--- LPWA Sending ---")
    print(f"Serial Port: {SERIAL_PORT}")
    print("Hex Dump:")
    hexdump.hexdump(payload)

    # 3. シリアル送信処理
    try:
        with serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=None) as ser:
            # 送信バッファが空くのを待つロジック（元コードより）
            while True:
                if ser.out_waiting == 0:
                    break
            
            ser.write(payload)
            ser.flush()
            print("SENDED via LPWA")
            
    except serial.SerialException as e:
        print(f"[Error] Serial Device access failed: {e}")

def start_server():
    """Wi-Fiからの接続を待ち受けるサーバープロセス"""
    # IPv4, TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # アドレス再利用の設定（再起動時のエラー回避）
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # すべてのインターフェース(0.0.0.0)で待ち受け
        s.bind(('0.0.0.0', WIFI_PORT))
        s.listen(1)
        
        print(f"Listening on port {WIFI_PORT} for Wi-Fi connection...")

        while True:
            try:
                # 接続待機
                conn, addr = s.accept()
                with conn:
                    print(f"\n[Wi-Fi] Connected by {addr}")
                    while True:
                        data = conn.recv(BUFFER_SIZE)
                        if not data:
                            break
                        
                        # 受信したデータをデコードして表示
                        text_msg = data.decode('utf-8')
                        print(f"[Wi-Fi] Received: {text_msg}")
                        
                        # LPWAへ転送
                        send_via_lpwa(text_msg)
            except KeyboardInterrupt:
                print("\nStopping Server...")
                break
            except Exception as e:
                print(f"Error in server loop: {e}")

if __name__ == "__main__":
    start_server()