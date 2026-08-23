import socket
import serial
import hexdump
import time

# --- LPWA設定 ---
SERIAL_PORT = "/dev/ttyS0"
BAUD_RATE = 9600
FIXED_MODE = True
TARGET_ADDRESS = 0x0000  # 送信先ラズパイ2のアドレス
TARGET_CHANNEL = 0x00    # 送信先チャンネル

# --- Wi-Fi設定 ---
WIFI_PORT = 50000

def send_to_lpwa(text):
    """ E220-900JPの仕様に合わせた送信処理 """
    # 1. ヘッダ生成 (Fixed Modeの場合: アドレスH, アドレスL, チャネル)
    if FIXED_MODE:
        t_addr_H = (TARGET_ADDRESS >> 8) & 0xFF
        t_addr_L = TARGET_ADDRESS & 0xFF
        payload = bytes([t_addr_H, t_addr_L, TARGET_CHANNEL])
    else:
        payload = bytes([])

    # 2. データ結合
    payload += text.encode('utf-8')

    print("\n--- LPWA Send Data ---")
    hexdump.hexdump(payload)

    try:
        with serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=None) as ser:
            # 送信バッファが空になるまで待機
            while ser.out_waiting > 0: pass
            ser.write(payload)
            ser.flush()
            print("✅ LPWA転送完了")
    except Exception as e:
        print(f"❌ シリアルエラー: {e}")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', WIFI_PORT))
    server.listen(1)
    print(f"RPi1 Waiting for Wi-Fi on port {WIFI_PORT}...")

    try:
        while True:
            conn, addr = server.accept()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data: break
                    
                    received_text = data.decode('utf-8')
                    print(f"📩 Wi-Fi受信: {received_text}")
                    
                    # LPWA転送実行
                    send_to_lpwa(received_text)
    except KeyboardInterrupt:
        print("停止します")
    finally:
        server.close()

if __name__ == "__main__":
    main()
