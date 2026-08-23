import serial
import time
import argparse
import hexdump

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("serial_port", help="Serial port path (e.g. /dev/ttyS0)")
    parser.add_argument("-b", "--baud", default="9600", help="Baud rate (default: 9600)")
    parser.add_argument("-m", "--model", default="E220-900JP", help="Module model")
    parser.add_argument("--rssi", action="store_true", help="Enable RSSI display")
    args = parser.parse_args()
    return args

def main():
    args = get_args()
    
    if args.model == "E220-900JP":
        print(f"serial port: {args.serial_port}")
        print("receive waiting...")
        
        # timeoutを設定して読み込み時のブロッキングを防止
        try:
            with serial.Serial(args.serial_port, int(args.baud), timeout=0.1) as ser:
                # 起動時に溜まっている古いバッファをクリアしてノイズを除去
                ser.reset_input_buffer()
                
                while True:
                    # データが届いているか確認
                    if ser.in_waiting > 0:
                        # 届いているデータを一度読み込む
                        payload = ser.read(ser.in_waiting)
                        
                        # LPWAのパケット分割に備え、少し待機して残りを一気に読み込む
                        while True:
                            time.sleep(0.05)
                            if ser.in_waiting > 0:
                                payload += ser.read(ser.in_waiting)
                            else:
                                break

                        # 受信データの出力
                        print("recv data hex dump:")
                        hexdump.hexdump(payload)
                        
                        # RSSI（電波強度）の計算と表示
                        if args.rssi and len(payload) > 0:
                            # 最後の1バイトをRSSI値として処理
                            rssi_value = int(payload[-1])
                            rssi_dBm = rssi_value - 256
                            print(f"RSSI: {rssi_dBm} dBm")
                        
                        print("RECEIVED\n")
                        
                        # 次の受信のためにpayloadを明示的にクリア（ループの先頭で再定義されるが安全のため）
                        payload = bytes()
                    
                    # CPU負荷を抑えるための待機
                    time.sleep(0.01)
                    
        except KeyboardInterrupt:
            print("\nStopped by user")
        except Exception as e:
            print(f"\nError: {e}")
            
    else:
        print("INVALID")

if __name__ == "__main__":
    main()
