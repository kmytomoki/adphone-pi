import RPi.GPIO as GPIO

# ピン番号の定義
M0_pin = 5
M1_pin = 6

# GPIOの設定（BCMモード：ラズパイの信号名で指定）
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)

# 出力ピンとして設定
GPIO.setup(M0_pin, GPIO.OUT)
GPIO.setup(M1_pin, GPIO.OUT)

# M0=low, M1=low に設定
GPIO.output(M0_pin, GPIO.LOW)
GPIO.output(M1_pin, GPIO.LOW)

print("Mode 0: Normal mode set (M0=0, M1=0)")
