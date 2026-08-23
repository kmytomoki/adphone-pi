import RPi.GPIO as GPIO  # 変更

M0_pin = 5
M1_pin = 6

GPIO.setmode(GPIO.BCM)    # 変更（BCMモードがwiringPiSetupGpioに相当）
GPIO.setwarnings(False)

# set output
GPIO.setup(M0_pin, GPIO.OUT)  # 変更
GPIO.setup(M1_pin, GPIO.OUT)  # 変更

# set M0=high,M1=high
GPIO.output(M0_pin, GPIO.HIGH) # 変更
GPIO.output(M1_pin, GPIO.HIGH) # 変更
