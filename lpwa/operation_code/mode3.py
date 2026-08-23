import wiringpi as w

M0_pin = 5
M1_pin = 6

w.wiringPiSetupGpio()

# set output
w.pinMode(M0_pin, 1)
w.pinMode(M1_pin, 1)

# set M0=high,M1=high
w.digitalWrite(M0_pin, 1)
w.digitalWrite(M1_pin, 1)
