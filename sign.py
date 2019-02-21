#!/usr/bin/env python

import sys
import struct
import hashlib
import serial

ser = serial.Serial('/dev/tty.usbserial-AH01SKWE')

connect = [126, 256-96, 0, 4, 0, 1, 16, 0, 0, 0, 0, 0, 0, 256-2, 256-1, 91, 256-17, 1, 0, 0, 0, 126]
poweron = [126, 256-96, 0, 4, 0, 1, 16, 0, 0, 0, 0, 0, 0, 256-3, 256-1, 92, 256-17, 2, 0, 0, 0, 126]
bytes = ser.write(connect)
print "Written bytes = " + str(bytes)
bytes = ser.read()
print "Read bytes = " + str(bytes)
bytes = ser.write(poweron)
print "Written bytes = " + str(bytes)
bytes = ser.read()
print "Read bytes = " + str(bytes)

# command = 1 # 1 - card power on; 2 - card power off
# seq = 1

# data = bytearray(255)
# data[0] = 32
# data_len = 16

# # command
# data[17] = command >> 8
# data[16] = command & 0xff
# data[2] = 4
# data_len += 4

# # sequence
# data[7] = ((seq & 0xFF000000) >> 24)
# data[6] = ((seq & 0xFF0000) >> 16)
# data[5] = ((seq & 0xFF00) >> 8)
# data[4] = ( seq & 0xFF )