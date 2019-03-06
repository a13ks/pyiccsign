    arr1 = bytearray.fromhex('7ea0010000011000000000000000005eee7e200004000110000000000000feffdbddef010000007e')
    pkt1 = Packet.from_buffer(translated(arr1))
    print "pkt1 checksum = ", pkt1.validate_checksum()

    arr2 = [0x20, 0x01, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    pkt2 = Packet.from_buffer(arr2)
    pkt2.set_checksum()
    print "pkt2 checksum = ", pkt2.validate_checksum()

    return

    arr3 = bytearray.fromhex('200004000110000000000000feffdbddef01000000')
    pkt3 = Packet.from_buffer(translated(arr3))
    print "pkt3 checksum = ", pkt3.validate_checksum()

    # arr4 = bytearray.fromhex('20 00 04 00 01 10 00 00 00 00 00 00 fe ff db dd ef 01 00 00 00')
    pkt4 = Packet.from_buffer([32, 0, 4, 0, 1, 16, 0, 0, 0, 0, 0, 0, -2, -1, -37, -17, 1, 0, 0, 0])
    print "pkt4 checksum = ", pkt4.validate_checksum()

    return
    

    data = [32, 0, 20, 0, 4, 16, 0, 0, 0, 0, 0, 0, 109, -76, 0, 0, 4, 0, 0, 0, 0, -92, 4, 0, 11, 78, 69, 87, 80, 79, 83, 45, 67, 65, 82, 68]
    csum1 = Packet.checksum(data, 0, 16)
    csum2 = Packet.checksum(data, 0, len(data))
    print csum1, csum2
    return

    pkt = Packet()
    get_seq()
    # pkt.set_restart_flag()
    pkt.set_sequence(get_seq())
    pkt.set_command(2)
    pkt.set_checksum()
    data = pkt.get_bytes()
    print binascii.hexlify(data)
    translated_data = translated(data)
    print binascii.hexlify(translated_data)
    print binascii.hexlify(restore_translated(translated_data))
    return

    connect = [126, 256-96, 0, 4, 0, 1, 16, 0, 0, 0, 0, 0, 0, 256-2, 256-1, 91, 256-17, 1, 0, 0, 0, 126]
    poweron = [126, 256-96, 0, 4, 0, 1, 16, 0, 0, 0, 0, 0, 0, 256-3, 256-1, 92, 256-17, 2, 0, 0, 0, 126]
    ser = serial.Serial('/dev/tty.usbserial-AH01SKWE', baudrate=115200)
    bytes = ser.write(connect)
    ser.flush()
    print "Written bytes = " + str(bytes)
    bytes = ser.read()
    print "More bytes = ", str(ser.in_waiting)
    print "Read bytes = " + str(len(bytes))
    bytes = ser.write(poweron)
    ser.flush()
    print "Written bytes = " + str(bytes)
    bytes = ser.read()
    print "Read bytes = " + str(len(bytes))
    exit(0)