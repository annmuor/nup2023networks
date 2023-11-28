import proto


def test_gen_key():
    assert len(proto.gen_crypto_key()) == 8


def test_encrypt_decrypt():
    data = b'\x01\x02\x03\x04\x05'
    key = proto.gen_crypto_key()
    enc_data = proto.encrypt_bytes(data, key)
    dec_data = proto.encrypt_bytes(enc_data, key)
    assert dec_data[:5] == data


def test_checksum():
    # https://en.wikipedia.org/wiki/Internet_checksum
    data = b'\x45\x00\x00\x73\x00\x00\x40\x00\x40\x11\xb8\x61\xc0\xa8\x00\x01\xc0\xa8\x00\xc7'
    assert len(data) == 20
    sum = proto.internet_checksum(data)
    assert sum == 0
    data = b'\x45\x00\x00\x73\x00\x00\x40\x00\x40\x11\x00\x00\xc0\xa8\x00\x01\xc0\xa8\x00\xc7'
    assert len(data) == 20
    sum = proto.internet_checksum(data)
    assert sum == 0xb861


def test_eth_header():
    me = b'\xbc\x54\x2f\xcb\x7b\x2c'
    gw = b'\xe0\x1c\xfc\x96\xd8\x8c'
    ex = b'\xbc\x54\x2f\xcb\x7b\x2c\xe0\x1c\xfc\x96\xd8\x8c\x08\x00'
    assert len(ex) == 14
    assert proto.pack_eth_header(gw, me, 0x0800) == ex


def test_ip_header():
    me = '192.168.0.144'
    remote = '185.12.215.5'
    ex = b'\x45\x00\x00\x8b\x57\xdc\x40\x00\x40\x11\x91\x3b\xc0\xa8\x00\x90\xb9\x0c\xd7\x05'
    assert len(ex) == 20
    assert proto.internet_checksum(ex) == 0
    _src, _dst, _proto, _len = proto.unpack_ip_header(header=ex)
    assert _src == me
    assert _dst == remote
    assert _proto == 0x11
    assert _len == 139
    data = proto.pack_ip_header(me, remote, 0x11, 139)
    assert proto.internet_checksum(data) == 0
    _src, _dst, _proto, _len = proto.unpack_ip_header(header=data)
    assert _src == me
    assert _dst == remote
    assert _proto == 0x11
    assert _len == 139


def test_icmp_header():
    data = b'\x08\x00\x12\x7e\x00\x21\x00\x0b\x03\x57\x66\x65\x00\x00\x00\x00\xb7\xc6\x05\x00\x00\x00\x00\x00\x10\x11' \
           b'\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b' \
           b'\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37'
    icmp_type, icmp_code, _id, seq = proto.unpack_icmp_header(data[:24])
    assert icmp_type == 8
    assert icmp_code == 0
    assert _id == 33
    assert seq == 11
    data = proto.pack_icmp(0, 0, _id, seq, data[24:])
    icmp_type, icmp_code, _id, seq = proto.unpack_icmp_header(data[:24])
    assert icmp_type == 0
    assert icmp_code == 0
    assert _id == 33
    assert seq == 11


def test_netmask_to_prefix():
    assert proto.netmask_to_prefix('255.255.255.255') == 32
    assert proto.netmask_to_prefix('255.255.255.0') == 24
    assert proto.netmask_to_prefix('255.255.0.0') == 16
    assert proto.netmask_to_prefix('255.255.255.252') == 30
