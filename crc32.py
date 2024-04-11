import binascii


def crc32(text):
    buf = text
    buf = binascii.crc32(buf) & 0xFFFFFFFF
    return "%08X" % buf
