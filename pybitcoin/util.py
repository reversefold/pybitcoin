from builtins import range
import binascii


def visual(bytes):
    return ' '.join(binascii.hexlify(c) for c in bytes).upper()


def visual2(msg):
    ii = [4, 12, 4, 4,
          4, 8, 8, 26, 26, 8, 16, 4]
    bytes = msg.bytes
    return '\n'.join(
        visual(b)
        for b in (
                bytes[sum(ii[:i]):sum(ii[:i]) + ii[i]]
                for i in range(len(ii))
        )
    ).upper()
