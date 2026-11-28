"""Original HONG AI monogram assets. Standard library only; no upstream logo."""
import argparse
import pathlib
import struct
import zlib


def png(size):
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            u, v = (x + 0.5) / size, (y + 0.5) / size
            dx, dy = max(abs(u - .5) - .29, 0), max(abs(v - .5) - .29, 0)
            inside = dx * dx + dy * dy <= .18 ** 2
            if not inside:
                pixel = (0, 0, 0, 0)
            elif (.25 <= u <= .39 and .24 <= v <= .76) or (.61 <= u <= .75 and .24 <= v <= .76) or (.36 <= u <= .64 and .43 <= v <= .57):
                pixel = (255, 255, 255, 255)
            else:
                gradient = (u + v) / 2
                pixel = (int(195 - 37 * gradient), int(25 - 8 * gradient), int(55 + 7 * gradient), 255)
            row.extend(pixel)
        rows.append(bytes(row))
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(b''.join(rows), 9)) + chunk(b'IEND', b'')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    out = pathlib.Path(args.output).resolve()
    if not out.is_absolute():
        raise SystemExit('ABSOLUTE_OUTPUT_REQUIRED')
    out.mkdir(parents=True, exist_ok=True)
    p256, p512 = png(256), png(512)
    (out / 'HONGAI.png').write_bytes(p512)
    ico = struct.pack('<HHH', 0, 1, 1) + struct.pack('<BBBBHHII', 0, 0, 0, 0, 1, 32, len(p256), 22) + p256
    (out / 'HONGAI.ico').write_bytes(ico)
    elements = b'ic08' + struct.pack('>I', len(p256) + 8) + p256 + b'ic09' + struct.pack('>I', len(p512) + 8) + p512
    (out / 'HONGAI.icns').write_bytes(b'icns' + struct.pack('>I', len(elements) + 8) + elements)


if __name__ == '__main__':
    main()
