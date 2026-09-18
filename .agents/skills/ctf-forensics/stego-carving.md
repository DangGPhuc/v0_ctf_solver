# Steganography & File Carving (skills/forensics/stego-carving.md)

## 1. Fast Triage Pipeline
```bash
# 1. File Metadata & Strings
file target.png
exiftool target.png
strings -n 8 target.png | grep -iE "flag|ctf"

# 2. Automated File Carving
binwalk -Me target.png
foremost -i target.png -o ./carved

# 3. PNG LSB Analysis
zsteg -a target.png
```

---

## 2. PNG Chunk Repair (IHDR CRC / Dimensions)
If PNG image has truncated height or CRC error:
```python
import zlib
import struct

# Fix PNG Height via CRC32 brute-force
with open('corrupt.png', 'rb') as f:
    data = bytearray(f.read())

crc_target = struct.unpack('>I', data[29:33])[0]

for h in range(1, 4000):
    for w in range(1, 4000):
        test_ihdr = data[12:16] + struct.pack('>II', w, h) + data[24:29]
        if zlib.crc32(test_ihdr) == crc_target:
            print(f"[+] Found Dimensions: Width={w}, Height={h}")
            data[16:20] = struct.pack('>I', w)
            data[20:24] = struct.pack('>I', h)
            with open('repaired.png', 'wb') as out:
                out.write(data)
            exit(0)
```

---

## 3. Audio Steganography
- **Sonic Visualiser**: Open audio file $\rightarrow$ Add Spectrogram (`Layer -> Add Spectrogram`).
- **DTMF Tones**: Decode telephone dial tones with `multimon-ng` or `dtmf-decoder`.
- **Morse Code**: Decode audio beeps via audio spectrum or python thresholding.
