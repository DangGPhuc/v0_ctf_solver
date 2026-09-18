---
name: ctf-forensics
description: |
  CTF Forensics Playbook Suite.
  Covers network packet captures (tshark, TLS decryption, USB HID analysis), Volatility 3 memory dump investigation,
  Steganography (zsteg, binwalk, PNG chunk repair, audio spectrograms), and disk filesystem artifact recovery.
---

# CTF Forensics Suite

## Playbooks in this Module
- [pcap-analysis.md](v0_ctf_knowledge/references/forensics/pcap-analysis.md): `tshark` stream filtering, HTTP/FTP object exports, USB HID keyboard/mouse stroke decoding, ICMP/DNS exfiltration.
- [memory-volatility.md](v0_ctf_knowledge/references/forensics/memory-volatility.md): Volatility 3 Linux and Windows plugins (`pslist`, `malfind`, `dumpfiles`, `hashdump`, `netscan`).
- [stego-carving.md](v0_ctf_knowledge/references/forensics/stego-carving.md): File carving (`binwalk`, `foremost`), PNG chunk repair (IHDR CRC/dimensions), `zsteg` LSB planes, audio spectrograms.
- [disk-and-artifacts.md](v0_ctf_knowledge/references/forensics/disk-and-artifacts.md): EXT4/NTFS carving, Windows Registry & EVTX logs, SQLite browser history extraction.
