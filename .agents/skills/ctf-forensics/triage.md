# Forensics Operational Triage

## 1. Artifact Classification
- Network Captures: PCAP / PCAPNG files.
- Memory Images: Raw RAM dumps, crash dumps (Windows, Linux).
- Disk Images: Raw dd, E01, VMDK, ext4, NTFS, LittleFS.
- Media Files: PNG, JPG, WAV, MP3, MP4 (steganography).

## 2. File Integrity & Header Verification
- Check magic bytes with file and hexdump to detect damaged headers or embedded payloads.
