# Forensics Operational Workflow

1. Header & Metadata Analysis: Inspect EXIF tags, file headers, packet summaries.
2. Data Carving & Stream Extraction:
   - Network: Reassemble TCP streams, extract HTTP objects, carve USB HID keystrokes.
   - Memory: Run Volatility 3 plugins (pslist, pstree, filescan, dumpfiles).
   - Stego: Scan bit planes (zsteg), frequency spectrum (sox spectrogram), LSB extraction.
3. Artifact Analysis: Examine extracted files, scripts, or network packets for embedded flags.
