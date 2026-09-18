# Network PCAP Analysis Playbook (skills/forensics/pcap-analysis.md)

## 1. Fast `tshark` Command Reference

### 1.1 Export HTTP Objects & Transferred Files
```bash
tshark -r capture.pcap --export-objects "http,./exported_http"
tshark -r capture.pcap --export-objects "imf,./exported_mail"
tshark -r capture.pcap --export-objects "smb,./exported_smb"
```

### 1.2 Extract Credentials & Form Data
```bash
tshark -r capture.pcap -Y 'http.request.method == "POST"' -T fields -e http.host -e http.request.uri -e urlencoded-form.key -e urlencoded-form.value
```

### 1.3 DNS Exfiltration Data Extraction
```bash
tshark -r capture.pcap -Y "dns.flags.response == 0 and dns.qry.name contains 'ctf'" -T fields -e dns.qry.name | cut -d'.' -f1 | tr -d '\n' | xxd -r -p
```

### 1.4 USB HID Keyboard Keystroke Reconstruction
Extract leftover capture data from USB packets:
```bash
tshark -r capture.pcap -Y 'usb.capdata' -T fields -e usb.capdata > keystrokes.txt
```
Python mapping script converts HID scancodes (e.g. `0x04` $\rightarrow$ `'a'`) to plaintext.
