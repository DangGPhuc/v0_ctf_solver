# Disk & Artifact Forensics (skills/forensics/disk-and-artifacts.md)

## 1. Filesystem Image Analysis
- Mount raw disk image:
  ```bash
  losetup -Pf disk.img
  mount /dev/loop0p1 /mnt/disk -o ro
  ```
- Carve deleted files with Sleuth Kit:
  ```bash
  fls -r -p disk.img
  icat disk.img <inode_number> > recovered_file
  ```

---

## 2. Windows Artifacts
- **EVTX Event Logs**: Analyze with `python3 -m evtx_dump Security.evtx | grep -i ...`.
- **Registry Hives (SAM, SYSTEM, SOFTWARE)**: Extract credentials using `secretsdump.py -sam SAM -system SYSTEM LOCAL`.
- **Browser History**: Query `places.sqlite` (Firefox) or `History` (Chrome) with `sqlite3`.
