# Usage

```
python lithtech_rez.py GAME.REZ                          # extract to ./GAME/ (default, as before)
python lithtech_rez.py -v GAME.REZ                       # version and metadata
python lithtech_rez.py -p FOLDER                         # pack to ./FOLDER.rez, format v1
python lithtech_rez.py -p FOLDER -o OUT.rez              # pack to a chosen file
python lithtech_rez.py -p FOLDER -clonev SRC.rez         # pack in SRC's format, no copy-pasting
```

---

# More details :
* **-clonev** copies the source’s header bytes exactly, so framing, file type, title, version, and any key or unknown bytes all carry over. It then recomputes only the offsets and sizes that depend on the new contents.
* **-v** reports the REZ version, header variant, file type, title, root directory location, timestamps, largest-name fields, and counts of directories, resources, and extensions.
* **Packing** writes files in a deterministic order and renames any .rez it finds inside the folder being packed. It writes to a temp file and renames it into place only after a verification pass. That pass re-reads the archive and checks every resource’s position, size, and CRC32.

# Notes :
* Without -clonev, new archives are always version 1. Version 2 and encoded archives can only be produced by cloning one, since I couldn’t confirm the encoded key scheme.
* Resource IDs are assigned sequentially from 10000000, as in the sample. Original IDs aren’t kept, so repacking an extracted archive won’t reproduce the original’s IDs.
* Symlinks are skipped with a warning.
* Names that can’t be written as cp1252 are written lossily, with a warning ofc :)

---

* RezMgr Copyright (C) 1995 MONOLITH INC.

<div align="center">

<b>Lithtech RezMgr reverse engineered by </b> <img src="https://img.shields.io/github/owner/Lithtech_rez_extractor?label=Owner&style=flat-square" alt="Repo Owner" />

</div>
