# How .rez works

All three projects describe the same LithTech format:

* **Header:** a 127-byte framed signature (CRLF-delimited file type and title, then an EOF byte). After that come a version number and the root directory’s position and size.
* **Directories:** each directory is a flat block of entries. Every entry starts with a 16-byte header (type, position, size, time). A directory entry carries a name and points to its child block. A resource entry carries an ID, a 4-byte reversed file extension, a key count, a name, a description, and a key array.
* **File data:** stored raw at the position and size given in the resource entry.

# What the script does

* **All three header variants:** the plain version-1 header, the version-2 layout, and the encoded 0x2A header.
* **Speed:** it memory-maps the archive and writes files from up to 8 threads. A 20,000-file, 195 MB archive extracts in about 2 seconds. Output is identical with 1 or 8 threads.
* **Safety:** every offset and size is bounds-checked, and directory cycles are detected. Names are sanitized for Windows, macOS, and Linux: illegal characters are replaced, reserved names like CON are prefixed, and .. can’t escape the output folder.
* **Collisions:** when two files would land on the same path (including case-only differences, or a file sharing a folder’s name), the second one is renamed name (2).ext instead of being overwritten.
* **Damage:** a corrupt directory block is reported, the readable parts are still extracted, and the exit code is non-zero.

# Usage
```
python rez_extract.py GAME.REZ              # -> ./GAME/
python rez_extract.py GAME.REZ -o out       # -> out/GAME/
python rez_extract.py *.REZ --list          # list contents only
```
