# third_party/

Single-file vendored dependencies used by TostónSync.

| File | Source | License |
|---|---|---|
| `qrcodegen.h` / `qrcodegen.c` | Project Nayuki, QR-Code-generator `c/` directory | MIT |
| `puff.h` / `puff.c` | Mark Adler, zlib `contrib/puff`, version 2.3 | zlib |
| `sqlite3.h` / `sqlite3.c` | SQLite amalgamation 3.46.0 | Public domain |

The reviewed QR generator implementation and header are included. Build these
shipped bytes, without downloading replacements from a mutable upstream branch.
For recovery, restore both files from the same TostónSync source tag. See `VENDOR_QRCODEGEN.txt`.

Exact provenance for the vendored decompressor and SQLite amalgamation is kept
in `VENDOR_PUFF.txt` and `VENDOR_SQLITE.txt`. Their upstream license notices
remain intact in the source files.
