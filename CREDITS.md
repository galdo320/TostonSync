# Credits

TostónSync uses open-source PS5 tooling and separately implemented platform
adapters. The dependency inventory and exact license notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

| Project | Contributors | Use |
| --- | --- | --- |
| [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) | John Törnblom and contributors | Pinned v0.43 compiler wrapper, CRT, libc, kernel and platform bindings. |
| [Monocypher](https://monocypher.org/) | Loup Vaillant and contributors | Ed25519 release verification and the Mac signing helper. |
| [QR-Code-generator](https://github.com/nayuki/QR-Code-generator) | Project Nayuki | OAuth QR rendering. |
| [puff](https://github.com/madler/zlib/tree/develop/contrib/puff) | Mark Adler | Standard DEFLATE extraction. |
| [SQLite](https://sqlite.org/) | SQLite contributors | The bundled 3.46.0 amalgamation. |

## Optional public title metadata

[PlayStation-Titles](https://github.com/andshrew/PlayStation-Titles), by andshrew,
is an optional name/region source (`main/PS5_Titles.tsv`). Its downloaded cache
contains no save data or accounts. It is not an official Sony API or a guarantee
of save compatibility. Its MIT notice is retained for cached copies:

```text
MIT License

Copyright (c) 2022 andshrew

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Platform references and independent implementation

The following references informed behavior research; their code and assets are
not incorporated: [PS5-Lapy-JB-Daemon](https://github.com/ArkSama/PS5-Lapy-JB-Daemon)
(Lapy / ArkSama), [PS5-Save-Mounter](https://github.com/n0llptr/PS5-Save-Mounter)
(n0llptr), [PS5-Xplorer](https://github.com/idlesauce/PS5-Xplorer) (idlesauce),
[ps5-ezremote-client](https://github.com/cy33hc/ps5-ezremote-client) (cy33hc),
PS5 Payload Manager 0.5.2, ShadowMount+ and PSCloud. Behavior research does not
imply permission to copy an unlicensed project's source. PSCloud source,
comments, structure, artwork and branding are not distributed here.

Public savedata/PFS contracts were checked against ps5-dev material, `sd_util`
and SDK exports: `/dev/pfsmgr`, ioctl `0xc0845302`, the 0x60-byte sealed key,
the key at offset 0x800 in `savedata0.bin`, save-mount option layouts and
`libSceFsInternalForVsh` exports. These constants are platform interface facts;
the wrapper implementation is project code. The native bootstrap follows the
SDK `samples/install_app` example, with GPL-3.0-or-later attribution in source.
The retained host kernel-dispatch fixture preserves its upstream GPL notice.

Console HTTP/SSL, networking, system-service, savedata and kernel libraries are
runtime imports; their proprietary binaries are not bundled. Jailbreak tools,
kstuff, elfldr and console FTP servers are separate prerequisites and are not
included. No game artwork or saves are shipped; the application may cache
metadata/artwork obtained explicitly through its supported providers.

Embedded CA provenance and issuer grants are documented in
[certificate terms](docs/CERTIFICATE-TERMS.md). The application name and logo
belong to the project; the proposed fork-branding policy remains a draft.
