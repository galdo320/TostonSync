# Third-party notices

This inventory covers source distributed in this repository and dependencies
linked into the daemon or launcher. It does not relicense third-party work.
Console system libraries are resolved on the PS5; their proprietary binaries
are not distributed here.

| Component | Version / use | License | Source / notices |
| --- | --- | --- | --- |
| ps5-payload-sdk | v0.43 payload CRT, kernel bindings and libc/runtime objects | GPL-3.0-or-later, with the individual MIT, BSD-3-Clause, ISC and Apache-2.0 WITH LLVM-exception terms below | Pinned source paths and hashes: [SDK-SOURCES.json](docs/SDK-SOURCES.json); exact permissive notices: [SDK-LICENSES.md](docs/SDK-LICENSES.md); full GPL: [LICENSE](LICENSE) |
| Monocypher | 4.0.3, Ed25519 | BSD-2-Clause OR CC0-1.0; this project uses the BSD option | `src/third_party/monocypher/`, [license](docs/MONOCYPHER_LICENSE.md) |
| SQLite | 3.46.0 amalgamation | Public domain | `src/third_party/sqlite3.c`, `sqlite3.h`, `VENDOR_SQLITE.txt` |
| puff | 2.3 DEFLATE reader | zlib | `src/third_party/puff.c`, `puff.h`, `VENDOR_PUFF.txt` |
| QR-Code-generator / qrcodegen | Project Nayuki C implementation | MIT | `src/third_party/qrcodegen.c`, `qrcodegen.h`, `VENDOR_QRCODEGEN.txt` |
| PlayStation-Titles | Optional downloaded display metadata; no game data shipped | MIT | [CREDITS.md](CREDITS.md), `src/title_catalog.c` |
| Google, ISRG and Sectigo certificates | Unmodified embedded HTTPS certificates | Issuer permission to reproduce and distribute complete certificates; not a blanket code license | [Certificate terms](docs/CERTIFICATE-TERMS.md), `certs/` |

## SDK and corresponding source

The pinned source commit is `d9c9519116944a7f1c22d262012c53b80b3520b7`.
It is preserved in the public [SDK fork](https://github.com/galdo320/TostonSync-sdk)
under the annotated [`tostonsync-sdk-v0.43` tag](https://github.com/galdo320/TostonSync-sdk/tree/tostonsync-sdk-v0.43).
The [pinned source](https://github.com/galdo320/TostonSync-sdk/tree/d9c9519116944a7f1c22d262012c53b80b3520b7)
is available independently of the TostónSync release assets.
The CRT and kernel headers identify John Törnblom and explicitly grant GPL
version 3 or, at your option, any later version. They are also preserved locally
at `build/sdk-download/crt-v0.43.c` and `kernel-v0.43.c`; those generated files
are not public source inputs. This is not a claim that every SDK file is GPL.

The linked runtime includes MIT `gmtime.c` / `strcasecmp.c`, BSD-3-Clause
`assert.c` / `mktemp.c`, ISC `arc4random.c`, and Apache-2.0 WITH LLVM-exception
`emutls.c`. Other mapped CRT/runtime components carry GPL-3.0-or-later notices.
[SDK-SOURCES.json](docs/SDK-SOURCES.json) records the exact per-file evidence;
[BUILD.md](BUILD.md) identifies both pinned source and binary SDK archives.
The launcher's native `_start` is implemented in `app/eboot.c`, adapted from
SDK `samples/install_app/eboot.c` (John Törnblom, GPL-3.0-or-later). It uses
the SDK's `samples/install_app/eboot.x` linker script without the payload CRT.
Separate provenance and build-input mappings in SDK-SOURCES.json cover that
sample, both linker scripts and the compiler/linker wrappers; they are not
additional linked daemon runtime units.
Optional SDK C++/unwind/UFS libraries are not linked by this C build.

Runtime imports of `libkernel_web`, `libSceLibcInternal`, `libSceHttp`, `libSceHttp2`, `libSceSsl`,
`libSceNet`, `libSceNetCtl`, `libSceSystemService`, `libSceUserService`,
`libSceFsInternalForVsh`, `libSceRandom` and pthread services refer to console
libraries, not bundled implementations. LLVM, Python, Node.js, Playwright and
the browser are build/test requirements, not release assets.

## Research and branding

PSCloud was consulted for behavior research. No PSCloud code, artwork or branding
is included. TostónSync implementations and tests were written independently.
See [CREDITS.md](CREDITS.md) and the approved
[name and logo policy](README.md#name-and-logo), which does not alter third-party licenses.

## Monocypher — BSD option

Copyright (c) 2017-2023, Loup Vaillant
Copyright (c) 2017-2019, Michael Savage
Copyright (c) 2017-2023, Fabio Scotoni
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## QR-Code-generator — MIT

QR Code generator library (C)

Copyright (c) Project Nayuki. (MIT License)
https://www.nayuki.io/page/qr-code-generator-library

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:
- The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
- The Software is provided "as is", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose and noninfringement. In no event shall the
authors or copyright holders be liable for any claim, damages or other
liability, whether in an action of contract, tort or otherwise, arising from,
out of or in connection with the Software or the use or other dealings in the
Software.


## puff — zlib

Copyright (C) 2002-2013 Mark Adler, all rights reserved
version 2.3, 21 Jan 2013

This software is provided 'as-is', without any express or implied
warranty.  In no event will the author be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
claim that you wrote the original software. If you use this software
in a product, an acknowledgment in the product documentation would be
appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.

Mark Adler    madler@alumni.caltech.edu


## SQLite — public-domain dedication


2001 September 15

The author disclaims copyright to this source code.  In place of
a legal notice, here is a blessing:

May you do good and not evil.
May you find forgiveness for yourself and forgive others.
May you share freely, never taking more than you give.
