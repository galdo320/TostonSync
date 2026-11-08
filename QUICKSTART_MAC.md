# TostónSync: Mac quick start

The ELF runs on a jailbroken PS5, not on macOS. The Mac verifies, builds and
transfers it. Never send a payload or install an icon without checking the
intended console and closing games first.

## Use a signed Release

Download the matching versioned ELF, `update-manifest.json` and
`update-manifest.sig` into one folder. Run the repository launcher:

```sh
./tools/start-tostonsync.command /path/to/release-folder
```

The launcher verifies the signature and exact ELF, asks for the console address
and reuses a responding daemon. Only a refused connection permits its one send;
an uncertain result stops. It does not perform a Restore or replace saved games.
The PS5 must already have its jailbreak and ELF loader running.

Open `http://<ps5-ip>:1993/` from the Mac. On the PS5 itself the local address is
`http://127.0.0.1:1993/`. The loopback address on the Mac points to the Mac, not
the console. Enable an access code for external devices and keep the UI on a
trusted LAN; see [SECURITY.md](SECURITY.md).

When TostónSync is already running, use **Settings → Update from a file**, check
the saved version, and choose Restart separately. Do not repeat an uncertain
save or restart. The optional dashboard icon is a separate installation;
[dashboard documentation](dashboard/README.md) describes its limits.

## Build locally

Install LLVM 18, GNU Make, Git, curl and unzip using your package manager.
For Apple Silicon with Homebrew:

```sh
brew install llvm@18 make git curl unzip
export LLVM_CONFIG=/opt/homebrew/opt/llvm@18/bin/llvm-config
```

On an Intel Mac, use `/usr/local/opt/llvm@18/bin/llvm-config` instead. In the
checkout containing the Makefile:

```sh
gmake sdk-setup
gmake check-ps5-sdk
gmake
gmake app
```

SDK setup is an explicit download with a pinned checksum. Build targets do not
contact the console. See [BUILD.md](BUILD.md) for exact source and runtime inputs.
No build success proves that a particular game or firmware is safe to restore.
