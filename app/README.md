# Native PS5 dashboard app

The icon runs a native executable. It checks the local daemon and, only when
positively stopped, sends the installed ELF to loopback elfldr. It opens the
browser after a valid readiness response. A healthy daemon is reused; an unknown
listener, unreadable marker or incomplete process inventory blocks a new send.
The app does not restore saves or change settings.

The jailbreak, kernel-access services and elfldr on `127.0.0.1:9021` must already
be active. The app cannot start them or make an unsupported firmware compatible.

```sh
gmake app
gmake dashboard-files
```

These commands build locally. `app/eboot.elf` is a native entry point, not a
loader payload. The installable file is `build/dashboard/TOST10001/eboot.bin`.
The daemon remains `/data/tostonsync/tostonsync.elf`. The app reads the `.port`
marker, defaulting to 1993 only when absent; an unreadable or invalid marker does
not authorize starting another daemon.

See [dashboard/README.md](../dashboard/README.md) before any installation.
Host checks and fake-SELF conversion do not establish native permissions or
physical firmware compatibility. The launcher lock coordinates cooperating
clicks, not an unrelated simultaneous deployment. Do not run another installer
or daemon sender concurrently. No PKG is fabricated without compatible tooling.
