# Catalog after Restart

The catalog is an in-memory observation, not a backup index persisted as Restore
authority. Restart clears it. A pure catalog GET returns observation unavailable
when no applicable snapshot exists; an empty UI at that point does not establish
that a destination is empty or that a backup was deleted.

Navigation, GET and opening a Restore menu must not scan, renew credentials,
prepare a review or enqueue work. The explicit **Scan backups** action uses
`POST /api/backups/catalog`. Its USB branch reads the destination; its Drive
branch may refresh and persist the OAuth session. Reports preserve independent
complete/partial/unavailable states per destination.

Only a matching current card can enter Verify. Verify binds the exact backup;
the mandatory final confirmation then sends Restore for that reviewed identity.
No automatic Scan is hidden in the Restore button, and no stale pre-Restart
review substitutes for current authority. Unknown stays unavailable rather than
being promoted to an empty catalog or verified backup.

This is the minimum contract retained in .272. Better Scan progress/results and
clearer distinctions between never scanned and incomplete scans are .273 UI work.
