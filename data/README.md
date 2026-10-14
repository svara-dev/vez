# data/ — what the RPM and the image install

**The spec is not here.** `vez.spec` lives at `packaging/copr/svara-tools/vez/vez.spec`,
which is where every other RPM spec in this repository lives (`docs/repository.md`: "the RPM
specs built into the Svara-owned COPRs"). One home per file — a second copy here would be the
one that goes stale, and the failure would be a published package built from a spec nobody
edited.

The files that ARE here are the ones both consumers install verbatim:

| File | Installed to | By |
|---|---|---|
| `vez.conf` | `/etc/vez/vez.conf` | `build_files/40-system.sh`, and the spec |
| `vez-makecache.service`, `vez-makecache.timer` | `/usr/lib/systemd/system/` | both |
| `man/vez.1`, `man/vez.conf.5` | `/usr/share/man/` | the spec |

The image builds `vez` from source in its own builder stage and installs the binary itself
(`build_files/30-components.sh`, `40-system.sh`); it does not use the spec. The spec exists for
the COPR route — see `docs/external-repos.md`.
