# vez

**vez** is **Svara's** package manager: a native, overlay-aware RPM package manager,
written in Rust. It is the default package manager on an installed Svara machine.

## This is a fork, and what changed

Vez is a fork of **rum**, RakuOS's package manager
(`https://gitlab.com/rakuos/packages/rakuos/rakuos-rum`, GPL-3.0-or-later). The
resolver, the repo-metadata handling, the rpmdb reader and the transaction layer are
that project's work, renamed here from `rum` to `vez`. The upstream is credited in
`NOTICE` at the repository root, and the licence is unchanged.

The fork exists for four differences, and only the first is interesting:

1. **The overlay is ours, and it is on disk.** RakuOS's overlay comes from a dracut
   module in `rakuos-core` (`90rakuos-overlay`): `/usr` is overlaid in the initramfs and
   the writable upperdir lives under `/var`. Svara has no equivalent, and `bootc
   usr-overlay` — the mechanism `dnf5 --transient` uses — is backed by **tmpfs**, so
   anything installed through it is in RAM and is discarded at reboot. That is not a
   bug; it is what the command documents, and it is why a package installed that way
   disappears when you restart. Vez supplies the missing piece: it mounts its own
   overlayfs on `/usr` with the upperdir at `/var/lib/svara/vez/overlay/upper`, and
   rebuilds it at boot from that directory. **That is the difference between an install
   that works and one that silently evaporates.**
2. **The base/extra split is read from the bootc deployment.** The base rpmdb is the
   deployment's own `/usr/share/rpm`; vez's is `/var/lib/svara/vez/rpmdb`. Presence is
   detected from `/run/ostree-booted` — a real boot — and never from `/etc/os-release`,
   which already says `ID=svara` inside an image build.
3. **No `dnf`/`dnf5` and no `zypper` shims.** Svara installs vez as the default package
   manager and leaves dnf present; nothing pretends to be dnf. A script that calls dnf
   by name still calls dnf.
4. **No install-count telemetry.** The upstream pings a vendor endpoint after a metadata
   refresh. That endpoint is not Svara's, and it is gone.

See `docs/plan/package-manager.md` in the Svara repository for the design and the
milestones, and `docs/research/rum.md` for the research the fork was based on.

## Why not just keep wrapping dnf?

Svara's `/usr` is a read-only OCI image, and everything installed on top lands in an
overlayfs upperdir under `/var`. dnf has no concept of that split: it sees one merged
view of "installed" and resolves against it exactly like a normal, non-overlay system.
That means every dnf-based install is blind to whether a dependency is already sitting
on the free, shared, image-provided base layer, versus whether it is about to duplicate
that dependency's files into the per-machine layer.

vez's whole reason to exist is closing that gap. It resolves dependencies
against an explicit base-image-vs-overlay diff, so installing a package
only ever writes to the overlay what the overlay doesn't already have. It
also refuses to ever quietly layer a base-image package into the overlay,
even if you ask for it by name (see `upgrade`/`reinstall`/`downgrade`/
`distro-sync` below): if a package only exists in the base image, vez
reports that and leaves it alone rather than duplicating it.

## Why vez ends up much lighter than dnf

vez isn't a port of dnf's code, it's a from-scratch reimplementation of the
commands and flags people actually use, built around what RakuOS needs.
There's no 1:1 porting of libdnf5's internals, so none of the weight that
comes along with carrying that over.

It also isn't reinventing rpm. dnf/libdnf reimplement a lot of what rpm
already does itself (its own transaction ordering, its own dependency
bookkeeping, its own package database handling in places), which is a
large part of why libdnf5 is such a big dependency. vez takes the opposite
approach: rpm stays the backbone. Actual transaction application (cpio
payload extraction, scriptlets, triggers, digest verification) is left to
`rpm` itself, vez only owns resolution and the base/overlay split on top
of it. Less code to carry means less code to maintain and fewer places
for RakuOS-specific bugs to hide.

vez accomplishes all of this in about 11,000 lines of Rust — a fraction of
dnf5/libdnf5's sprawling C++ codebase.

## Architecture

Still speaks plain yum/dnf-compatible repo metadata (`repomd.xml` +
`primary.xml`) and reads standard `/etc/yum.repos.d/*.repo` files. vez
changes how packages get resolved and applied, not the repo ecosystem
underneath it. Existing Svara, Fedora, Terra, RPM Fusion, etc. repos work
unmodified.

Every path below is defined once, in `crates/vez-overlay/src/paths.rs`, and
nothing else in the workspace spells a vez path out. That module is the first
thing to read when any of these needs to move.

```
crates/
  vez-core        NEVRA identity, dependency expressions, rpm's version-
                   comparison algorithm (rpmvercmp, epoch-aware EVR compare)
  vez-rpmdb        Queries an on-disk rpmdb (shells to `rpm`, doesn't
                   reimplement rpmdb's on-disk format)
  vez-overlay      The differentiator, and the part of this fork that differs most
                   from upstream. Holds `OverlayPaths`, which resolves every path
                   below, detects the mode, and decides whether a transaction needs
                   `--nodeps`. Adds `vez-overlay::paths` (the canonical path
                   constants) and `vez-overlay::mount` (the persistent overlay).
                   vez's own rpmdb is /var/lib/svara/vez/rpmdb, entirely separate
                   from the base image's own database at /usr/share/rpm; the two
                   are unioned and never merged, so there is no "is the merged view
                   stale" question to answer. Falls back to a single plain rpmdb
                   (rpm's own default) with no base/extra distinction at all
                   outside a booted system (distrobox, podman, an image build),
                   see `OverlayMode`.
  vez-overlay::mount
                   THE ONLY COPY OF THIS MECHANISM ON THE SYSTEM. Mounts overlayfs
                   on /usr with upperdir /var/lib/svara/vez/overlay/upper, refuses
                   to install while it is down, and is what `vez-overlay.service`
                   runs at boot so the layer is rebuilt from /var. bootc's own
                   `usr-overlay` is tmpfs and loses everything at reboot.
  vez-repo         Fetches/parses repomd.xml + primary.xml, loads .repo
                   INI files, caches metadata under /var/cache/vez/repos
                   (dnf5-style <id>-<hash> per-repo dirs) honoring each
                   repo's metadata_expire= before re-fetching, enables/
                   disables Copr repos (vez-repo::copr), and loads
                   /etc/vez/vez.conf. Its actual transfers (vez-repo::net)
                   go through vez-librepo.
  vez-librepo      FFI bindings to librepo (the same C library dnf5 uses
                   for repo metadata/package downloading); backs every
                   HTTP(S) transfer vez-repo::net makes
  vez-resolver     Dependency resolver backed by vez-solv/libsolv; consults
                   vez-overlay before ever considering a repo candidate for
                   a dependency
  vez-solv         FFI bindings to libsolv; builds a Pool from vez's
                   base/extra/candidate package data and drives the solve
  vez-transaction  Downloads resolved packages, applies them via `rpm -U`
                   / `rpm -e` against vez's own extra dbpath (or rpm's
                   default dbpath outside a booted system), plus
                   history, versionlock, and GPG key handling
  vez-cli          `vez` binary and all its subcommands
```

Upstream also shipped a `rum-dnf-shim` and a `rum-zypper-shim`. **Both are cut.** Svara
installs vez as the default package manager and leaves dnf present, so nothing pretends to
be dnf; a script that calls dnf by name still calls dnf.

## The persistent overlay, which is why this fork exists

`bootc usr-overlay` — the same mechanism `dnf5 --transient` uses — mounts a **tmpfs**
overlay on `/usr` and tells you so: what it installs is in RAM and is discarded at reboot.
On an immutable image that is the only mechanism bootc offers, which is why installing a
package the obvious way appears to work and then silently loses it.

vez mounts its own overlayfs instead, with the upper directory on disk:

```
lowerdir = /usr                                  the deployment's own, read-only
upperdir = /var/lib/svara/vez/overlay/upper      on disk, survives reboot
workdir  = /var/lib/svara/vez/overlay/work
```

`/var` is the one writable path that survives everything else — a reboot *and* a base image
update — so an installed package's files stay there, and the mount is rebuilt from them at
boot by `vez-overlay.service`. Metadata and files are restored together: the rpmdb entry is
in `/var/lib/svara/vez/rpmdb`, also under `/var`.

Two rules follow, and both are load-bearing:

- **An install refuses to run while the overlay is down.** Falling back to a tmpfs overlay
  would put the files in RAM, report success, and lose them at the next reboot — the exact
  failure this replaces. `vez-overlay::mount::ensure` is the guard.
- **Nothing may be written to `/usr` outside the overlay.** If the mount is missing, the
  read-only image rejects the write loudly, which is the correct outcome.

## Command status

vez aims for full dnf5 CLI parity over time. Most day-to-day commands are
implemented; a handful of larger subsystems (modularity, advisories,
offline transactions) are still stubs that print a "not implemented"
message rather than doing something wrong silently.

**Implemented:**

- `install`, `remove` (aliases `in`, `rm`)
- `upgrade`, `system-upgrade` (aliases `up`, `update`)
- `reinstall`, `downgrade`, `distro-sync` (aliases `rei`, `dg`, `dsync`)
- `autoremove`, `swap`, `mark`, `check`
- `list`, `search` (aliases `ls`, `se`)
- `provides`, `check-upgrade` (alias `check-update`), `repoquery` (alias `rq`)
- `info` (alias `if`), `leaves`, `origin`, `paths`
- `makecache` (alias `mc`), `copr enable`/`copr disable`
- `clean`, `download`, `debuginfo-install`, `changelog`, `needs-restarting`
- `repo list`/`repo info` (and the `repolist`/`repoinfo` top-level aliases)
- `history`, `versionlock`, `config-manager`
- `group list`/`group info`/`group install`/`group remove`, and `@group-id`
  install syntax (e.g. `install @fonts @hardware-support`) — parses
  `comps.xml`/`group_gz` from repo metadata; a group's `mandatory` and
  `default` packagereqs are pulled in, matching dnf's own default `group
  install` set (`optional` members are skipped)
- `environment list`/`environment info`/`environment install`/`environment
  remove`, and `@^environment-id` install syntax — parsed from the same
  comps data as `group`; an environment's `<grouplist>` groups are pulled in
  (not `<optionlist>`), matching dnf's own default `environment install` set
- `reposync` — mirrors an enabled repo's (or `--repo`-selected repos')
  packages to local disk via `--download-path`/`-p`, with `--newest-only`
  and `--norepopath`
- `repomanage` — scans a local directory of `.rpm` files (not repo
  metadata) and reports old/`--new` versions per name+arch, honoring
  `--keep`
- `repoclosure` — checks every candidate package's `Requires` against the
  full candidate pool of the enabled repos, optionally restricted to a
  `--pkg` glob; reports anything unresolved
- `module list`/`module info`/`module enable`/`module disable`/`module
  reset` — parses `modules.yaml` (modulemd v2, `type="modules"` repo data)
  for module-stream metadata; `enable`/`disable`/`reset` persist state that
  filters every other command's candidate pool (an enabled stream's RPMs
  become visible, a disabled module's are blocked outright, everything else
  falls back to the repo's own `modulemd-defaults` stream if it has one),
  matching dnf's own "only the active stream's packages are installable"
  modularity behavior

`upgrade`, `reinstall`, `downgrade`, and `distro-sync` only ever touch
overlay-installed packages, even when you name a base-image package
explicitly. Naming one prints a message telling you it's provided by the
base image and won't be layered; it does not error out or silently do
nothing.

**Not yet implemented (stubs that print a message and exit):**

- `advisory`/`updateinfo` (updateinfo.xml isn't fetched or parsed)
- `offline`, `offline-upgrade`, `offline-distrosync` (no reboot-time
  transaction staging)
- `builddep`/`build-dep` (no spec-file BuildRequires parsing)
- `replay`, `do`

**Deliberately not reimplemented:** actual RPM transaction application
(cpio payload extraction, scriptlets, triggers, low-level digest
verification). vez shells out to `rpm` itself for that step, the same way
dnf5 sits on top of librpm rather than reimplementing it. Re-owning
that logic is a security and format-fragility liability for very little
upside over trusting rpm to do it right.

## Standalone mode: containers, distrobox and image builds

vez is not tied to Svara's overlay. [`OverlayPaths::detect()`](crates/vez-overlay/src/lib.rs)
picks `Standalone` whenever the process is not on a booted OSTree system, which is every
container, every distrobox and every image build. The test is `/run/ostree-booted` and
deliberately **not** `/etc/os-release`: a build chroot's `os-release` already says
`ID=svara` long before any boot, and upstream had a bug where trusting it forced the split
view onto builds that had no overlay — which split one rpmdb view into a stale base plus a
separate extra, and pulled unrelated already-installed packages into transactions.

In `Standalone` mode there is no base/extra split at all: vez reads and writes rpm's own
default rpmdb, exactly like dnf does, with no Svara-specific behaviour left to trip over.
Point it at a plain Fedora, CentOS Stream, RHEL or other dnf-compatible system's
`/etc/yum.repos.d` and it resolves and installs against that system directly.

`vez install httpd`, `vez remove foo` and the rest work as-is on any system with standard
yum/dnf repo metadata: vez reads `repomd.xml`/`primary.xml` and `.repo` files unmodified,
so existing Fedora, EPEL, RPM Fusion, Copr and other third-party repos work without
changes.

Since vez only owns dependency resolution and shells out to real `rpm` for transaction
application, its resolver decisions are held to the same constraints rpm itself would
enforce, so this is not a "mostly works" approximation of dnf, it is a resolver aimed at
full dnf5 CLI parity (see **Command status** above) sitting on the same trusted `rpm`
backbone dnf itself uses.

## Resolver behavior

Dependency resolution is backed by [libsolv](https://github.com/openSUSE/libsolv)
itself — the same SAT-solving library dnf5 and zypper use — via the
[`vez-solv`](crates/vez-solv/src/lib.rs) crate's FFI bindings, not a
hand-rolled solver. `vez-resolver` builds a libsolv `Pool` from vez's own
overlay/base/candidate package data (rather than handing libsolv rpmdb/repo
files directly), so it covers the cases that matter day to day:

- Consults the overlay/base split before ever considering a repo
  candidate, so a dependency already satisfied by the base image never
  gets pulled into the overlay — every base solvable is locked in the
  pool before each solve, RakuOS's Split-mode "never erase a base
  package" guarantee.
- Rich/boolean dependency syntax (`(A if B)`, `(A if B else C)`,
  `(A unless B)`, `(A or B)`, `(A and B)`, `(A with B)`, `(A without B)`)
  is parsed natively by libsolv (`pool_parserpmrichdep`, from
  `libsolvext`) rather than being translated by vez itself.
  RakuOS ships no SELinux userspace, so `vez-resolver` strips
  `Requires` on `selinux-policy`, `policycoreutils`, any `-selinux`
  subpackage, and a couple of other known-broken repo-metadata
  dependencies out of a package's requirements before it ever reaches
  libsolv, rather than treating them as unsatisfiable (see
  `is_selinux_ignored`/`is_broken_repo_dep_ignored` in
  [`vez-resolver`](crates/vez-resolver/src/lib.rs)).
- Conflicts, Obsoletes, multilib version consistency, and backtracking to
  the next-best provider when the highest-EVR candidate leads to a dead
  end are all handled by libsolv's solver directly.
- Reports already-installed packages a transaction will obsolete via
  `Plan::to_obsolete`. rpm itself auto-erases them during `-U`; this is
  just for plan-summary visibility before the transaction runs.

`protected_packages=` is enforced on removal. `installonlypkgs=`/
`installonly_limit=`/`install_weak_deps=` (`vez.conf`) and `allow_erasing`/
`force_names` are accepted as [`ResolveOptions`](crates/vez-resolver/src/lib.rs)
but not yet translated into libsolv jobs/flags — only the plain `Requires`
closure and the base-package erasure guard above are wired up against the
libsolv backend so far. See [`vez-repo`'s `main_config`](crates/vez-repo/src/lib.rs)
for where these are parsed from `vez.conf`.

## Repo metadata and caching

`primary.xml`/`repomd.xml`/`.repo` parsing handles gzip/xz/zstd metadata
compression, `$releasever`/`$basearch` expansion, and mirrorlist/metalink
resolution with a live `HEAD` probe against each candidate mirror's
`repomd.xml` before committing to it. GPG key import and signature
verification run before install (`rpm --import` / `rpm -K`), gated
per-repo by `gpgcheck=`.

Repo metadata caching is modeled on dnf5's `/var/cache/libdnf5` layout:
per-repo `<id>-<hash>` cache dirs under `/var/cache/vez/repos`,
`metadata_expire=` parsing with `s`/`m`/`h`/`d` suffixes and `-1`/`never`
support, a cache hit makes zero network calls, and `--refresh` or
`vez makecache` forces an unconditional re-fetch.

Copr repo enable/disable auto-detects the right chroot from
`/etc/os-release`'s `ID_LIKE`/`ID` and `VERSION_ID`.

## Output

vez prints dnf-style progress by default, not gated behind `RUST_LOG`/
`-v`: `<repo>: refreshing repository metadata` only when a repo's cache
actually needed a network fetch (silent on a cache hit, same as dnf),
`Downloading Packages:` with a `(n/total): <file>.rpm` line per package
actually fetched, `Importing GPG key for repo '<id>': <url>` before
`rpm --import`, and `Running transaction` / `Running transaction test`
immediately before handing off to `rpm -Uvh`/`rpm -ev`. rpm's own `-v`
output (per-package hashmarks, `Preparing...`, `Running scriptlet:`, etc.)
prints directly since the child process inherits vez's stdout/stderr, so
scriptlet output is visible exactly as it would be running `rpm` by hand.

Every HTTP `GET` (repo metadata, mirrorlist/metalink, package downloads,
GPG keys, Copr repo files) retries on a transient connect/send error
before giving up, using a short backoff. Plain `reqwest` doesn't retry at
all, unlike dnf/libdnf's own `retries=` default, which made vez noticeably
more fragile against a common, usually-harmless failure: a pooled
keep-alive connection the remote end had already closed by the time
`reqwest` tried to reuse it ("connection closed before message
completed"). The retry count is configurable via `retries=` in
`/etc/vez/vez.conf` (default 4).

## Configuration

`/etc/vez/vez.conf` follows the same `[main]` section format as
`/etc/dnf/dnf.conf`. Recognized options: `cachedir`, `reposdir`,
`keepcache`, `assumeyes`, `gpgcheck`, `exclude`, `includepkgs`,
`metadata_expire`, `retries`, `timeout`, `max_parallel_downloads`,
`skip_if_unavailable`, `clean_requirements_on_remove`, `installroot`.
`best=` is parsed but not currently wired to any resolver behavior: vez's
resolver already always backtracks to the next-best provider on a
conflict, so there's no separate best=0/best=1 mode to map it onto.

`exclude`/`excludepkgs`, `includepkgs`, and `skip_if_unavailable` can also
be set per repo in a `.repo` file's own section (same as dnf), layered on
top of `vez.conf`'s `[main]` defaults rather than replacing them: a
per-repo `excludepkgs=` only ever drops candidates sourced from that one
repo, an identically-named build from another enabled repo is unaffected;
a per-repo `skip_if_unavailable=1` lets one flaky/optional repo (e.g. a
Copr) be skipped on failure without changing the default for every other
configured repo.

## Building

`vez-solv` links against libsolv/libsolvext, so building requires
`libsolv-devel` on top of a Rust toolchain (`dnf install libsolv-devel`, or
equivalent). Its FFI bindings are committed pre-generated
(`crates/vez-solv/generated/`) rather than produced by `bindgen` at every
build, so ordinary builds don't need `clang-devel`/`libclang` at all — this
keeps `clang-devel`'s LLVM version out of the RPM `BuildRequires`, which
matters on distros (e.g. EL10) where it can conflict with the LLVM version
our own `rust` package is pinned to. Maintainers refresh the vendored
bindings after a libsolv upgrade with:

```
cargo build -p vez-solv --features regen-bindings
```

which needs `clang-devel` installed and rewrites
`crates/vez-solv/generated/{bindings.rs,static_fns.c}` in place.

Repo/package downloading (`vez-librepo`) links against
[librepo](https://github.com/rpm-software-management/librepo) — the same C
library dnf5 uses — plus GLib, which librepo's own API is built on. Building
requires `librepo-devel` and `glib2-devel` (`dnf install librepo-devel
glib2-devel`, or equivalent). Unlike `vez-solv`, `vez-librepo`'s FFI layer
(`crates/vez-librepo/src/sys.rs`) is hand-written directly against
`/usr/include/librepo/*.h` rather than bindgen output — librepo's
`lr_handle_setopt` is a genuine C varargs function and its error convention
is GLib's `GError**`, neither of which bindgen turns into a usable Rust
signature — so there's no `regen-bindings` feature or vendored bindings file
to refresh here.

```
cargo build --workspace
cargo test --workspace
```

### CI owns the FFI/test gate

CI (`.github/workflows/ci.yml`) is not a formality here. It runs `cargo fmt --all
--check`, `cargo test --locked`, `cargo build --release --locked`, and a pkg-config
check that the libsolv, librepo, glib-2.0, openssl and rpm headers are present — all
inside a Fedora container, against the same headers the RPM is built against. **This
is the only place those run.** COPR builds the RPM with `cargo build --release
--locked` alone, and the Svara image no longer compiles vez at all, so without this
workflow a change that breaks a hand-written binding — `vez-librepo/src/sys.rs` is
written by hand against `/usr/include/librepo/*.h` — would build green and fail on a
user's machine.

## Usage (early/unstable)

```
vez install <pkg> [<pkg>...]   # resolve + install, skipping base-satisfied deps
vez install --dry-run <pkg>    # resolve + validate only (rpm --test)
vez remove <pkg> [<pkg>...]
vez upgrade [<pkg>...]         # upgrade overlay-installed packages only
vez system-upgrade             # upgrade every overlay-installed package; never touches the read-only base image
vez list [filter]              # list installed packages, optionally name-filtered
vez search <query>             # search enabled repos' name+summary
vez origin <pkg>               # Base / Overlay / Installed / NotInstalled
vez paths                      # print the overlay paths / mode vez is using
vez makecache                  # force-refresh cached repo metadata for every enabled repo
vez copr enable <owner>/<project> [chroot]  # enable a Copr repo (auto-detects chroot)
vez copr disable <owner>/<project>          # remove a previously-enabled Copr repo
```

`--refresh` is also accepted on `install`/`upgrade`/`system-upgrade`/`search`
to force that one command's repo-metadata fetch to ignore its cache instead
of running a separate `makecache` first.

## Commands and flags

Every command below also accepts every global flag listed under **Global
flags** — they can appear before or after the subcommand, exactly like dnf5.

### Global flags

These apply to `vez` itself, not to a specific subcommand, and work no
matter where on the command line they're placed:

| Flag | Meaning |
| --- | --- |
| `--config <path>` | Path to `vez.conf` (default `/etc/vez/vez.conf`). |
| `--repo-dir <path>` | Directory of `.repo` files (default `/etc/yum.repos.d`). |
| `--cache-dir <path>` | Where downloaded `.rpm`s and repo metadata cache live (default `/var/cache/vez`). |
| `-y`, `--assumeyes` | Assume "yes" to any prompt (vez doesn't currently prompt for anything; accepted for script compatibility). |
| `--assumeno` | Assume "no" to any prompt — same compatibility note as `-y`. |
| `-q`, `--quiet` | Suppress non-essential output. |
| `-x`, `--exclude <pattern>` | Exclude a package (name, glob-capable) from resolution — repeatable. |
| `-C`, `--cacheonly` | Run entirely from cached repo metadata; error instead of touching the network. |
| `--refresh` | Force a repo metadata refresh, ignoring `metadata_expire=`. |
| `--repo <id>` (alias `--repoid`) | Restrict operations to only these repo ids (glob-capable, repeatable). |
| `--enablerepo <id>` (alias `--enable-repo`) | Enable a repo for this run only, even if `enabled=0` — repeatable. |
| `--disablerepo <id>` (alias `--disable-repo`) | Disable a repo for this run only, even if `enabled=1` — repeatable. |
| `--no-gpgchecks` (alias `--nogpgcheck`) | Skip GPG signature verification entirely for this run. |
| `--setopt KEY=VALUE` | dnf-style config override, repeatable. vez only acts on `tsflags=noscripts` (skip rpm scriptlets); any other key is accepted and ignored. |
| `--allowerasing` | Permit replacing/erasing conflicting or obsoleted packages to complete a transaction instead of refusing. |
| `--best` | Accepted for dnf compatibility — vez's resolver always picks the newest candidate already, so there's no separate mode to opt into. |
| `--skip-unavailable` | Drop package names that don't match anything in the enabled repos instead of failing the whole transaction (only affects `install`). |
| `--repofrompath <name,baseurl>` | Add an ad-hoc repo for this run only — repeatable. |
| `--no-autoremove` (alias `--noautoremove`) | Don't sweep up now-unneeded dependency-only packages after `remove`. |
| `--installroot <path>` | Install/operate against an alternate root instead of `/`, same semantics as dnf/rpm. Writes a fresh, disposable overlay rpmdb under `<installroot>/var/lib/svara/vez/rpmdb`. |
| `--no-recommends` | Don't pull in weak dependencies (`Recommends`) for this run. |

### Package transaction commands

| Command | Aliases | Flags | Notes |
| --- | --- | --- | --- |
| `install <pkg>...` | `in`, `pour` | `--dry-run` | Resolve + install, skipping deps already satisfied by the base image. Accepts `@group-id`/`@^environment-id` entries. |
| `remove <pkg>...` | `rm`, `erase` | `--dry-run` | Removes packages, then runs an implicit `autoremove` sweep unless `--no-autoremove`/`clean_requirements_on_remove=false`. |
| `upgrade [<pkg>...]` | `up`, `update` | `--dry-run` | Upgrades overlay-installed packages only, even if a base-image name is given explicitly (reports it instead of layering a duplicate). |
| `system-upgrade` | | `--dry-run` | Upgrades every overlay-installed package; never touches the read-only base image. |
| `reinstall <pkg>...` | `rei` | `--dry-run` | Reinstalls at the exact currently-installed version. |
| `downgrade <pkg>...` | `dg` | `--dry-run` | Downgrades to the newest available version older than what's installed. |
| `distro-sync [<pkg>...]` | `dsync`, `distrosync` | `--dry-run` | Makes installed packages exactly match the best available repo version (up or down). No names = every overlay-installed package. |
| `autoremove` | | `--dry-run` | Removes overlay packages pulled in only as a dependency that nothing installed still needs. |
| `swap <remove-spec> <install-spec>` | | | Remove then install as two back-to-back transactions (an approximation of dnf's atomic swap). |
| `mark install <pkg>...` / `mark dependency <pkg>...` | | | Changes a package's recorded install reason, controlling `autoremove` eligibility. |
| `check` | | | Checks every overlay-installed package's `Requires` against what's currently installed (base + overlay). |
| `download <pkg>...` | | `--destdir <path>` | Resolves and downloads packages (and deps) without installing. |
| `debuginfo-install <pkg>...` | | `--dry-run` | Installs `<name>-debuginfo` for named packages (thin wrapper over `install`). |

### Query commands

| Command | Aliases | Flags | Notes |
| --- | --- | --- | --- |
| `list [filter]` | `ls` | `--base` | Lists installed packages, optionally name-filtered. `--base` lists the read-only base image's set instead of the overlay's. |
| `search <query>` | `se` | | Searches enabled repos' name + summary for a substring. |
| `provides <capability>` | `whatprovides` | | Shows what's installed or available that provides a name/versioned dep/file path. |
| `check-upgrade [<pkg>...]` | `check-update` | `--json` | Lists installed packages with a newer version available. `--json` emits `{"updates": [...]}`. |
| `repoquery [pattern]` | `rq` | `--installed`, `--available`, `--whatprovides <cap>`, `--whatrequires <cap>`, `--requires`, `--provides` | Queries repo package metadata. No `--list` (filelists.xml isn't parsed). |
| `info <pkg>` | `if`, `more` | | NEVRA, repo, and summary for a package. |
| `leaves` | | | Lists overlay-installed packages nothing else installed depends on. |
| `origin <pkg>` | | | `Base` / `Overlay` / `Installed` / `NotInstalled`. |
| `paths` | | | Prints the overlay paths and mode (`Split`/`Standalone`) vez is using. |
| `changelog <pkg>...` | | | Prints the RPM changelog for installed packages. |
| `needs-restarting` | | | Scans running processes for ones with a deleted/replaced mapped file. Reports PIDs, not systemd units. |

### Repo and metadata commands

| Command | Aliases | Flags | Notes |
| --- | --- | --- | --- |
| `makecache` | `mc` | | Unconditionally refreshes cached repo metadata for every enabled repo. |
| `repo list` | `repolist` (top-level) | `--all` | Lists configured repos and whether each is enabled (`--all` also lists disabled). |
| `repo info <id>` | `repoinfo` (top-level) | | Shows one repo's full configuration. |
| `copr enable <owner>/<project> [chroot]` | | | Enables a Copr repo; auto-detects chroot from `/etc/os-release` unless one is given. |
| `copr disable <owner>/<project>` | | | Removes a previously-enabled Copr repo's `.repo` file. |
| `config-manager` | | `--set-enabled <id>`, `--set-disabled <id>`, `--add-repo <id=baseurl>` | Minimal `.repo` editing: enable/disable existing repos or add a new one from a bare baseurl. All repeatable. |
| `reposync` | | `-p`/`--download-path <path>`, `--newest-only`, `--norepopath` | Mirrors a repo's packages to local disk. Respects the global `--repo` filter for which repo(s). |
| `repomanage <path>` | | `--new`, `--keep <n>` (default 1) | Scans a local directory of `.rpm` files and reports old (or, with `--new`, newest) versions per name+arch. |
| `repoclosure` | | `--pkg <pattern>` (repeatable) | Checks every candidate's `Requires` against the full candidate pool of enabled repos; reports unresolved ones. |
| `clean [all\|packages\|metadata]` | | | Clears cached data under `--cache-dir` (default `all`). |

### History and version pinning

| Command | Flags | Notes |
| --- | --- | --- |
| `history list` | | Lists every recorded transaction, oldest first. |
| `history info <id>` | | Shows one transaction's full package list by id. |
| `versionlock add <pkg>` | | Excludes a package from `upgrade`/`distro-sync` candidate selection. |
| `versionlock delete <pkg>` | | Removes a versionlock entry. |
| `versionlock list` | | Lists current versionlock entries. |
| `versionlock clear` | | Clears all versionlock entries. |

### Comps groups and environments

| Command | Notes |
| --- | --- |
| `group list` / `group info <id>` / `group install <id>` / `group remove <id>` | Comps group management, parsed from each repo's `group`/`group_gz` metadata. `install`/`remove` act on a group's mandatory + default members only (matching dnf's own default). Also usable inline as `install @<group-id>`. |
| `environment list` / `environment info <id>` / `environment install <id>` / `environment remove <id>` | Comps environment management, from the same comps data as `group`. `install`/`remove` act on every group in the environment's `<grouplist>` (not `<optionlist>`). Also usable inline as `install @^<environment-id>`. |

### Not yet implemented

These parse but print a message and exit rather than doing something wrong
silently: `module list`/`info`/`enable`/`disable`/`reset`, `advisory`
(alias `updateinfo`), `offline`, `offline-upgrade`, `offline-distrosync`,
`builddep` (alias `build-dep`), `replay`, `do`.

`vez paths` reports which mode is active: `Split` (a booted Svara system: the
deployment's read-only `/usr/share/rpm` plus vez's own
`/var/lib/svara/vez/rpmdb`, with the persistent overlay's upperdir under
`/var/lib/svara/vez/overlay/upper`) or `Standalone` (no overlay present —
distrobox, podman or an image-build environment, a single rpmdb using rpm's own
default, auto-detected from `/run/ostree-booted`).

Repo metadata is cached under `/var/cache/vez/repos/<repoid>-<hash>/`
(hash derived from the repo's `baseurl`/`mirrorlist`/`metalink`, so a URL
change gets a fresh cache slot automatically, mirroring dnf5's
`/var/cache/libdnf5` naming). Each repo's `metadata_expire=` (seconds, or
suffixed `6h`/`7d`/`14d`, or `-1`/`never` to disable expiry, defaulting to
172800s/48h if unset, matching `dnf5.conf`) controls how long a cache hit
is trusted before vez re-fetches. Package downloads for install/upgrade
use a separate location directly under `--cache-dir` (default
`/var/cache/vez`), unaffected by this.

`vez copr enable owner/project` guesses the right Copr chroot from
`/etc/os-release`'s `ID_LIKE` (falling back to `ID`) for the family, and from the
base image's Fedora release for the version. **The version cannot come from
`VERSION_ID`**: Svara sets `ID=svara`, `ID_LIKE="fedora"`, `VERSION_ID=0.1`, so
`VERSION_ID` would ask Copr for `fedora-0.1-<arch>` and fail. `/etc/fedora-release`
is read instead, and `$releasever` in repo URLs is resolved the same way and for
the same reason. Other
families (`mageia`, `opensuse`/`suse`, `rhel`/`centos`/`almalinux`/`rocky`
mapping to `epel-*`) are recognized the same way any RHEL/openSUSE/Mageia
derivative's `ID_LIKE` would name them, in `ID_LIKE`'s listed order
(closest upstream first) so a distro that lists multiple families doesn't
resolve to the wrong one. Pass an explicit chroot (e.g.
`vez copr enable owner/project fedora-44-x86_64`) to override the guess.
The fetched `.repo` file is written to
`<repo-dir>/_copr:copr.fedorainfracloud.org:<owner>:<project>.repo`,
matching dnf's own copr plugin's naming convention.
