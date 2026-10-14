%global debug_package %{nil}
# Build number is bumped by CI from the newest package already in the repo.
%{!?_build_num:%global _build_num 1}

# VEZ HAS ITS OWN VERSION, and it is not the Fedora release.
#
# The first draft of this spec set `Version:` from the Fedora release (44), which is right
# for a package that follows the distribution's release — the hyprland-stack specs do that —
# and wrong for this one. `vez` is a standalone program with its own lifecycle, published from its
# own repository, and users will update it on a Fedora 44 machine and a Fedora 45 machine
# alike. Tying its version to the build chroot would mean the same code is `vez-44` in one
# chroot and `vez-45` in another, and an update across a Fedora rebase would look like a
# downgrade or be refused.
#
# VERSION IS OVERRIDABLE so the release workflow does not have to edit this file:
#   rpmbuild --define 'vez_version 0.2.0' ...
%{!?vez_version:%global vez_version 0.1.2}

# THE COMMIT IS PINNED, NOT A BRANCH. Source0 must identify one immutable artifact or two
# builds of the same Release can differ, which defeats the point of having a Release.
#
# THIS LINE, NOT THE PUSHED HEAD, IS WHAT COPR BUILDS. `.copr/Makefile` lifts `Source0` straight
# out of this spec with `rpmspec -P` (no `--define`) and downloads that archive; it does not
# substitute the commit it was cloned at. Deriving the commit from the clone was tried and
# rejected — see `.copr/Makefile` — because the clone's HEAD is the release commit while Source0
# names the EARLIER commit that holds the code, and the two produced a "Bad file" with no hint
# about the version pin behind it.
#
# So this value decides what code goes into the package, and forgetting to bump it has NO
# SYMPTOM: the version looks new, the build is green, the package is published, and the code
# inside is the previous commit. `release.sh` is what keeps it in step with `vez_version`; it
# writes both, from git, in one command.
%{!?vez_commit:%global vez_commit 0350b71ccfd17b96a98dfce451f1595dbb2641df}

Name:           vez
Version:        %{vez_version}
Release:        %{_build_num}%{?dist}
Summary:        vez — Svara's overlay-aware RPM package manager
License:        GPL-3.0-or-later
URL:            https://github.com/svara-dev/vez
# The commit archive, not `refs/heads/main`: COPR downloads this server-side rather than
# building from a checkout, so the URL has to name the immutable artifact. `%%autosetup` is
# given the directory GitHub actually produces, which is `vez-<commit>` — the reason the tarball
# is not renamed to something tidier.
Source0:        %{url}/archive/%{vez_commit}/vez-%{vez_commit}.tar.gz

ExclusiveArch:  x86_64 aarch64

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  systemd-rpm-macros
BuildRequires:  libsolv-devel
BuildRequires:  pkgconfig(libsolv)
BuildRequires:  pkgconfig(libsolvext)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(librepo)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(rpm)

Requires:       rpm
Requires:       systemd
Requires:       libsolv
Requires:       librepo

%{?systemd_requires}

%description
vez is Svara's package manager. It consumes standard yum/dnf-compatible repo
metadata but resolves and applies transactions itself, so it can tell packages
already provided by the read-only base image apart from packages installed on
top — something dnf, working from a single merged view of "installed", cannot
do.

On a booted Svara system the base lives in an immutable OCI image, so a package
installed on top has nowhere of its own to live. Vez records it in its own rpm
database under /var/lib/svara/vez, writes its files into an overlayfs on /usr
whose upper directory is also under /var, and rebuilds that overlay at every
boot. That last part is what makes an install survive a reboot: `bootc
usr-overlay`, which is what `dnf5 --transient` uses, is backed by tmpfs, so
anything installed through it is discarded on the next boot.

Vez does not replace dnf. Svara installs it as the default package manager and
leaves dnf present; no dnf or dnf5 shim is shipped, so a script that calls dnf
by name still gets dnf.

%prep
%autosetup -n vez-%{vez_commit}

%build
# Strip -flto=auto/-ffat-lto-objects from the RPM-injected CFLAGS before
# building. cc-rs (used by vez-solv's bindgen build and by the vendored C
# sources in zstd-sys/lzma-sys) picks up $CFLAGS automatically, but rustc's
# final link step doesn't do LTO-aware linking. Static archives built from
# fat-LTO objects then fail to link under ld.bfd with "undefined reference to
# FSE_readNCount"/"HUF_readStats" (zstd-sys) even though the real (non-IR)
# symbols are in the object. Reproduced upstream with a from-scratch `rpmbuild`
# (plain `cargo build` doesn't hit it) in a matching Fedora 44 container.
# Dropping only the LTO flags fixes it and keeps every other hardening flag RPM
# sets.
export CFLAGS="$(echo "${CFLAGS:-%{optflags}}" | sed -E 's/-flto=[^ ]*//g; s/-ffat-lto-objects//g')"
cargo build --release --locked

%install
install -d %{buildroot}%{_bindir}
install -m 0755 target/release/vez %{buildroot}%{_bindir}/vez
install -d %{buildroot}%{_sysconfdir}/vez
install -m 0644 data/vez.conf %{buildroot}%{_sysconfdir}/vez/vez.conf
install -d %{buildroot}%{_unitdir}
install -m 0644 data/vez-makecache.service %{buildroot}%{_unitdir}/vez-makecache.service
install -m 0644 data/vez-makecache.timer %{buildroot}%{_unitdir}/vez-makecache.timer
install -Dm 0644 data/man/vez.1 %{buildroot}%{_mandir}/man1/vez.1
install -Dm 0644 data/man/vez.conf.5 %{buildroot}%{_mandir}/man5/vez.conf.5

# VEZ'S OWN RUNTIME DIRECTORIES. They have to exist in the buildroot for %files to be able
# to name them, and they have to exist on a system where this package is installed by rpm
# rather than by the image. On a booted Svara machine `tmpfiles.d/svara.conf` creates the
# same paths at boot, which is the mechanism that matters there; this is the other entry
# point, and the two must agree or the later one wins.
#
# MODES ARE SET EXPLICITLY, AND THAT IS NOT DECORATION. `%dir` makes rpm RESET a directory's
# mode at install time regardless of what is on disk, so a directory declared here without a
# %attr would have its permissions decided by rpm's default rather than by this file — and
# the two modes that matter are load-bearing:
#
#   overlay/upper  0755  Overlayfs gives a merged directory the attributes of its upper
#                        counterpart, so an upperdir of 0700 makes the overlay report /usr
#                        as drwx------. Root still traverses it so nothing looks wrong as
#                        root; every service systemd execs as a non-root user is refused
#                        with EACCES, which at boot is dbus-broker, polkit, resolved, rtkit,
#                        avahi and upower all failing at once and no login prompt.
#   overlay/work   0700  internal to overlayfs, never merged, and overlayfs refuses a
#                        workdir that is not private to it.
#
# An rpm install that silently changed the upperdir's mode would reproduce exactly the
# broken boot that took a whole debugging session to find, so the modes are asserted here
# as well as in data/svara.conf and in `vez overlay mount`.
install -d -m 0755 %{buildroot}%{_localstatedir}/lib/svara/vez
install -d -m 0755 %{buildroot}%{_localstatedir}/lib/svara/vez/overlay
install -d -m 0755 %{buildroot}%{_localstatedir}/lib/svara/vez/overlay/upper
install -d -m 0700 %{buildroot}%{_localstatedir}/lib/svara/vez/overlay/work
install -d -m 0700 %{buildroot}%{_localstatedir}/lib/svara/vez/state
install -d -m 0755 %{buildroot}%{_localstatedir}/cache/vez

%post
%systemd_post vez-makecache.timer

%preun
%systemd_preun vez-makecache.timer

%postun
%systemd_postun_with_restart vez-makecache.timer

%files
%license LICENSE
%{_bindir}/vez
%config(noreplace) %{_sysconfdir}/vez/vez.conf
%{_unitdir}/vez-makecache.service
%{_unitdir}/vez-makecache.timer
%{_mandir}/man1/vez.1*
%{_mandir}/man5/vez.conf.5*
# Vez's own rpmdb, overlay upper/work, replay state and cache. Created at first use by
# vez itself, and declared here so an rpm install of this package owns the paths rather
# than `rpm -V`/needs-restarting reporting them as unowned.
#
# %dir with an explicit %attr, for the reason set out in %install: rpm resets a declared
# directory's mode, and giving the overlay's upperdir the wrong one breaks boot for every
# non-root service. `%{_cachedir}` is NOT used here — Fedora does not define it, so it
# survived unexpanded into `%files` and rpm rejected the line with
# "File must begin with /", which is how this was found.
%dir %attr(0755,root,root) %{_localstatedir}/lib/svara/vez
%dir %attr(0755,root,root) %{_localstatedir}/lib/svara/vez/overlay
%dir %attr(0755,root,root) %{_localstatedir}/lib/svara/vez/overlay/upper
%dir %attr(0700,root,root) %{_localstatedir}/lib/svara/vez/overlay/work
%dir %attr(0700,root,root) %{_localstatedir}/lib/svara/vez/state
%dir %attr(0755,root,root) %{_localstatedir}/cache/vez

%changelog
* Wed Oct 14 2026 Svara maintainer <maintainer@svara.dev> - 0.1.2-1
- `vez upgrade` can now update the `vez` package itself. `vez` ships in the base
  image and the upgrade path was overlay-only, so a base package could never be
  updated through it — which is why `vez upgrade` reported "Nothing to upgrade"
  even when a newer `vez` sat in an enabled repo. `vez` is now the one base
  package the upgrade path may shadow in the overlay (SELF_UPGRADABLE_NAMES):
  the resolver's base lock is deliberately left untouched, and the self-upgrade
  is applied through the normal overlay-install path, so the base image's copy is
  never modified and stays as the recovery. `vez check-upgrade` reports it too.

* Wed Oct 14 2026 Svara maintainer <maintainer@svara.dev> - 0.1.1-1
- No functional change. This release exists to exercise the update channel end
  to end: COPR builds 0.1.1 from the commit pinned below, and an installed
  machine should move to it with `vez upgrade` (or `dnf upgrade vez`) without an
  image rebuild. `vez --version` and the RPM Version both report 0.1.1, which is
  the pair that has to agree for the update to be verifiable rather than merely
  to have happened.

* Tue Oct 13 2026 Svara maintainer <maintainer@svara.dev> - %{vez_version}-1
- Forked from RakuOS's rum (GPL-3.0-or-later) as vez, Svara's package manager.
  Renamed every crate and path; cut the zypper shim, the dnf/dnf5 shims and the
  vendor's install-count telemetry; replaced the RakuOS overlay detection with
  the bootc layout; added a persistent disk-backed overlay on /usr with a
  boot-time replay, because bootc's own usroverlay is tmpfs and loses installs
  at reboot.
- Fixed $releasever resolving to Svara's VERSION_ID instead of the base image's
  Fedora release, which made every Fedora and COPR repository URL wrong.
- Fixed `vez copr enable` guessing a nonexistent `fedora-0.1-<arch>` chroot for
  the same reason.
- Upstream changelog follows, with the upstream package name where it was
  written that way.

* Sat Aug 15 2026 Joshua Webb <joshwebb84@outlook.com> - %{vez_version}-1
- Drop the manual "Requires: libsolvext" — no package is actually named
  libsolvext on Fedora or EL10 (libsolvext.so.1 ships inside the libsolv
  package on both), so the literal name was unsatisfiable; rpm's automatic
  soname scanner already adds the correct libsolvext.so.1()(64bit)
  requirement from the linked binary
* Sat Aug 15 2026 Joshua Webb <joshwebb84@outlook.com> - %{vez_version}-1
- vez-solv: generated/static_fns.c is now hand-maintained, wrapping only
  the two static-inline libsolv functions we actually call
  (pool_id2solvable, queue_push2) instead of every static inline function
  bindgen's wrap_static_fns happened to find. The full vendored dump broke
  on EL10 (libsolv 0.7.33) with "implicit declaration of function
  'allochashtable'" — that helper isn't part of libsolv's stable API and
  simply isn't declared in EL10's older headers, even though we never
  called it. Verified end-to-end with a real `rpmbuild -bb` inside a
  CentOS Stream 10 container.
* Sat Aug 15 2026 Joshua Webb <joshwebb84@outlook.com> - %{vez_version}-1
- vez-solv: use committed, pre-generated libsolv FFI bindings by default
  instead of running bindgen at build time (bindgen is now an opt-in
  `regen-bindings` cargo feature for maintainers only); drop clang-devel
  BuildRequires — on rakuos-el (EL10) it required a newer llvm-libs than
  our own `rust` package is built against, making the two mutually
  uninstallable via `dnf builddep`
* Sat Aug 15 2026 Joshua Webb <joshwebb84@outlook.com> - %{vez_version}-1
- %build: strip -flto=auto/-ffat-lto-objects from RPM-injected CFLAGS
  before `cargo build` — fixes "undefined reference to
  FSE_readNCount"/"HUF_readStats" link errors: cc-rs (used by zstd-sys's
  vendored C sources) picks up $CFLAGS automatically, but rustc's final
  link step isn't LTO-aware, so static archives built from fat-LTO objects
  fail to link under ld.bfd even though the real symbols are present
* Sat Aug 15 2026 Joshua Webb <joshwebb84@outlook.com> - %{vez_version}-1
- Resolver now backed by libsolv (vez-solv crate) instead of a hand-rolled
  SAT solver; add libsolv-devel BuildRequires and libsolv/libsolvext
  runtime Requires (pool_parserpmrichdep, used for rpm rich/boolean
  dependency parsing, lives in libsolvext)
* Sat Aug 15 2026 Joshua Webb <joshwebb84@outlook.com> - %{vez_version}-1
- Add vez-makecache.service/.timer (mirrors dnf-makecache.timer): refreshes
  repo metadata hourly in the background so update checks hit a warm cache
  instead of a cold/expired one
* Wed Aug 12 2026 Joshua Webb <joshwebb84@outlook.com> - %{vez_version}-1
- Package downloads now stream straight to disk instead of buffering the
  whole body in memory, verifying the transfer against the server-reported
  Content-Length (the same safety net rakurpm gets from wget, without
  losing the client's pooled-connection reuse across hundreds of packages)
- Client no longer applies a single whole-request timeout to package/
  metadata fetches (was killing large downloads that legitimately took
  longer than `timeout=`); replaced with a per-chunk stall timeout so only
  a connection gone genuinely silent gets aborted
- vez-dnf-shim: add dnf-command(<verb>) provides (dnf4 plugin capability
  naming) alongside the existing dnf5-command(<verb>) set — fixes
  `dnf-command(repoquery)` (needed by fedora-review) becoming unsatisfiable
  once dnf-plugins-core, its real provider, is obsoleted/conflicted away
* Sun Aug 09 2026 Joshua Webb <joshwebb84@outlook.com> - %{vez_version}-1
- Add vez-dnf-shim subpackage: Rust dnf/dnf5 CLI shims that exec into the package manager,
  Provides/Obsoletes/Conflicts real dnf5 so it can be removed outright
- Extend Provides/Obsoletes/Conflicts to cover dnf5-plugins, the legacy
  dnf4/yum/microdnf stack, and every dnf5-command(<verb>) capability it
  implements, so nothing pulls the real dnf/dnf5 packages back in
* Fri Aug 07 2026 Joshua Webb <joshwebb84@outlook.com> - %{vez_version}-1
- Initial package: install/remove/upgrade/system-upgrade/list/search/origin/paths
- Overlay-aware dependency resolution with Conflicts/Obsoletes handling
- GPG key import and signature verification on downloaded packages
- gzip/xz/zstd repo metadata support, $releasever/$basearch expansion
