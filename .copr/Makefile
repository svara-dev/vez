# .copr/Makefile — how COPR turns this Git repository into a source RPM.
#
# WHY THIS FILE EXISTS. Without it, getting vez into COPR means a person (or a CI job holding a
# COPR API token) running `copr-cli build` with an uploaded spec after every change. With it,
# COPR builds **straight from this Git repository**:
#
#     copr-cli buildscm dodo986/svara-tools --clone-url https://github.com/svara-dev/vez
#
# and, with the webhook on the COPR project, a push to `main` starts that build on its own.
# Verified: a push produced build 11122234 with no manual step.
#
# COPR runs `make -f .copr/Makefile srpm outdir=<dir> spec=<path>` in a clone of this
# repository. The only contract is: produce a `.src.rpm` in `$outdir`. How is up to us.
#
# ── WHAT THE SOURCE IS, AND WHY ─────────────────────────────────────────────
#
# `Source0` is a GitHub **commit archive** of `%{vez_commit}`: one immutable artifact, so two
# builds of the same Release are identical. That commit is where the code being packaged lives.
#
# `%{vez_commit}` is therefore the single thing that decides what gets built, and a release is:
# bump it to the commit that holds the change, bump `vez_version`, push. The release commit pins
# ITSELF, which is ordinary for this shape and worth stating plainly because it looks circular:
# the spec is inside the archive at that commit, and the archive's copy of the spec is not the
# one rpmbuild reads — the working copy is. It is reproducible, which is the whole point.
#
# ── WHAT WAS TRIED AND REJECTED, IN ORDER ───────────────────────────────────
#
# Three attempts, each failing for a different reason. They are recorded because each looked
# correct and the error messages pointed somewhere other than the cause.
#
#   1. `commit=$(git rev-parse HEAD)` — derive the commit from COPR's own clone. WRONG: the
#      clone's HEAD is the commit being built, while Source0 names `%{vez_commit}`, which for a
#      release is an EARLIER commit. Two commits, one filename:
#          error: Bad file: .../vez-<clone-HEAD>.tar.gz: No such file or directory
#
#   2. `spectool --all --get-files` — let the tool that reads Source0 do the download. WRONG:
#      COPR's source-build chroot has no `rpmdevtools`, and the guard fired on every build:
#          spectool is missing (install rpmdevtools)
#
#   3. `rpmbuild -bs` alone — let rpm fetch Source0 itself. WRONG, and the least obvious:
#      `%_disable_source_fetch` is **1** by default on Fedora, so rpm refuses to download and
#      reports the same "Bad file" as (1). COPR sets it to 0 in its own build path; a Makefile
#      running inside microvm/mock does not inherit that.
#
# What is left is `curl`, which is present, has no macro to disagree with, and is what
# `spectool` calls underneath anyway.
#
# ── WHY THE URL IS READ FROM THE SPEC AND NOT WRITTEN HERE ──────────────────
#
# If this file hardcoded the template, `%{vez_commit}` would live in two places and one would go
# stale — the same drift the symlink in `packaging/copr/svara-tools/` exists to avoid. Instead
# `rpmspec -P` expands the spec and the Source0 line is lifted from its output. One home.
#
# COPR passes the spec path as a MAKE VARIABLE; ignoring it is silent, because a default of
# `vez.spec` also exists in the repository root. `notdir` — NOT `basename`, which in Make strips
# the suffix (`vez.spec` -> `vez`).

ifneq ($(spec),)
SPEC := $(notdir $(spec))
else
SPEC := vez.spec
endif

.PHONY: srpm clean

srpm:
	@command -v rpmbuild >/dev/null 2>&1 || { echo "rpmbuild is missing (install rpm-build)"; exit 1; }
	@command -v rpmspec  >/dev/null 2>&1 || { echo "rpmspec is missing (install rpm-build)"; exit 1; }
	@command -v curl     >/dev/null 2>&1 || { echo "curl is missing"; exit 1; }
	set -eux; \
	mkdir -p "$(outdir)"; \
	url=$$(rpmspec -P "$(SPEC)" | awk '$$1 == "Source0:" { print $$2; exit }'); \
	test -n "$$url" || { echo "no Source0: in $(SPEC)"; exit 1; }; \
	file=$$(basename "$$url"); \
	curl -fsSL "$$url" -o "$$file"; \
	rpmbuild -bs \
	    --define "_sourcedir $$PWD" \
	    --define "_srcrpmdir $(outdir)" \
	    --define "_specdir $$PWD" \
	    "$(SPEC)"

# A local reproduction, which is the whole reason to prefer a Makefile over a description of
# one:
#     make -f .copr/Makefile srpm outdir=$PWD/out
clean:
	rm -rf out *.tar.gz
