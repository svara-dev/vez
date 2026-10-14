#!/usr/bin/env bash
# =============================================================================
# release.sh -- cut a vez release: pin the version and commit, show what changed.
# =============================================================================
# WHY A SCRIPT FOR TWO EDITS. A release has to keep three things consistent, and every one of
# them is a silent failure when it is wrong:
#
#   1. `vez_version` in vez.spec      -- becomes the RPM Version
#   2. `vez_commit`  in vez.spec      -- Source0, the immutable artifact COPR downloads
#   3. the git tag / the pushed HEAD  -- what actually gets built
#
# If (1) does not move, COPR builds the same NVR again and **refuses or silently reuses** the
# old package: the release appears to succeed and changes nothing. If (2) does not move, the
# new version is built from the OLD source — a version bump that ships the previous code,
# which is the worst of the three because it looks completely successful from every side.
#
# So the two numbers are written together, from git, by one command.
#
# Usage:
#   ./release.sh 0.2.0            # pin 0.2.0 to the current HEAD
#   ./release.sh 0.2.0 --commit <sha>
#   ./release.sh --show           # print what is pinned now
#
# The script does NOT commit, tag or push. Those are the maintainer's decisions and a script
# that makes them is a script that eventually tags the wrong tree. It prints the commands.
# =============================================================================

set -o errexit
set -o nounset
set -o pipefail

PROG=${0##*/}
readonly PROG
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly HERE
readonly SPEC="$HERE/vez.spec"

die() { printf '[x] %s\n' "$*" >&2; exit 1; }
info() { printf '[*] %s\n' "$*"; }
ok() { printf '  \033[32m✔\033[0m %s\n' "$*"; }

[ -f "$SPEC" ] || die "no spec at $SPEC"

current_version() { sed -n 's/^%{!?vez_version:%global vez_version \(.*\)}$/\1/p' "$SPEC" | head -1; }
current_commit()  { sed -n 's/^%{!?vez_commit:%global vez_commit \(.*\)}$/\1/p'  "$SPEC" | head -1; }

if [ "${1:-}" = '--show' ] || [ "$#" -eq 0 ]; then
    printf 'vez version pinned: %s\n' "$(current_version)"
    printf 'vez commit  pinned: %s\n' "$(current_commit)"
    exit 0
fi

VERSION=$1
shift

COMMIT=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --commit) [ "$#" -ge 2 ] || die "--commit needs a value"; COMMIT=$2; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

# A version that is not x.y.z, or an x.y.z with a dist suffix, produces an NVR that either
# sorts wrongly or collides. Checked here rather than discovered by COPR.
case "$VERSION" in
    [0-9]*.[0-9]*.[0-9]*) ;;
    *) die "version must look like MAJOR.MINOR.PATCH (got '$VERSION')" ;;
esac
case "$VERSION" in
    *-*|*.fc*|*.el*) die "version must be bare semver: '$VERSION' carries a dist/release suffix.
     The channel comes from the spec's Release (%{?dist}) and from the COPR chroot, not from
     Version. Two Fedora chroots must be able to serve the same Version." ;;
esac

if [ -z "$COMMIT" ]; then
    # THE COMMIT MUST COME FROM THE VEZ REPOSITORY, NOT FROM WHATEVER REPOSITORY THIS
    # DIRECTORY SITS INSIDE. `git -C "$HERE" rev-parse HEAD` finds the ENCLOSING repository,
    # and while `packages/vez/` lives untracked inside the Svara monorepo it returns the
    # MONOREPO's HEAD — a commit that does not contain vez.spec at its root. Pinning that makes
    # Source0 download an archive with no Cargo.toml, and COPR then fails at %prep with a
    # message about a missing directory, which says nothing about the version pin that caused
    # it.
    #
    # Measured, not imagined: this exact mistake pinned the monorepo's HEAD the first time this
    # script ran.
    #
    # So the commit is only trusted when the repository it came from has vez.spec at its root;
    # `git cat-file -e HEAD:vez.spec` asks precisely that.
    if ! git -C "$HERE" cat-file -e 'HEAD:vez.spec' 2>/dev/null; then
        die "cannot determine the commit to pin.

     $HERE is not the root of a git repository containing vez.spec. It is either untracked
     inside the Svara monorepo — whose HEAD does not contain this file — or the fork is not
     checked out. Pinning the enclosing repository's HEAD would make COPR download a source
     archive with no Cargo.toml.

     Publish the fork first (from the monorepo root):
         ./tools-publish-vez.sh
     then run this from a checkout of the fork, or pass the commit explicitly:
         ./release.sh $VERSION --commit <full-sha-of-the-vez-repo>"
    fi
    COMMIT=$(git -C "$HERE" rev-parse HEAD)
fi

case "$COMMIT" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
    *) die "--commit must be a full git object name (got '$COMMIT')" ;;
esac

oldv=$(current_version)
oldc=$(current_commit)
info "version $oldv -> $VERSION"
info "commit  ${oldc:0:12} -> ${COMMIT:0:12}"

# In-place, one sed per line, so a failure cannot leave the spec half-rewritten into a state
# where the version moved but the commit did not — the failure mode this script exists to
# prevent.
sed -i "s|^%{!?vez_version:%global vez_version .*}$|%{!?vez_version:%global vez_version $VERSION}|" "$SPEC"
sed -i "s|^%{!?vez_commit:%global vez_commit .*}$|%{!?vez_commit:%global vez_commit $COMMIT}|" "$SPEC"

gotv=$(current_version); gotc=$(current_commit)
[ "$gotv" = "$VERSION" ] || die "version did not take (now '$gotv')"
[ "$gotc" = "$COMMIT" ]  || die "commit did not take (now '$gotc')"
ok "spec pinned to $gotv at ${gotc:0:12}"

# The changelog is what a user reads in `rpm -q --changelog vez`. A release with no entry is
# a release nobody can date, so a missing one is reported now rather than noticed later.
if ! grep -q "^%changelog" "$SPEC"; then
    die "the spec has no %changelog section"
fi
if ! sed -n '/^%changelog/,$p' "$SPEC" | grep -q "$VERSION"; then
    info "no %changelog entry mentions $VERSION yet — add one:"
    printf '    * %s %s <%s> - %s-1\n' "$(date +%a)" "$(date '+%b %d %Y')" "${RPM_AUTHOR:-you@example.com}" "$VERSION"
    printf '    - <what changed>\n'
fi

cat <<EOF

[*] next:
    git -C "$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null || echo "$HERE")" commit -am "vez $VERSION"
    git tag -a "v$VERSION" -m "vez $VERSION"
    git push origin HEAD --tags

    # then publish the fork and let COPR build it from the pinned commit:
    ./tools-publish-vez.sh
    copr-cli buildscm dodo986/svara-tools --clone-url https://github.com/svara-dev/vez
EOF
