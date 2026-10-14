//! RPM's version comparison (`rpmvercmp`) plus epoch-aware EVR comparison.
//! Dependency resolution depends on this: if it's wrong, vez silently picks
//! the wrong package version. Ported from upstream rpm's `rpmvercmp.c`
//! semantics, including the special `~` (sorts before anything, even empty)
//! and `^` (sorts after anything, even empty) separators from rpm
//! 4.10+/4.15+.

use std::cmp::Ordering;

pub trait EvrCompare {
    fn compare_evr(&self, other: &str) -> Ordering;
}

impl EvrCompare for str {
    fn compare_evr(&self, other: &str) -> Ordering {
        compare_evr(self, other)
    }
}

/// Splits `epoch:version-release` (epoch and release both optional) into
/// its three parts, defaulting a missing epoch to `"0"`.
fn split_evr(evr: &str) -> (&str, &str, &str) {
    let (epoch, rest) = match evr.split_once(':') {
        Some((e, r)) => (e, r),
        None => ("0", evr),
    };
    let (version, release) = rest.split_once('-').unwrap_or((rest, ""));
    (epoch, version, release)
}

/// Compares two full `epoch:version-release` strings the way rpm does: epoch
/// first (numeric), then version, then release, each with [`rpmvercmp`]. A
/// missing epoch counts as `0`, and a missing or empty release only compares
/// equal to another empty release.
pub fn compare_evr(a: &str, b: &str) -> Ordering {
    let (ea, va, ra) = split_evr(a);
    let (eb, vb, rb) = split_evr(b);

    let ea: i64 = ea.parse().unwrap_or(0);
    let eb: i64 = eb.parse().unwrap_or(0);
    match ea.cmp(&eb) {
        Ordering::Equal => {}
        ord => return ord,
    }

    match rpmvercmp(va, vb) {
        Ordering::Equal => {}
        ord => return ord,
    }

    rpmvercmp(ra, rb)
}

/// Compares `evr` (a real package's full EVR) against `want` (the version
/// side of a `Requires`/`Conflicts`/`Provides` constraint) the way rpm's
/// `rpmdsCompare` does for dependency satisfaction. If `want` has no release
/// at all, the release is skipped instead of compared. rpm emits some deps
/// that way on purpose, e.g. an auto-generated ISA self-provide like
/// `Requires: foo(x86-64) = 0:6.11.1`, so it matches *any* release of that
/// version. Comparing the release anyway would never match a real package's
/// release (e.g. `-1.fc44`) and every such dependency would look
/// unsatisfiable. [`compare_evr`] has to stay a plain three-way EVR compare,
/// because version sorting needs a blank release to count as "older", so this
/// is its own function.
pub fn compare_evr_for_dep(evr: &str, want: &str) -> Ordering {
    let (e_evr, v_evr, r_evr) = split_evr(evr);
    let (e_want, v_want, r_want) = split_evr(want);

    let e_evr: i64 = e_evr.parse().unwrap_or(0);
    let e_want: i64 = e_want.parse().unwrap_or(0);
    match e_evr.cmp(&e_want) {
        Ordering::Equal => {}
        ord => return ord,
    }

    match rpmvercmp(v_evr, v_want) {
        Ordering::Equal => {}
        ord => return ord,
    }

    if r_want.is_empty() {
        return Ordering::Equal;
    }
    rpmvercmp(r_evr, r_want)
}

/// The segment-by-segment comparison rpm uses for both `version` and
/// `release`. Both strings are walked left to right in alternating runs of
/// digits and letters. Numeric runs compare as numbers (leading zeros
/// stripped) and alpha runs compare lexically. `~` sorts before anything,
/// including end of string; `^` sorts after anything, including end of
/// string.
pub fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }

    let a = a.as_bytes();
    let b = b.as_bytes();
    let (mut i, mut j) = (0usize, 0usize);

    loop {
        // Tilde sorts before everything, even a shorter or empty remainder.
        let a_tilde = i < a.len() && a[i] == b'~';
        let b_tilde = j < b.len() && b[j] == b'~';
        if a_tilde || b_tilde {
            if !a_tilde {
                return Ordering::Greater;
            }
            if !b_tilde {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }

        // Caret sorts after everything, but a caret followed by end of string
        // is *older* than a real trailing segment on the other side (rpm's
        // post-4.15 behavior).
        let a_caret = i < a.len() && a[i] == b'^';
        let b_caret = j < b.len() && b[j] == b'^';
        if a_caret || b_caret {
            if !a_caret {
                return Ordering::Less;
            }
            if !b_caret {
                return Ordering::Greater;
            }
            i += 1;
            j += 1;
            continue;
        }

        // Skip any run of separator characters (non-alphanumeric, not
        // tilde/caret) on both sides. How many there are doesn't matter, only
        // that a boundary happened.
        let a_start_sep = i;
        while i < a.len() && !is_alnum(a[i]) && a[i] != b'~' && a[i] != b'^' {
            i += 1;
        }
        let b_start_sep = j;
        while j < b.len() && !is_alnum(b[j]) && b[j] != b'~' && b[j] != b'^' {
            j += 1;
        }
        if i > a_start_sep || j > b_start_sep {
            // At least one side had a separator run, and both now sit at the
            // next alnum/tilde/caret/end. Loop back so tilde/caret get
            // checked again at the new position.
            continue;
        }

        if i == a.len() || j == b.len() {
            break;
        }

        if a[i].is_ascii_digit() {
            if !b[j].is_ascii_digit() {
                // Numeric segments are always newer than alpha segments.
                return Ordering::Greater;
            }
            let a_seg_start = i;
            while i < a.len() && a[i].is_ascii_digit() {
                i += 1;
            }
            let b_seg_start = j;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            let a_num = strip_leading_zeros(&a[a_seg_start..i]);
            let b_num = strip_leading_zeros(&b[b_seg_start..j]);
            match a_num.len().cmp(&b_num.len()) {
                Ordering::Equal => match a_num.cmp(b_num) {
                    Ordering::Equal => continue,
                    ord => return ord,
                },
                ord => return ord,
            }
        } else if b[j].is_ascii_digit() {
            return Ordering::Less;
        } else {
            // Both alpha segments.
            let a_seg_start = i;
            while i < a.len() && a[i].is_ascii_alphabetic() {
                i += 1;
            }
            let b_seg_start = j;
            while j < b.len() && b[j].is_ascii_alphabetic() {
                j += 1;
            }
            match a[a_seg_start..i].cmp(&b[b_seg_start..j]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
    }

    // Ran out of segments on one or both sides: whichever side has leftover
    // (non-separator) characters is newer, with no alpha-vs-numeric special
    // case. Checked against real `rpm`/`rpmdev-vercmp`: `3.8-1.fc42` compares
    // *greater than* `3.8-1`, because a dist-tag suffix counts as more
    // version and isn't a pre-release marker. rpm's final rule is just
    // "leftover characters win". An earlier version of this function treated
    // trailing alpha segments as pre-release tags that sort *older* (`"1.0a"
    // < "1.0"`), which was wrong. rpm already handles `"1.0a"` vs `"1.0"`
    // inside the segment loop above (alpha vs digit at the transition, "digit
    // newer than alpha"). This fallback only runs once every segment pair so
    // far compared equal, so there's no pre-release signal left; it's
    // leftover text, and more text wins. Only `^` keeps a special case (a
    // caret suffix is older than nothing, unlike an ordinary trailing
    // segment), matching rpm's post-4.15 semantics.
    match (i == a.len(), j == b.len()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => Ordering::Equal,
    }
}

fn is_alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

fn strip_leading_zeros(digits: &[u8]) -> &[u8] {
    match digits.iter().position(|&c| c != b'0') {
        Some(i) => &digits[i..],
        // All zeros (or empty): collapse to a single "0" so "00" and "0"
        // still compare equal in length and content.
        None => &digits[digits.len().saturating_sub(1)..],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_strings() {
        assert_eq!(rpmvercmp("1.0", "1.0"), Ordering::Equal);
    }

    #[test]
    fn numeric_newer() {
        assert_eq!(rpmvercmp("1.2", "1.10"), Ordering::Less);
        assert_eq!(rpmvercmp("1.10", "1.2"), Ordering::Greater);
    }

    #[test]
    fn leading_zeros_ignored() {
        assert_eq!(rpmvercmp("1.05", "1.5"), Ordering::Equal);
    }

    #[test]
    fn trailing_segment_always_wins_regardless_of_alpha_or_numeric() {
        // Checked against real `rpmdev-vercmp`: a trailing segment is more
        // version whether it's alpha or numeric. Once every earlier segment
        // compared equal there's no pre-release special case.
        assert_eq!(rpmvercmp("1.0a", "1.0"), Ordering::Greater);
        assert_eq!(rpmvercmp("1.0", "1.0a"), Ordering::Less);
        assert_eq!(rpmvercmp("3.8-1.fc42", "3.8-1"), Ordering::Greater);
        assert_eq!(rpmvercmp("6b-47.fc42", "6b-47"), Ordering::Greater);
    }

    #[test]
    fn tilde_sorts_before_everything() {
        assert_eq!(rpmvercmp("1.0~rc1", "1.0"), Ordering::Less);
        assert_eq!(rpmvercmp("1.0", "1.0~rc1"), Ordering::Greater);
        assert_eq!(rpmvercmp("1.0~rc1", "1.0~rc2"), Ordering::Less);
    }

    #[test]
    fn caret_sorts_after_everything() {
        assert_eq!(rpmvercmp("1.0^git1", "1.0"), Ordering::Greater);
        assert_eq!(rpmvercmp("1.0", "1.0^git1"), Ordering::Less);
    }

    #[test]
    fn evr_epoch_dominates() {
        assert_eq!(compare_evr("1:1.0-1", "2:0.1-1"), Ordering::Less);
        assert_eq!(compare_evr("0:1.0-1", "1.0-1"), Ordering::Equal);
    }

    #[test]
    fn evr_release_tiebreak() {
        assert_eq!(compare_evr("1.0-1", "1.0-2"), Ordering::Less);
    }

    #[test]
    fn dep_compare_ignores_release_when_want_has_none() {
        // rpm auto-generates ISA self-provide Requires without a release
        // (`foo(x86-64) = 0:6.11.1`), and those must match any release of
        // that version. A plain compare_evr would treat the missing release
        // as older than any real release and reject every match.
        assert_eq!(
            compare_evr_for_dep("0:6.11.1-1.fc44", "0:6.11.1"),
            Ordering::Equal
        );
        assert_eq!(
            compare_evr_for_dep("6.11.1-1.fc44", "6.11.1"),
            Ordering::Equal
        );
    }

    #[test]
    fn dep_compare_still_compares_release_when_want_has_one() {
        assert_eq!(compare_evr_for_dep("1.0-1", "1.0-2"), Ordering::Less);
        assert_eq!(compare_evr_for_dep("1.0-2", "1.0-1"), Ordering::Greater);
        assert_eq!(compare_evr_for_dep("1.0-1", "1.0-1"), Ordering::Equal);
    }
}
