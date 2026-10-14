//! Copr repo support (`vez copr enable/disable`), modeled on the copr plugin
//! in dnf's `dnf-plugins-core`. Given `owner/project`, work out which Copr
//! chroot matches this machine and fetch the `.repo` file Copr generates for
//! it, so the user doesn't have to guess a chroot name.
//!
//! Chroot names are `<distname>-<version>-<arch>` (e.g. `fedora-44-x86_64`).
//! `<distname>`/`<version>` come from `/etc/os-release`: `ID_LIKE` (falling
//! back to `ID`) picks the Copr chroot family and `VERSION_ID` picks the
//! version. Svara's `/etc/os-release` sets `ID=svara`, `ID_LIKE="fedora"`,
//! `VERSION_ID=0.1`. Copr has no `svara-*` chroots, so `ID_LIKE` pointing at
//! `fedora` is what resolves a Svara machine to a Fedora chroot and not a
//! nonexistent `svara-*` one.
//!
//! `ID_LIKE` is therefore load-bearing for Svara, not a nicety: without it,
//! `vez copr enable` would ask Copr for a chroot that cannot exist.

use crate::get_with_retry;
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const COPR_HOSTNAME: &str = "copr.fedorainfracloud.org";
const COPR_URL: &str = "https://copr.fedorainfracloud.org";

/// The handful of `/etc/os-release` fields chroot-guessing needs.
struct OsRelease {
    id: String,
    id_like: String,
    version_id: String,
}

impl OsRelease {
    fn load() -> Result<Self> {
        let text = fs::read_to_string("/etc/os-release")
            .or_else(|_| fs::read_to_string("/usr/lib/os-release"))
            .context("reading /etc/os-release")?;
        Ok(Self::parse(&text))
    }

    fn parse(text: &str) -> Self {
        let mut fields: HashMap<String, String> = HashMap::new();
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            fields.insert(
                key.trim().to_string(),
                value.trim().trim_matches('"').to_string(),
            );
        }
        Self {
            id: fields.get("ID").cloned().unwrap_or_default(),
            id_like: fields.get("ID_LIKE").cloned().unwrap_or_default(),
            version_id: fields.get("VERSION_ID").cloned().unwrap_or_default(),
        }
    }

    /// `ID` followed by the words of `ID_LIKE`, in order. `os-release` lists
    /// `ID_LIKE` from closest to furthest upstream (AlmaLinux ships
    /// `ID_LIKE="rhel centos fedora"`: RHEL-compatible first, Fedora only as
    /// a loose last resort). Scanning in this order and taking the first word
    /// [`guess_chroot_from`] recognizes picks the most specific family, where
    /// a `contains()` check would pick whichever test happened to run first.
    fn family_words(&self) -> Vec<String> {
        std::iter::once(self.id.as_str())
            .chain(self.id_like.split_whitespace())
            .map(|w| w.to_lowercase())
            .collect()
    }
}

/// This machine's architecture in Copr's naming. Matches `uname -m`, which is
/// also what dnf's `$basearch` resolves to on every arch Copr supports.
fn basearch() -> &'static str {
    std::env::consts::ARCH
}

/// The Fedora release this machine's base image is built from, as a string
/// like `44`.
///
/// Read from Fedora's own release file, which the base image carries:
/// `/etc/fedora-release` contains `Fedora release 44 (Forty Four)`. Svara's
/// `VERSION_ID` cannot be used for this — it is Svara's version, and on a
/// derivative the two are unrelated. See the `fedora` arm of
/// [`guess_chroot_from`].
///
/// `None` when the file is absent or does not parse, which is the correct
/// answer on a non-Fedora machine: the caller then falls back to
/// `VERSION_ID`, where the field does mean the release.
fn fedora_release_version() -> Option<String> {
    let text = fs::read_to_string("/etc/fedora-release").ok()?;
    // "Fedora release 44 (Forty Four)" — the release is the token after
    // "release". Parsing positionally rather than by a fixed slice keeps this
    // working for "Fedora release 44 (Forty Four)" and for a hypothetical
    // single-word suffix.
    let mut words = text.split_whitespace();
    while let Some(w) = words.next() {
        if w.eq_ignore_ascii_case("release") {
            let v = words.next().unwrap_or_default();
            // A rawhide base spells it `Rawhide`; pass that through so the
            // caller's existing rawhide branch handles it.
            return if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            };
        }
    }
    None
}

/// Guesses the Copr chroot for this machine, e.g. `fedora-44-x86_64`. Follows
/// `_guess_chroot` from dnf's `copr` plugin, extended to read `ID_LIKE`.
/// dnf's plugin only sees `NAME`/`VERSION_ID` through
/// `platform.freedesktop_os_release`, so it can't do this, and Svara's `ID`
/// (`svara`) will never be a Copr chroot family by itself.
pub fn guess_chroot() -> Result<String> {
    let os_release = OsRelease::load()?;
    // Read the base image's Fedora release once, here, and pass it in: the
    // decision logic below stays a pure function of its inputs, which is what
    // lets the tests below assert the Svara case at all. A test cannot write
    // `/etc/fedora-release`.
    let fedora_release = fedora_release_version();
    guess_chroot_from(&os_release, fedora_release.as_deref())
}

fn guess_chroot_from(os_release: &OsRelease, fedora_release: Option<&str>) -> Result<String> {
    let arch = basearch();
    let version = os_release.version_id.as_str();

    // The first recognized family word wins. See the doc comment on
    // `family_words`: going by order, instead of by whether a substring
    // appears anywhere, is what makes a RHEL derivative that also lists
    // `fedora` in `ID_LIKE` resolve to `epel-*` and not `fedora-*`.
    for word in os_release.family_words() {
        let chroot = match word.as_str() {
            "fedora" => {
                // THE VERSION IS THE BASE IMAGE'S FEDORA RELEASE, NOT OURS.
                // `VERSION_ID` in Svara's os-release is Svara's own version
                // (`0.1`), because that is what the field means for the distro
                // we are. Copr chroots are named after Fedora releases, so
                // using it would ask for `fedora-0.1-<arch>` and 404 — every
                // `vez copr enable` would fail on a Svara machine, and the
                // error would blame the user's repo name.
                //
                // Fedora's own release file is authoritative when present, so
                // it is preferred even when it disagrees with `VERSION_ID`.
                // Falling back to `VERSION_ID` keeps a plain Fedora system —
                // where the two agree — working if that file is ever absent.
                let fedora_version = fedora_release.unwrap_or(version);
                if fedora_version.is_empty() || fedora_version.eq_ignore_ascii_case("rawhide") {
                    format!("fedora-rawhide-{arch}")
                } else {
                    format!("fedora-{fedora_version}-{arch}")
                }
            }
            "mageia" => {
                if version.eq_ignore_ascii_case("cauldron") {
                    format!("mageia-cauldron-{arch}")
                } else {
                    format!("mageia-{version}-{arch}")
                }
            }
            "opensuse" | "suse" => {
                if version.to_lowercase().contains("tumbleweed") {
                    format!("opensuse-tumbleweed-{arch}")
                } else {
                    format!("opensuse-leap-{version}-{arch}")
                }
            }
            "rhel" | "centos" | "almalinux" | "rocky" => {
                format!(
                    "epel-{}-{arch}",
                    version.split('.').next().unwrap_or(version)
                )
            }
            _ => continue,
        };
        return Ok(chroot);
    }

    // Nothing recognized at all (unknown ID, no ID_LIKE). EPEL's chroot
    // naming is the closest thing Copr has to a generic fallback.
    Ok(format!(
        "epel-{}-{arch}",
        version.split('.').next().unwrap_or(version)
    ))
}

/// Splits `owner/project`. dnf's copr plugin also accepts a 3-part
/// `hostname/owner/project` form for other Copr instances. That isn't
/// supported here; vez only talks to the main Fedora Copr instance.
fn split_project(owner_project: &str) -> Result<(&str, &str)> {
    let mut parts = owner_project.splitn(2, '/');
    let owner = parts.next().filter(|s| !s.is_empty());
    let project = parts.next().filter(|s| !s.is_empty());
    match (owner, project) {
        (Some(o), Some(p)) => Ok((o, p)),
        _ => bail!("expected `owner/project` (e.g. `atim/starship`), got '{owner_project}'"),
    }
}

/// The `.repo` filename vez writes for an enabled Copr project. It matches
/// the `_copr:<hostname>:<owner>:<project>.repo` naming of dnf's copr plugin,
/// so on a system with both tools they don't collide or add the same repo
/// twice under different names.
fn repo_filename(repo_dir: &Path, owner: &str, project: &str) -> PathBuf {
    repo_dir.join(format!("_copr:{COPR_HOSTNAME}:{owner}:{project}.repo"))
}

/// Enables a Copr project: guesses (or uses the given) chroot, downloads
/// the `.repo` file Copr generates for that owner/project/chroot, and
/// writes it into `repo_dir`. Returns the path written.
pub async fn enable(
    client: &reqwest::Client,
    owner_project: &str,
    chroot: Option<&str>,
    repo_dir: &Path,
) -> Result<PathBuf> {
    let (owner, project) = split_project(owner_project)?;
    let chroot = match chroot {
        Some(c) => c.to_string(),
        None => guess_chroot().context("guessing Copr chroot from /etc/os-release")?,
    };
    let parts: Vec<&str> = chroot.rsplitn(2, '-').collect();
    let (arch, short_chroot) = match parts.as_slice() {
        [arch, short] => (*arch, *short),
        _ => bail!("bad chroot '{chroot}', expected '<distname>-<version>-<arch>'"),
    };

    let url =
        format!("{COPR_URL}/coprs/{owner}/{project}/repo/{short_chroot}/dnf.repo?arch={arch}");
    let resp = get_with_retry(client, &url).await?;
    if resp.status >= 400 {
        bail!(
            "Copr has no build of '{owner}/{project}' for chroot '{chroot}' (HTTP {})",
            resp.status
        );
    }
    let body = resp
        .text()
        .await
        .with_context(|| format!("reading response body from {url}"))?;

    fs::create_dir_all(repo_dir).with_context(|| format!("creating {}", repo_dir.display()))?;
    let path = repo_filename(repo_dir, owner, project);
    fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Disables (removes) the `.repo` file of a previously enabled Copr project.
/// Not an error if it was never enabled, same as `vez remove` on a package
/// that isn't installed.
pub fn disable(owner_project: &str, repo_dir: &Path) -> Result<()> {
    let (owner, project) = split_project(owner_project)?;
    let path = repo_filename(repo_dir, owner, project);
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svara_resolves_to_the_base_images_fedora_release() {
        // The Svara identity, exactly as `system_files/usr/lib/os-release` sets
        // it: `ID=svara`, `ID_LIKE="fedora"`, and `VERSION_ID` is **Svara's**
        // version, `0.1`. Copr chroots are named after Fedora releases, so the
        // base image's release (from `/etc/fedora-release`) is what must be
        // used. Using `VERSION_ID` here asked Copr for `fedora-0.1-<arch>`,
        // which does not exist, so every `vez copr enable` failed on Svara.
        let os_release = OsRelease {
            id: "svara".into(),
            id_like: "fedora".into(),
            version_id: "0.1".into(),
        };
        let chroot = guess_chroot_from(&os_release, Some("44")).unwrap();
        assert_eq!(chroot, format!("fedora-44-{}", basearch()));
        // And the base release wins even if VERSION_ID happens to look like one.
        let chroot = guess_chroot_from(&os_release, Some("45")).unwrap();
        assert_eq!(chroot, format!("fedora-45-{}", basearch()));
    }

    #[test]
    fn plain_fedora_falls_back_to_version_id_when_the_release_file_is_absent() {
        // Without `/etc/fedora-release` there is nothing better to go on, and on
        // Fedora itself `VERSION_ID` *is* the release, so the fallback is exact.
        let os_release = OsRelease {
            id: "fedora".into(),
            id_like: String::new(),
            version_id: "44".into(),
        };
        let chroot = guess_chroot_from(&os_release, None).unwrap();
        assert_eq!(chroot, format!("fedora-44-{}", basearch()));
    }

    #[test]
    fn guesses_fedora_rawhide() {
        let os_release = OsRelease {
            id: "fedora".into(),
            id_like: String::new(),
            version_id: "rawhide".into(),
        };
        let chroot = guess_chroot_from(&os_release, None).unwrap();
        assert_eq!(chroot, format!("fedora-rawhide-{}", basearch()));
        // Recorded as "Rawhide" in the release file, which is how the base
        // image would spell it; the branch is case-insensitive either way.
        let chroot = guess_chroot_from(&os_release, Some("Rawhide")).unwrap();
        assert_eq!(chroot, format!("fedora-rawhide-{}", basearch()));
    }

    #[test]
    fn guesses_epel_chroot_for_rhel_like() {
        let os_release = OsRelease {
            id: "almalinux".into(),
            id_like: "rhel centos fedora".into(),
            version_id: "9.3".into(),
        };
        // "fedora" also appears in id_like here (common in RHEL-family
        // os-release files), but rhel/centos should win: EPEL is the right
        // chroot family for a RHEL derivative.
        //
        // A Fedora release file must not change this: the EPEL arm never reads
        // it. Passing one proves the base-release override is scoped to the
        // `fedora` family and does not leak into a RHEL derivative's answer.
        let chroot = guess_chroot_from(&os_release, Some("44")).unwrap();
        assert_eq!(chroot, format!("epel-9-{}", basearch()));
    }

    #[test]
    fn splits_owner_project() {
        assert_eq!(
            split_project("atim/starship").unwrap(),
            ("atim", "starship")
        );
        assert!(split_project("no-slash").is_err());
    }

    #[test]
    fn repo_filename_matches_dnf_copr_plugin_convention() {
        let path = repo_filename(Path::new("/etc/yum.repos.d"), "atim", "starship");
        assert_eq!(
            path,
            PathBuf::from("/etc/yum.repos.d/_copr:copr.fedorainfracloud.org:atim:starship.repo")
        );
    }
}
