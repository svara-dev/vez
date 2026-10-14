use serde::{Deserialize, Serialize};

/// One `vez versionlock` entry. As in dnf5, a lock pins a name to the exact
/// `epoch:version-release` (and, for an arch-specific package, the exact
/// arch) it had *when it was locked*. `evr`/`arch` are `None` when the name
/// wasn't installed at lock time, so there was nothing to record. Such a lock
/// blocks nothing for now, same as dnf5, where a versionlock entry for a
/// package that isn't installed has no version to restrict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionLock {
    pub name: String,
    pub evr: Option<String>,
    pub arch: Option<String>,
}

impl VersionLock {
    /// `true` if `evr`/`arch` (a candidate's own fields) match what this lock
    /// pins the name to. On a mismatch the candidate must never be selected
    /// while the lock exists, whether it's picked directly
    /// (`install`/`upgrade`) or pulled in as someone else's dependency.
    pub fn allows(&self, evr: &str, arch: &str) -> bool {
        self.evr.as_deref().is_none_or(|locked| locked == evr)
            && self.arch.as_deref().is_none_or(|locked| locked == arch)
    }
}

/// Serialized as `name\tevr\tarch`, with `*` for an unconstrained field. One
/// entry per line so the on-disk file stays easy to diff and grep, like the
/// old plain name list.
impl std::fmt::Display for VersionLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}\t{}\t{}",
            self.name,
            self.evr.as_deref().unwrap_or("*"),
            self.arch.as_deref().unwrap_or("*")
        )
    }
}

impl std::str::FromStr for VersionLock {
    type Err = ();

    fn from_str(line: &str) -> Result<Self, ()> {
        let mut parts = line.splitn(3, '\t');
        let name = parts.next().ok_or(())?.to_string();
        let evr = parts.next().filter(|s| *s != "*").map(str::to_string);
        let arch = parts.next().filter(|s| *s != "*").map(str::to_string);
        Ok(Self { name, evr, arch })
    }
}
