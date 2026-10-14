//! `/etc/svara/packages.toml` — the declarative package set, and the plan computed from it.
//!
//! The point of this file is that a machine's extra packages become **data**. Everything vez
//! can already do is imperative (`vez install foo`), which means a machine's intent lives in
//! a shell history and cannot be reproduced, diffed or reviewed. A declared set can be:
//!
//! - read by `svara`'s first-login flow, so the default app set is not embedded in installer
//!   code (`config/payload.toml` reserves an `[apps]` block for exactly this);
//! - diffed before it is applied, so "what would change" is answerable without acting;
//! - copied between machines, which is what makes it worth having.
//!
//! ## What a declared set is NOT, and the rule that keeps it honest
//!
//! **A set is additive. It never removes anything and it never downgrades anything.** There
//! is no `version` that pins a package to a task, and no "not listed means uninstall". The
//! reason is that the alternative is a file whose accidental mis-edit uninstalls a user's
//! software, and packages are not a declarative resource the way a config file is: a base
//! image update can move them, a user can remove one deliberately, and neither fact is
//! visible from the file alone.
//!
//! So [`Plan::remove`] reports a package that is present and *not* declared as **extra**, not
//! as something to delete, and nothing acts on it. Whether a declared set may ever mean
//! "remove what is absent" is an open design question — the machinery for a user's deliberate
//! removal to survive (a sticky presence set rather than a ledger) is designed in
//! `docs/plan/package-manager.md` §2a and is not built.
//!
//! ## The format
//!
//! ```toml
//! # One schema number, so a file written for a newer vez is refused rather than misread.
//! schema = 1
//!
//! # Names to install. Grouped only for the reader's benefit; order does not matter and
//! # nothing depends on it.
//! packages = ["gimp", "inkscape"]
//!
//! # Glob patterns, resolved against what is already installed. Useful for "everything from
//! # this family that is present", which cannot be written as a list.
//! patterns = ["kde-*"]
//! ```
//!
//! Every field is optional. A file with none of them is valid and declares the empty set,
//! which is a meaningful thing to declare and must not be an error.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

/// The highest `schema` this build understands.
///
/// A file declaring a higher number is REFUSED, not read leniently. The failure a schema
/// number exists to prevent is a newer file being silently half-understood — an old vez
/// ignoring a field it does not know and reporting success for a set it did not apply.
pub const SCHEMA: u32 = 1;

/// A parsed `/etc/svara/packages.toml`.
#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredSet {
    /// Format version. Absent means the current one; see [`SCHEMA`].
    #[serde(default)]
    pub schema: Option<u32>,
    /// Package names to install, exactly as they would be given to `vez install`.
    #[serde(default)]
    pub packages: Vec<String>,
    /// Glob patterns resolved against what is already installed.
    ///
    /// Deliberately resolved against the *installed* set and not against repo candidates: a
    /// pattern that matched repo candidates would install every package whose name happens
    /// to start with a prefix, which is not what anyone writing `kde-*` means.
    #[serde(default)]
    pub patterns: Vec<String>,
}

impl DeclaredSet {
    /// Parse a set from TOML text.
    ///
    /// `deny_unknown_fields` is a deliberate departure from the "ignore unknown keys" rule
    /// that `config/payload.toml` follows, and the difference is the audience. The payload is
    /// a machine-written contract between a release and a CLI, so a newer writer and an older
    /// reader is the normal case and ignoring the extra key is correct. This file is
    /// human-written and hand-edited, so an unknown key is almost always a typo —
    /// `package = [...]` instead of `packages = [...]` — and the failure mode of ignoring it
    /// is a promised install that silently does not happen. Rejecting it costs a clear
    /// message and saves a confusing one.
    pub fn parse(text: &str) -> Result<Self> {
        let set: Self = toml::from_str(text).context("parsing the declared package set")?;
        set.validate()?;
        Ok(set)
    }

    /// Read a set from disk. A missing file is NOT an error: the absence of a declared set is
    /// a machine that declares nothing, which is every machine until someone writes one.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).with_context(|| format!("reading {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Reject a file this build cannot faithfully apply.
    pub fn validate(&self) -> Result<()> {
        if let Some(schema) = self.schema {
            if schema > SCHEMA {
                bail!(
                    "the declared package set is schema {schema}, and this vez understands {SCHEMA}.\n\
                     Refusing rather than applying part of it: a newer file may declare something\n\
                     this build would silently ignore. Update vez (or the base image) first."
                );
            }
            if schema == 0 {
                bail!("the declared package set says `schema = 0`, which no vez has ever written");
            }
        }
        for name in &self.packages {
            if name.trim().is_empty() {
                bail!("the declared package set contains an empty package name");
            }
        }
        for pat in &self.patterns {
            if pat.trim().is_empty() {
                bail!("the declared package set contains an empty pattern");
            }
        }
        Ok(())
    }

    /// Every declared name: the explicit list plus the installed names its patterns match.
    ///
    /// Sorted and deduplicated so the plan is stable, which matters because a plan that
    /// reorders between runs is one nobody can diff.
    pub fn resolve_names(&self, installed: &[String]) -> BTreeSet<String> {
        let mut out: BTreeSet<String> = self
            .packages
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        for pattern in &self.patterns {
            for name in installed {
                if vez_core::glob_match(pattern, name) {
                    out.insert(name.clone());
                }
            }
        }
        out
    }
}

/// What a declared set asks a machine to change.
///
/// Computed, never acted on directly — [`Plan`] is what `vez diff` prints and what
/// `vez apply` executes, so the two cannot disagree about what would happen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Declared and not installed. `apply` installs these.
    pub install: Vec<String>,
    /// Declared and already installed. Listed so a user can see the set was honoured, and
    /// the reason `apply` twice does nothing the second time.
    pub present: Vec<String>,
    /// Installed, not declared. **Reported, never removed** — see the module docs.
    pub extra: Vec<String>,
}

impl Plan {
    /// Is there nothing to do?
    pub fn is_empty(&self) -> bool {
        self.install.is_empty()
    }

    /// Compute the plan for a declared set against what is installed.
    ///
    /// `tracked` is the set of names vez itself installed — packages that are a user's extra
    /// layer rather than part of the image. It is what makes `extra` meaningful: without it,
    /// every one of the image's hundreds of base packages would be "extra", which is true and
    /// useless.
    pub fn compute(declared: &DeclaredSet, installed: &[String], tracked: &[String]) -> Self {
        let names = declared.resolve_names(installed);
        let installed_set: BTreeSet<&str> = installed.iter().map(String::as_str).collect();
        let tracked_set: BTreeSet<&str> = tracked.iter().map(String::as_str).collect();

        let mut plan = Plan::default();
        for name in names {
            if installed_set.contains(name.as_str()) {
                plan.present.push(name);
            } else {
                plan.install.push(name);
            }
        }
        for name in tracked_set {
            // Only a package vez installed can be "extra". A base-image package is the
            // image's business, not the set's.
            if !plan.present.iter().any(|p| p == name) && !plan.install.iter().any(|p| p == name) {
                plan.extra.push(name.to_string());
            }
        }
        plan.present.sort();
        plan.extra.sort();
        plan
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(text: &str) -> DeclaredSet {
        DeclaredSet::parse(text).expect("should parse")
    }

    #[test]
    fn an_empty_file_declares_the_empty_set() {
        // Meaningful, not an error: a machine may declare nothing.
        let s = DeclaredSet::parse("").expect("empty is valid");
        assert!(s.packages.is_empty());
        assert!(s.patterns.is_empty());
        assert_eq!(s.schema, None);
    }

    #[test]
    fn parses_the_documented_format() {
        let s = set("schema = 1\npackages = [\"gimp\", \"inkscape\"]\npatterns = [\"kde-*\"]\n");
        assert_eq!(s.schema, Some(1));
        assert_eq!(s.packages, vec!["gimp", "inkscape"]);
        assert_eq!(s.patterns, vec!["kde-*"]);
    }

    #[test]
    fn a_newer_schema_is_refused_not_partly_read() {
        // The whole reason the field exists. A file written for a future vez might declare
        // something this build would ignore, and reporting success for a set it did not fully
        // apply is the failure a schema number prevents.
        let err = DeclaredSet::parse("schema = 2\npackages = [\"gimp\"]\n").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("schema 2"),
            "should name the file's schema: {msg}"
        );
        assert!(msg.contains("understands 1"), "should name ours: {msg}");
    }

    #[test]
    fn schema_one_is_accepted() {
        assert!(DeclaredSet::parse("schema = 1\n").is_ok());
    }

    #[test]
    fn schema_zero_is_a_typo_not_a_version() {
        assert!(DeclaredSet::parse("schema = 0\n").is_err());
    }

    #[test]
    fn an_unknown_key_is_rejected() {
        // `package` for `packages` is the typo this catches. Ignoring it would silently
        // install nothing while reporting success.
        let err = DeclaredSet::parse("package = [\"gimp\"]\n").unwrap_err();
        assert!(
            format!("{err:#}").to_lowercase().contains("unknown"),
            "got: {err:#}"
        );
    }

    #[test]
    fn empty_names_and_patterns_are_rejected() {
        assert!(DeclaredSet::parse("packages = [\"\"]\n").is_err());
        assert!(DeclaredSet::parse("patterns = [\"  \"]\n").is_err());
    }

    #[test]
    fn patterns_resolve_against_installed_names_only() {
        let s = set("packages = [\"vim\"]\npatterns = [\"kde-*\"]\n");
        let installed = vec![
            "kde-plasma".to_string(),
            "kde-foo".to_string(),
            "htop".to_string(),
        ];
        let names = s.resolve_names(&installed);
        assert!(names.contains("vim"));
        assert!(names.contains("kde-plasma"));
        assert!(names.contains("kde-foo"));
        assert!(
            !names.contains("htop"),
            "a pattern must not pull in what it does not match"
        );
        // The pattern must NOT match repo candidates; there are none in this signature, which
        // is the point: resolve_names can only see installed names.
    }

    #[test]
    fn resolve_is_sorted_and_deduplicated() {
        let s = set("packages = [\"vim\", \"gimp\", \"vim\"]\npatterns = [\"kde-*\"]\n");
        let installed = vec!["kde-b".to_string(), "kde-a".to_string()];
        let names: Vec<String> = s.resolve_names(&installed).into_iter().collect();
        assert_eq!(names, vec!["gimp", "kde-a", "kde-b", "vim"]);
    }

    #[test]
    fn plan_splits_declared_into_install_and_present() {
        let s = set("packages = [\"gimp\", \"vim\"]\n");
        let installed = vec!["vim".to_string(), "htop".to_string()];
        let plan = Plan::compute(&s, &installed, &["vim".to_string(), "htop".to_string()]);
        assert_eq!(plan.install, vec!["gimp"]);
        assert_eq!(plan.present, vec!["vim"]);
        // htop is installed by vez and not declared, so it is extra — reported, not removed.
        assert_eq!(plan.extra, vec!["htop"]);
        assert!(!plan.is_empty());
    }

    #[test]
    fn an_unlisted_base_package_is_not_extra() {
        // Only what vez installed counts. Otherwise every base-image package would be
        // reported, which is true and useless.
        let s = set("packages = [\"gimp\"]\n");
        let installed = vec!["gimp".to_string(), "glibc".to_string(), "bash".to_string()];
        let plan = Plan::compute(&s, &installed, &[]);
        assert!(
            plan.extra.is_empty(),
            "base packages must not be reported: {:?}",
            plan.extra
        );
    }

    #[test]
    fn applying_a_converged_set_plans_nothing() {
        // `apply` twice changes nothing the second time: the check the plan promises.
        let s = set("packages = [\"gimp\"]\n");
        let installed = vec!["gimp".to_string()];
        let plan = Plan::compute(&s, &installed, &["gimp".to_string()]);
        assert!(plan.is_empty());
        assert_eq!(plan.present, vec!["gimp"]);
        assert!(plan.extra.is_empty());
    }

    #[test]
    fn a_missing_file_is_an_empty_set_not_an_error() {
        let s = DeclaredSet::load(Path::new("/nonexistent/packages.toml"))
            .expect("absence is harmless");
        assert!(s.packages.is_empty());
    }
}
