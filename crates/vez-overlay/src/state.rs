//! Whether the extra layer still matches the deployment it was built against.
//!
//! Vez's extra layer lives in two places that outlive a lot: the rpmdb at
//! [`crate::paths::RPMDB`] and the overlay upperdir at [`crate::paths::OVERLAY_UPPER`], both
//! under `/var`. That is what makes an install survive a reboot — **a reboot does not
//! invalidate the upperdir**, and this module has nothing to do on one.
//!
//! A **deployment change** is different, and it is the case this exists for. `bootc upgrade`
//! stages a new image; on the next boot `/usr` is that new deployment, while the upperdir
//! still holds files extracted on top of the *old* one. Overlayfs merges them, so a package
//! installed months ago shadows the new base wherever their file sets overlap — including
//! `/usr/lib64` sonames, which is how an upgrade leaves a machine with a mix of two releases
//! and no obvious cause. Nothing detects that on its own; that is what [`State`] is for.
//!
//! ## The signal
//!
//! The image's own release `generation` from `/usr/share/svara/base/version.json`. It is the
//! number `docs/update-model.md` already defines as "what a machine compares", it is written
//! by the build, and it moves exactly when the deployment does — because a deployment **is**
//! an image generation. Using it means one identity for the whole update model rather than a
//! second one invented here.
//!
//! A missing or unparseable `version.json` is treated as "unknown", not as "changed": a
//! machine that cannot state its generation should not have every boot treated as an upgrade.
//! [`State::lags_deployment`] returns `None` in that case and callers report the doubt rather
//! than acting on a guess.
//!
//! ## What this module does NOT do
//!
//! It decides and records. It does not reinstall anything — that is `vez replay`, which uses
//! it — and it deliberately does not "fix" the layer by itself, because re-applying packages
//! is a root operation a user should be able to see coming.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The image's release record, written at build time. `/usr` is read-only, so this is the
/// deployment's own statement about itself.
pub const VERSION_JSON: &str = "/usr/share/svara/base/version.json";

/// What `/usr` currently is, as far as vez can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deployment {
    /// The image's release generation, e.g. `115`.
    Generation(u64),
    /// The record is missing or does not parse. Kept distinct from a generation so callers
    /// can say "I don't know" instead of inventing a number — the alternative is a machine
    /// whose generation reads as 0 reporting that every boot is an upgrade.
    Unknown,
}

/// Reads the image's release generation.
///
/// Parsed with a full JSON reader rather than a substring search for `"generation"`, because
/// the file also carries `schema`, `version`, `commit` and `built`; a regex that grabbed the
/// wrong number would silently make every boot look like a deployment change, and the failure
/// would be a replay on a machine that did not need one.
pub fn read_deployment() -> Deployment {
    read_deployment_from(Path::new(VERSION_JSON))
}

/// The parsing half of [`read_deployment`], so the "unknown" cases are testable without
/// arranging a real `/usr/share/svara/base/version.json`.
pub fn read_deployment_from(path: &Path) -> Deployment {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Deployment::Unknown;
    };
    parse_deployment(&text)
}

/// Parse a release record. `Unknown` when `generation` is absent, not a number, or negative.
pub fn parse_deployment(text: &str) -> Deployment {
    #[derive(Deserialize)]
    struct Record {
        generation: Option<i64>,
    }
    match serde_json::from_str::<Record>(text) {
        Ok(Record {
            generation: Some(g),
        }) if g >= 0 => Deployment::Generation(g as u64),
        _ => Deployment::Unknown,
    }
}

/// The extra layer's own record of what it was built against.
///
/// Written by `vez replay` once the layer matches the deployment, and by the first successful
/// install (which by definition is built against the deployment it ran on). Its **absence** is
/// meaningful and must stay harmless: a machine that has never installed anything has no layer
/// to restore, so there is nothing to replay and no state to keep.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Format version, so a future field can be added without an older vez misreading it.
    #[serde(default)]
    pub schema: Option<u32>,
    /// The deployment generation the layer was last made to match.
    #[serde(default)]
    pub applied_generation: Option<u64>,
    /// When that happened, unix seconds. Informational; nothing branches on it.
    #[serde(default)]
    pub applied_at: Option<u64>,
}

/// The current state format.
pub const SCHEMA: u32 = 1;

impl State {
    /// Read the state, or the default when there is none.
    ///
    /// A missing file is `State::default()` rather than an error — see the type's doc comment.
    /// An unreadable or corrupt file is ALSO defaulted, deliberately: the consequence of not
    /// knowing the state is one extra replay, and refusing to start is a much worse trade for
    /// a file whose only job is to save work.
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| toml::from_str(&t).ok())
            .unwrap_or_default()
    }

    /// Record that the layer now matches `generation`.
    ///
    /// Written atomically (temp + rename) so an interrupted write cannot leave a half-record
    /// that reads as "already applied" — which would silently skip a needed replay.
    pub fn record(&self, path: &Path, generation: Option<u64>) -> Result<()> {
        let next = State {
            schema: Some(SCHEMA),
            applied_generation: generation,
            applied_at: some_now(),
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let text = toml::to_string(&next).context("serialising the layer state")?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
        Ok(())
    }

    /// Does the extra layer lag the deployment?
    ///
    /// - `None` — the layer has never been built (no state), or `/usr` cannot state its
    ///   generation. Both are "cannot answer", and neither is a reason to replay: an empty
    ///   layer has nothing to restore, and replaying on an unknown generation is a guess.
    /// - `Some(true)` — the deployment moved past what the layer was built against. This is
    ///   the `bootc upgrade` case, and the layer must be re-applied or it silently shadows the
    ///   new base.
    /// - `Some(false)` — they agree.
    pub fn lags_deployment(&self, current: &Deployment) -> Option<bool> {
        let applied = self.applied_generation?;
        match current {
            Deployment::Generation(g) => Some(*g != applied),
            Deployment::Unknown => None,
        }
    }
}

/// Unix seconds, without pulling in a date crate for one field.
fn some_now() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_generation_out_of_a_real_release_record() {
        // Copied from a built image. This is the exact shape the function must handle.
        let text = r#"{
  "schema": 1,
  "image": "svara",
  "version": "0.1.0",
  "codename": "Zora",
  "commit": "389a1e3",
  "generation": 115,
  "built": "2026-10-14T10:12:03Z",
  "fedora_release": "44",
  "channel": "stable"
}"#;
        assert_eq!(parse_deployment(text), Deployment::Generation(115));
    }

    #[test]
    fn a_release_record_without_a_generation_is_unknown() {
        // Not generation 0. Zero would compare equal to nothing and unequal to everything,
        // making every boot look like an upgrade.
        assert_eq!(
            parse_deployment(r#"{"schema":1,"version":"0.1.0"}"#),
            Deployment::Unknown
        );
    }

    #[test]
    fn a_corrupt_or_unreadable_record_is_unknown_rather_than_an_error() {
        assert_eq!(parse_deployment("not json at all"), Deployment::Unknown);
        assert_eq!(parse_deployment(""), Deployment::Unknown);
        assert_eq!(
            read_deployment_from(Path::new("/nonexistent/version.json")),
            Deployment::Unknown
        );
    }

    #[test]
    fn a_negative_generation_is_unknown() {
        // A negative generation is nonsense; treating it as a u64 would wrap it to something
        // enormous and make the layer look permanently behind.
        assert_eq!(
            parse_deployment(r#"{"generation":-1}"#),
            Deployment::Unknown
        );
    }

    #[test]
    fn a_machine_that_never_installed_anything_has_nothing_to_replay() {
        // The absence of state must be harmless: this is every machine until it first installs.
        let s = State::default();
        assert_eq!(s.applied_generation, None);
        assert_eq!(s.lags_deployment(&Deployment::Generation(115)), None);
    }

    #[test]
    fn a_moved_generation_lags_and_a_same_one_does_not() {
        let s = State {
            schema: Some(SCHEMA),
            applied_generation: Some(115),
            applied_at: Some(0),
        };
        assert_eq!(s.lags_deployment(&Deployment::Generation(115)), Some(false));
        assert_eq!(
            s.lags_deployment(&Deployment::Generation(116)),
            Some(true),
            "bootc upgrade moved it forward"
        );
        // A rollback moves it BACKWARD, and that is still a different deployment whose /usr
        // the layer was not built against — so it must replay too. Comparing with `!=` rather
        // than `>` is what gets this right.
        assert_eq!(
            s.lags_deployment(&Deployment::Generation(114)),
            Some(true),
            "rollback is also a new /usr"
        );
    }

    #[test]
    fn an_unknown_current_generation_answers_i_cannot_tell() {
        let s = State {
            schema: Some(SCHEMA),
            applied_generation: Some(115),
            applied_at: None,
        };
        assert_eq!(
            s.lags_deployment(&Deployment::Unknown),
            None,
            "a machine that cannot state its generation must not have every boot treated as an upgrade"
        );
    }

    #[test]
    fn state_round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!("vez-state-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("layer-state.toml");

        // No file yet: default, and harmless.
        assert_eq!(State::load(&path), State::default());

        State::default().record(&path, Some(115)).expect("record");
        let back = State::load(&path);
        assert_eq!(back.applied_generation, Some(115));
        assert_eq!(back.schema, Some(SCHEMA));
        assert_eq!(
            back.lags_deployment(&Deployment::Generation(116)),
            Some(true)
        );

        // A corrupt file is defaulted, not fatal: one extra replay beats a machine that
        // refuses to work because a bookkeeping file got mangled.
        std::fs::write(&path, "]]] not toml [[").unwrap();
        assert_eq!(State::load(&path), State::default());

        // Recording again after a replay clears the lag.
        State::load(&path).record(&path, Some(116)).expect("record");
        assert_eq!(
            State::load(&path).lags_deployment(&Deployment::Generation(116)),
            Some(false)
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
