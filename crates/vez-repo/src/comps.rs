//! Streaming parser for `comps.xml` (yum/dnf "groups" metadata). It covers
//! what `@groupname`/`@^environmentname` install expansion and `vez group
//! list/info`/`vez environment list/info` need. Both `<group>` and
//! `<environment>` entries are parsed. `<category>` is skipped because it's
//! only a UI grouping of environments that dnf doesn't use in transactions.
//! Within a group, only `mandatory` and `default` `<packagereq>` entries are
//! collected, which is dnf's default `group install` set (`optional` members
//! only come in when asked for by name). Within an environment, only
//! `<grouplist>` group ids are collected (`<optionlist>` is skipped), which
//! is dnf's default `environment install` group set.

use quick_xml::events::Event;
use quick_xml::Reader;
use serde::{Deserialize, Serialize};

/// A single comps `<group>`. `id` is the stable machine name used by
/// `@id`/`vez group install <id>`. `name` is the human-readable `<name>`, or
/// `id` if comps has no untranslated `<name>`. `packages` is the
/// mandatory+default member list dnf installs for this group by default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub packages: Vec<String>,
}

/// A single comps `<environment>`. `id` is the stable machine name used by
/// `@^id`/`vez environment install <id>`. `name` is the human-readable
/// `<name>`, with the same untranslated-first fallback as [`Group::name`].
/// `group_ids` is the `<grouplist>` member list (`<optionlist>` excluded),
/// which is dnf's default `environment install` set. Each id is turned into
/// packages by looking it up in the same repo's parsed [`Group`]s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub id: String,
    pub name: String,
    pub group_ids: Vec<String>,
}

/// Both comps data types parsed from one `comps.xml` document. They come from
/// the same `group`/`group_gz` repomd entry, so a repo has both or neither.
#[derive(Debug, Clone, Default)]
pub struct CompsData {
    pub groups: Vec<Group>,
    pub environments: Vec<Environment>,
}

pub fn parse_comps_xml(xml: &str) -> CompsData {
    parse_comps_xml_with_types(xml, &["mandatory".to_string(), "default".to_string()])
}

/// Like [`parse_comps_xml`], but `wanted_types` (`group_package_types=`) sets
/// which `<packagereq type="...">` values count as group members instead of
/// hardcoding dnf's default of `mandatory`+`default`.
pub fn parse_comps_xml_with_types(xml: &str, wanted_types: &[String]) -> CompsData {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut groups = Vec::new();
    let mut environments = Vec::new();

    let mut in_group = false;
    let mut in_environment = false;
    let mut in_packagelist = false;
    let mut in_grouplist = false;
    let mut in_optionlist = false;
    let mut in_id = false;
    let mut in_name = false;
    let mut in_packagereq = false;
    let mut packagereq_wanted = false;

    let mut cur_id = String::new();
    let mut cur_name = String::new();
    let mut cur_packages = Vec::new();
    let mut cur_group_ids = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.local_name().as_ref() {
                b"group" => {
                    in_group = true;
                    cur_id.clear();
                    cur_name.clear();
                    cur_packages.clear();
                }
                b"environment" => {
                    in_environment = true;
                    cur_id.clear();
                    cur_name.clear();
                    cur_group_ids.clear();
                }
                b"id"
                    if (in_group || in_environment)
                        && !in_packagelist
                        && !in_grouplist
                        && !in_optionlist =>
                {
                    in_id = true
                }
                // Translated names carry an `xml:lang` attribute. dnf
                // displays and matches the untranslated `<name>` (the one
                // without that attribute) by default.
                b"name"
                    if (in_group || in_environment)
                        && !in_packagelist
                        && !in_grouplist
                        && !in_optionlist =>
                {
                    in_name = !e
                        .attributes()
                        .flatten()
                        .any(|a| a.key.as_ref() == b"xml:lang");
                }
                b"packagelist" if in_group => in_packagelist = true,
                b"packagereq" if in_packagelist => {
                    in_packagereq = true;
                    let ty = e
                        .attributes()
                        .flatten()
                        .find(|a| a.key.local_name().as_ref() == b"type")
                        .map(|a| String::from_utf8_lossy(&a.value).to_string())
                        .unwrap_or_else(|| "default".to_string());
                    packagereq_wanted = wanted_types.iter().any(|t| t == &ty);
                }
                b"grouplist" if in_environment => in_grouplist = true,
                b"optionlist" if in_environment => in_optionlist = true,
                b"groupid" if in_grouplist => in_id = true,
                _ => {}
            },
            Ok(Event::Text(t)) => {
                let text = t.unescape().unwrap_or_default().trim().to_string();
                if in_grouplist && in_id {
                    if !text.is_empty() {
                        cur_group_ids.push(text);
                    }
                } else if in_id {
                    cur_id.push_str(&text);
                } else if in_name {
                    cur_name.push_str(&text);
                } else if in_packagereq && packagereq_wanted && !text.is_empty() {
                    cur_packages.push(text);
                }
            }
            Ok(Event::End(e)) => match e.local_name().as_ref() {
                b"id" | b"groupid" => in_id = false,
                b"name" => in_name = false,
                b"packagereq" => in_packagereq = false,
                b"packagelist" => in_packagelist = false,
                b"grouplist" => in_grouplist = false,
                b"optionlist" => in_optionlist = false,
                b"group" => {
                    in_group = false;
                    if !cur_id.is_empty() {
                        groups.push(Group {
                            id: cur_id.clone(),
                            name: if cur_name.is_empty() {
                                cur_id.clone()
                            } else {
                                cur_name.clone()
                            },
                            packages: cur_packages.clone(),
                        });
                    }
                }
                b"environment" => {
                    in_environment = false;
                    if !cur_id.is_empty() {
                        environments.push(Environment {
                            id: cur_id.clone(),
                            name: if cur_name.is_empty() {
                                cur_id.clone()
                            } else {
                                cur_name.clone()
                            },
                            group_ids: cur_group_ids.clone(),
                        });
                    }
                }
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    CompsData {
        groups,
        environments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mandatory_and_default_skips_optional() {
        let xml = r#"<comps>
  <group>
    <id>fonts</id>
    <name>Fonts</name>
    <name xml:lang="fr">Polices</name>
    <packagelist>
      <packagereq type="mandatory">dejavu-sans-fonts</packagereq>
      <packagereq type="default">liberation-fonts</packagereq>
      <packagereq type="optional">google-noto-fonts</packagereq>
    </packagelist>
  </group>
  <group>
    <id>hardware-support</id>
    <name>Hardware Support</name>
    <packagelist>
      <packagereq type="mandatory">alsa-firmware</packagereq>
    </packagelist>
  </group>
</comps>"#;
        let comps = parse_comps_xml(xml);
        assert_eq!(comps.groups.len(), 2);
        assert_eq!(comps.groups[0].id, "fonts");
        assert_eq!(comps.groups[0].name, "Fonts");
        assert_eq!(
            comps.groups[0].packages,
            vec!["dejavu-sans-fonts", "liberation-fonts"]
        );
        assert_eq!(comps.groups[1].id, "hardware-support");
        assert_eq!(comps.groups[1].packages, vec!["alsa-firmware"]);
    }

    #[test]
    fn parses_environment_grouplist_skips_optionlist() {
        let xml = r#"<comps>
  <group>
    <id>fonts</id>
    <name>Fonts</name>
    <packagelist>
      <packagereq type="mandatory">dejavu-sans-fonts</packagereq>
    </packagelist>
  </group>
  <environment>
    <id>workstation-product-environment</id>
    <name>Fedora Workstation</name>
    <name xml:lang="fr">Fedora Workstation FR</name>
    <grouplist>
      <groupid>fonts</groupid>
      <groupid>hardware-support</groupid>
    </grouplist>
    <optionlist>
      <groupid>container-management</groupid>
    </optionlist>
  </environment>
</comps>"#;
        let comps = parse_comps_xml(xml);
        assert_eq!(comps.environments.len(), 1);
        let env = &comps.environments[0];
        assert_eq!(env.id, "workstation-product-environment");
        assert_eq!(env.name, "Fedora Workstation");
        assert_eq!(env.group_ids, vec!["fonts", "hardware-support"]);
    }
}
