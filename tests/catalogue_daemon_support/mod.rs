#![allow(dead_code)]

use std::path::Path;
use std::time::{Duration, Instant};

use keyless::cmd::ls::ls;
use keyless::config::Config;
use keyless::daemon::config::DaemonConfig;
use keyless::ipc::client::Client;
use keyless::ipc::protocol::{Reply, Request};
use keyless::store::Resolution;

use crate::support::client::write_secrets;
use crate::support::short_socket_path;

/// The value the stand-in vendor injects. Never asserted against a store's
/// config — only against what came back through the socket.
pub const DECOY: &str = "decoy-Cat4-derived-name-answered-0912";

/// One vault, which is what the mint's `vault` coordinate is taken from.
pub const ONE_VAULT: &str = r#"{"vaults":[{"name":"personal","id":"V1"}]}"#;

/// A listing holding the titles named, all live.
pub fn listing_of(titles: &[&str]) -> String {
    let items: Vec<String> = titles
        .iter()
        .enumerate()
        .map(|(nth, title)| {
            // The id is bound rather than interpolated inline, so the literal
            // below reads as a template to `tests/publication.rs`'s coordinate
            // scanner. A spelled-out `It3m{nth}` is not a metavariable there and
            // lands as an unallowlisted coordinate.
            let id = format!("It3m{nth}");
            format!(
                r#"{{"id":"{id}","share_id":"ShAr3","state":"Active","title":"{title}","item_type":"login"}}"#
            )
        })
        .collect();
    format!(r#"{{"items":[{}]}}"#, items.join(","))
}

/// A daemon over one Proton vault and an EMPTY `secrets` map.
///
/// Empty on purpose: every name these cases resolve is one nobody declared, so
/// a fixture with declarations would prove nothing about deriving them.
///
/// The listing TTL is the crate's own default, deliberately. It was 1 ms here
/// while the rebuilder still read through the shared cache like any other
/// reader, and that hid the defect rather than testing around it: on a real
/// install the default is 60 s, so a rebuild queued by a miss would have spent
/// a minute reading a listing fetched before the item existed. The rebuilder's
/// own adapter now refuses a cached listing, so the fixture no longer needs a
/// TTL nobody runs with.
pub fn daemon_over(dir: &Path, vendor: &Path) -> DaemonConfig {
    crate::support::generations::publish_generation(&dir.join("session"));
    let credentials = dir.join("proton.json");
    write_secrets(
        &credentials,
        &[("AGENT_TOKEN", "token-decoy"), ("LOCAL_KEY", "key-decoy")],
    );
    serde_json::from_str(&format!(
        r#"{{"socket":"{socket}","audit":"{audit}",
             "cache_ttl_seconds":0,"idle_timeout_seconds":5,
             "stores":{{"proton":{{"enabled":true,"binary":"{vendor}",
                                   "session_dir":"{session}",
                                   "credentials_file":"{credentials}",
                                   "credentials":{{"PROTON_PASS_PERSONAL_ACCESS_TOKEN":"AGENT_TOKEN",
                                                   "PROTON_PASS_ENCRYPTION_KEY":"LOCAL_KEY"}},
                                   "timeout_ms":60000}}}},
             "secrets":{{}}}}"#,
        socket = short_socket_path(dir).display(),
        audit = dir.join("audit.jsonl").display(),
        session = dir.join("session").display(),
        credentials = credentials.display(),
        vendor = vendor.display(),
    ))
    .expect("valid daemon config")
}

/// A resolution in one word.
///
/// [`Resolution`] carries a [`keyless::secret::Secret`] and so implements no
/// `Debug` — which is the point of that type. A panic message needs a word for
/// which arm came back, and this is it, with nothing from inside the arm.
pub fn arm(resolution: &Resolution) -> &'static str {
    match resolution {
        Resolution::Found { .. } => "found",
        Resolution::NotFound { .. } => "not-found",
        Resolution::Failed { .. } => "failed",
        Resolution::Ambiguous { .. } => "ambiguous",
        Resolution::Refused { .. } => "refused",
    }
}

/// Wait until the daemon lists `name`, or give up.
///
/// Polling the SOCKET rather than the index: a test that reached into the
/// catalogue would be asserting against the implementation, and this is the
/// only view a caller has.
pub fn wait_until_served(socket: &Path, name: &str) -> Vec<String> {
    let client = Client::new(socket.to_path_buf(), Duration::from_secs(3));
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = Vec::new();
    while Instant::now() < deadline {
        if let Ok(Reply::Info { names }) = client.request(&Request::names()) {
            if names.iter().any(|listed| listed == name) {
                return names;
            }
            last = names;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("`{name}` never reached the listing; it held {last:?}");
}

/// The listing, as a parser gets it.
pub fn listing(config: &Config) -> (String, String) {
    let mut out: Vec<u8> = Vec::new();
    let mut err: Vec<u8> = Vec::new();
    ls(config, false, &mut out, &mut err).expect("writing to a Vec cannot fail");
    (
        String::from_utf8(out).expect("utf-8"),
        String::from_utf8(err).expect("utf-8"),
    )
}
