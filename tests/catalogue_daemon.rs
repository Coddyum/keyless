//! What a session can learn about the names behind the daemon.
//!
//! # The defect this file is the control for
//!
//! `Op::Names` had a handler in the daemon and no sender anywhere in the crate,
//! so `keyless ls` on a machine whose secrets live behind the daemon printed
//! NOTHING — on exactly the installs where the session's own config is empty by
//! design and the listing is the only way to find out a name exists.
//!
//! Every assertion here is about NAMES. A client may learn what the daemon will
//! serve; it may never learn what a store HOLDS, which is why no test below
//! looks for a vault, a title, a field or a count.

#![cfg(any(target_os = "macos", keyless_force_xnu))]

mod catalogue_daemon_support;
mod support;

use std::path::Path;
use std::time::{Duration, Instant};

use keyless::store::{Invocation, Resolution, build};

use catalogue_daemon_support::{
    DECOY, ONE_VAULT, arm, daemon_over, listing, listing_of, wait_until_served,
};
use support::backend::Backend;
use support::client::{client_config, write_secrets};
use support::daemon::{daemon_config, policy_allowing_self, start_daemon};
use support::proton::{set_catalogue_listing, stub_pass_cli_catalogue};
use support::scratch;

/// How long the vendor tallies must sit still before a rebuild is called done.
///
/// Sized against ONE gap: a rebuild is a `vault list` and then one `item list`
/// per vault, so the longest a running rebuild can leave the tallies unmoved is
/// the time to spawn one stub process. The worker's idle wait is unbounded and
/// wakes on its condvar, so there is no polling interval to cover any more —
/// this was 750 ms against a 250 ms `WORKER_POLL` that no longer exists, and it
/// stays there as headroom for a loaded machine rather than as a number derived
/// from anything.
///
/// A ceiling, never a measurement: a machine slower than this goes RED at the
/// deadline in [`settle`] rather than green.
const QUIET: Duration = Duration::from_millis(750);

/// Wait until no rebuild is running or pending.
///
/// # Why waiting for the NAME is not enough
///
/// `wait_until_served` returns the moment an index containing the name exists,
/// which says nothing about whether another rebuild is still in flight — and
/// while no index exists at all, every `Op::Names` the poll sends queues one.
/// A test that mutated the vault at that point could have its change read by a
/// rebuild it did not ask for, and its first resolve would then HIT: the case
/// would report a pass having proved nothing about the retry.
///
/// The observable is the stub's own spawn tallies. Two conditions together:
/// the two counts are EQUAL, which rules out a rebuild sitting between its
/// vault listing and its item listing, and neither has moved for [`QUIET`],
/// which rules out one starting. After that the only producers left are a
/// resolve miss and an `Op::Names` over a daemon with no index, and the caller
/// controls both.
fn settle(dir: &Path) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let before = (
            support::proton::vault_list_count(dir),
            support::proton::listing_count(dir),
        );
        std::thread::sleep(QUIET);
        let after = (
            support::proton::vault_list_count(dir),
            support::proton::listing_count(dir),
        );
        if before == after && after.0 == after.1 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the vendor tallies never settled: {before:?} then {after:?}"
        );
    }
}

#[test]
fn ls_over_an_empty_session_config_prints_what_the_daemon_serves() {
    let dir = scratch("ls-serves");
    let mut config = daemon_config(&dir);
    config.secrets.insert(
        "DECLARED_BEHIND_THE_DAEMON".to_owned(),
        serde_json::from_str(r#"{"store":"file"}"#).expect("valid"),
    );
    write_secrets(
        &config.stores.file.path,
        &[("DECLARED_BEHIND_THE_DAEMON", "unread-by-this-test")],
    );
    let running = start_daemon(&config, policy_allowing_self());

    // The session's own config declares no secret at all — the case that
    // printed an empty listing before `Request::names` existed.
    let session = client_config(running.socket(), 3_000);
    assert!(
        session.secrets.is_empty(),
        "the fixture must declare nothing"
    );

    let (listed, complaints) = listing(&session);
    assert!(complaints.is_empty(), "{complaints}");

    let row = listed
        .lines()
        .find(|line| line.starts_with("DECLARED_BEHIND_THE_DAEMON"))
        .unwrap_or_else(|| panic!("the daemon's name is not in the listing:\n{listed}"));
    let fields: Vec<&str> = row.split('\t').collect();
    // The four-field contract is load-bearing and unchanged: a daemon row says
    // `daemon` and then says nothing, because location and note would both be
    // things the client is not allowed to learn.
    assert_eq!(fields.len(), 4, "{row}");
    assert_eq!(fields[1], "daemon", "{row}");
    assert_eq!(fields[2], "-", "{row}");
    assert_eq!(fields[3], "-", "{row}");

    // The negative control for the whole file: the value the daemon holds for
    // that name is not in the listing, and neither is the store path.
    assert!(!listed.contains("unread-by-this-test"), "{listed}");
}

#[test]
fn a_daemon_that_cannot_answer_leaves_the_local_listing_standing() {
    // An absent daemon must not turn a listing into an error: a hard failure
    // here reads as an empty vault, which is the one wrong answer.
    let dir = scratch("ls-absent");
    let mut session = client_config(&dir.join("nothing-is-bound-here.sock"), 300);
    session.secrets.insert(
        "LOCAL".to_owned(),
        serde_json::from_str(r#"{"note":"still mine"}"#).expect("valid"),
    );

    let (listed, complaints) = listing(&session);
    assert!(listed.starts_with("LOCAL"), "{listed}");
    assert!(listed.contains("still mine"), "{listed}");
    assert!(
        complaints.contains("could not say what it serves"),
        "the degrade is said once, on stderr: {complaints:?}"
    );
}

#[test]
fn an_item_added_after_the_daemon_started_is_usable_after_one_retry() {
    // C1, and the whole point of the effort: no `sudo`, no restart, and no
    // edit to a root-owned config between the miss and the value.
    let dir = scratch("catalogue-new-item");
    let vendor = stub_pass_cli_catalogue(
        &dir,
        &Backend::Injects(DECOY),
        ONE_VAULT,
        &listing_of(&["decoy"]),
        "{}",
    );
    let config = daemon_over(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());
    let client = client_config(running.socket(), 3_000);
    let registry = build(&client, &Invocation::default()).registry;

    // The daemon enumerates FIRST, so the listing it holds is already cached
    // when the vault changes. Without that the case is vacuous: a rebuild with
    // nothing cached fetches fresh whatever the rules are, and the defect this
    // is written against is a rebuild reading a listing older than the question
    // that queued it. At the crate's default TTL that is a full minute of a
    // daemon unable to learn what it was started to learn.
    wait_until_served(running.socket(), "DECOY");
    // And then until nothing is still enumerating. Rewriting the fixture under
    // a rebuild that is already running lets it read the new listing, and the
    // first resolve below then HITS — the assertion would fail, correctly,
    // having proved nothing.
    settle(&dir);
    // One enumeration, not one per poll. `Op::Names` asks for a rebuild
    // whenever it finds no index, and the worker clears the request when it
    // TAKES it — so without the in-flight guard every poll of the wait above
    // bought another whole vault walk, and each of those is a permanent
    // off-machine audit entry. It is also what made this case racy: a second
    // rebuild still running when the fixture changed read the new listing.
    assert_eq!(
        support::proton::vault_list_count(&dir),
        1,
        "priming the index cost more than one enumeration"
    );

    // Somebody adds an item to the vault. Nothing else happens: the daemon is
    // not signalled, not restarted, and its config is not touched.
    set_catalogue_listing(&dir, &listing_of(&["decoy", "decoy alpha"]));

    // The first ask misses — the index was built before the item existed.
    let first = registry.resolve("DECOY_ALPHA");
    assert!(
        !matches!(first, Resolution::Found { .. }),
        "the fixture must start from a genuine miss: {}",
        arm(&first)
    );

    // That miss is what queues the rebuild. Once it lands, the name is served.
    let served = wait_until_served(running.socket(), "DECOY_ALPHA");
    assert!(served.contains(&"DECOY".to_owned()), "{served:?}");

    match registry.resolve("DECOY_ALPHA") {
        Resolution::Found { secret, store } => {
            assert_eq!(secret.expose(), DECOY);
            assert_eq!(store, "daemon");
        }
        other => panic!("the retry after the rebuild must resolve: {}", arm(&other)),
    }
}

#[test]
fn two_items_minting_one_name_are_refused_without_asking_any_store() {
    // C4. The assertion that matters is the ABSENCE of a vendor `run`: a
    // first-wins ambiguity would hand back a real credential that is the wrong
    // credential, and nothing downstream could tell.
    let dir = scratch("catalogue-ambiguous");
    let vendor = stub_pass_cli_catalogue(
        &dir,
        &Backend::Injects(DECOY),
        ONE_VAULT,
        &listing_of(&["my-key", "My Key", "other-key"]),
        "{}",
    );
    let config = daemon_over(&dir, &vendor);
    let running = start_daemon(&config, policy_allowing_self());
    let client = client_config(running.socket(), 3_000);
    let registry = build(&client, &Invocation::default()).registry;

    // Enumerate first, so the miss below is a decision about a name the daemon
    // knows two items mint — not a name it has never heard of.
    let served = wait_until_served(running.socket(), "OTHER_KEY");
    assert!(
        !served.contains(&"MY_KEY".to_owned()),
        "a name the daemon refuses must not be listed: {served:?}"
    );

    let refused = registry.resolve("MY_KEY");
    assert!(
        !matches!(refused, Resolution::Found { .. }),
        "a colliding name must not resolve: {}",
        arm(&refused)
    );
    // No `run` was created. `pass-cli.argv` is written by the stub's run branch
    // and by nothing else, so its absence is the assertion — the same shape
    // `tests/daemon_proton.rs` argues for an undeclared name.
    // Nor is a title spelling that mints the colliding name: it is refused
    // under that name rather than guessed.
    let refused = registry.resolve("my-key");
    assert!(
        !matches!(refused, Resolution::Found { .. }),
        "a title spelling of a colliding name must not resolve: {}",
        arm(&refused)
    );
    assert!(
        !dir.join("pass-cli.argv").exists(),
        "a colliding name reached the vendor"
    );

    // The control: a non-colliding name from the same listing still resolves,
    // so the case above is about the collision and not about a broken fixture.
    match registry.resolve("OTHER_KEY") {
        Resolution::Found { secret, .. } => assert_eq!(secret.expose(), DECOY),
        other => panic!("the collision must not spread: {}", arm(&other)),
    }
    assert!(dir.join("pass-cli.argv").exists());
}
