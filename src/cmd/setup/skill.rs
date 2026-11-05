//! The agent instructions `keyless setup` installs, and the step that puts
//! them in place without overwriting a copy somebody edited.

use std::io::{self, Write};
use std::path::PathBuf;

use crate::cmd::receipt::{FileRecord, Receipt, digest_of};
use crate::paths::SetupPaths;

use super::super::status::{Mark, heading, row};
use super::{SUBJECT, SetupRequest};

/// Where the agent instructions live.
pub(super) fn skill_file(setup: &SetupPaths) -> PathBuf {
    setup
        .claude_dir
        .join("skills")
        .join(crate::NAME)
        .join("SKILL.md")
}

/// The agent instructions, and why there are so few of them.
///
/// Every line here had to survive one question: **could this have been designed
/// away instead?** Most could, and were:
///
/// - "there is no verb that prints a value" teaches itself — `keyless get`
///   answers with the reason rather than an unknown-subcommand error.
/// - "do not `cat` a `.env`" teaches itself — the guard refuses the read and
///   names the working command in the same breath.
/// - "quote the body and keep it inside `sh -c`" is now half a runtime warning:
///   an unexpanded `$NAME` handed to a program that is not a shell is reported
///   by `run` itself, at the moment it happens, naming the corrected line.
///
/// What is left is the half no design can remove: a `run` whose credential did
/// not resolve is INDISTINGUISHABLE from a successful one by exit code, because
/// the exit code belongs to the child and this tool refuses to invent one.
/// There is no mechanism that can teach that at the moment it matters, because
/// at that moment nothing has gone wrong yet.
pub(super) const SKILL: &str = concat!(
    "---\n",
    "name: keyless\n",
    "description: >-\n",
    "  Use a credential without ever reading one. Load when a command needs an API key,\n",
    "  a token, a database URL or any other secret; when a `.env` or credential file read\n",
    "  is refused; or when a command fails to authenticate and the value came from a\n",
    "  secret store.\n",
    "---\n",
    "\n",
    "# keyless\n",
    "\n",
    "A named credential reaches one child process's environment and nothing else.\n",
    "You never receive the value, and this transcript never contains it.\n",
    "\n",
    "```\n",
    "keyless run -s DATABASE_URL -- psql\n",
    "keyless run -s GITHUB_TOKEN -- gh pr list\n",
    "keyless ls                                 the names you can use\n",
    "```\n",
    "\n",
    "## The one thing no error will tell you\n",
    "\n",
    "**`keyless run` never refuses to run your command.** A name that does not\n",
    "resolve is a warning on stderr, and the child runs with an untouched\n",
    "environment — so a missing credential arrives as your program's own 401, at\n",
    "your program's own exit code.\n",
    "\n",
    "**So the exit code cannot tell you the credential arrived. Read stderr for\n",
    "`DEGRADED`.** Exit 0 with a `DEGRADED` banner means the command ran without\n",
    "the secret.\n",
    "\n",
    "## Quoting\n",
    "\n",
    "The variable is set in the CHILD, so only the child's own shell can expand it:\n",
    "\n",
    "```\n",
    "keyless run -s TOKEN -- sh -c 'curl -H \"Authorization: Bearer $TOKEN\" $URL'\n",
    "```\n",
    "\n",
    "Single-quote the body. Double quotes let YOUR shell expand `$TOKEN` first,\n",
    "where it is unset, and an empty credential is sent instead of a missing one.\n",
    "\n",
    "## There is no way to see the value\n",
    "\n",
    "No verb prints one, no flag prints one, and none is coming. If a command\n",
    "needs the credential, run that command under `keyless run`.\n",
    "\n",
    "*Installed by `keyless setup`. `keyless uninstall` removes it.*\n"
);

/// Write the agent instructions, or leave a file somebody else has taken over.
pub(super) fn step_skill(
    request: &SetupRequest<'_>,
    out: &mut dyn Write,
    receipt: &mut Receipt,
) -> io::Result<u32> {
    let style = request.style;
    heading(out, style, "AGENT INSTRUCTIONS")?;
    let path = skill_file(request.setup);

    if !request.setup.claude_dir.is_dir() {
        row(
            out,
            style,
            Mark::Off,
            "skill",
            SUBJECT,
            "off",
            "no agent harness here, so there is nothing that would load them.",
        )?;
        return Ok(0);
    }

    let wanted = digest_of(SKILL.as_bytes());
    if path.exists() {
        let current = std::fs::read(&path).map(|bytes| digest_of(&bytes)).ok();
        if current.as_deref() == Some(wanted.as_str()) {
            row(
                out,
                style,
                Mark::Proven,
                "skill",
                SUBJECT,
                "proven",
                &format!("{} is already what this version installs", path.display()),
            )?;
            return Ok(0);
        }
        let ours = receipt
            .file(&path)
            .is_some_and(|record| current.as_deref() == Some(record.sha256.as_str()));
        if !ours {
            // Somebody edited it, or wrote their own. Either way it is theirs
            // now, and replacing it would delete work with no way back.
            row(
                out,
                style,
                Mark::Off,
                "skill",
                SUBJECT,
                "off",
                &format!(
                    "{} exists and is not what setup wrote. It is left exactly as \
                     it is; nothing here overwrites a file somebody edited.",
                    path.display()
                ),
            )?;
            return Ok(0);
        }
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let created = !path.exists();
    std::fs::write(&path, SKILL)?;
    receipt.record_file(FileRecord {
        path: path.clone(),
        created,
        sha256: wanted,
        remove_on_uninstall: true,
    });
    row(
        out,
        style,
        Mark::Proven,
        "skill",
        SUBJECT,
        "proven",
        &path.display().to_string(),
    )?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::SKILL;

    #[test]
    fn the_skill_declares_the_two_fields_a_harness_needs() {
        assert!(SKILL.starts_with("---\nname: keyless\n"), "{SKILL}");
        assert!(SKILL.contains("\ndescription:"), "{SKILL}");
        assert!(SKILL.matches("---\n").count() >= 2, "{SKILL}");
    }

    #[test]
    fn the_agent_instructions_carry_no_value_and_no_off_switch() {
        // Two properties at once. The guards' off switch must not appear in
        // text an AGENT loads, because an agent that is being blocked will
        // reach for it — and neither may the words somebody would try in order
        // to print a value, because naming them is teaching them.
        for forbidden in ["disable", "--reveal", "KEYLESS_HOOKS_DISABLE"] {
            assert!(
                !SKILL.contains(forbidden),
                "the skill hands an agent `{forbidden}`"
            );
        }
    }
}
