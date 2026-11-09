# Issue tracker: GitHub

Issues and specs for this repo live as GitHub issues on `nbstr/keyless`.

## Conventions

- A ticket or comment carries no PII, secret, internal host or absolute path; a path in it is repo-relative.
- **Create an issue**: only one the person asked for; one the work turns up → propose it, and create nothing until they say yes.
  - Label `needs-triage`, plus its category: `bug`, `enhancement`, `documentation` or `question`.
  - Search first for an issue already covering it; one found → name it, and create nothing until the person answers.
  - Its description opens with a 2–4 line **In short.** block.
  - One issue is one piece of work: never split one by size; restate its criteria to fit.
- **Start work**: assign the issue to yourself first.
- **Read an issue**: by its number (`#123`), always with its comments (`gh issue view <n> --comments`), which often hold context the description lacks.
- **Close**: an issue is done when the pull request closing it merges; one not to be actioned is labelled `wontfix` and closed as not planned.

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external PRs as feature requests; `/triage` reads this flag.)_

## Wayfinding operations

Used by `/wayfinder`. The **map** is a single issue with **child** issues as tickets.

- **Map**: a single issue labelled `wayfinder:map`, holding the Notes / Decisions-so-far / Fog body.
- **Child ticket**: a sub-issue of the map, labelled `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`). Once claimed, the ticket is assigned to the driving dev.
- **Blocking**: GitHub's native blocked-by relation. A ticket is unblocked when every blocker is closed.
- **Frontier query**: the map's open children, dropping any with an open blocker or an assignee; first in the map's sub-issue order wins.
- **Claim**: assign the ticket to yourself, the session's first write.
- **Resolve**: comment the answer, close the ticket, then append a context pointer (gist + link) to the map's Decisions-so-far.
