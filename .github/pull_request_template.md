## What changes

<!-- One or two lines: what you added, removed or fixed, and why. -->

## Checks

<!-- To sign the Contributor License Agreement (CLA.md), type its sentence on a
line of its own in this description. Every other commit author writes the
sentence in a comment on this pull request. The sentence is in CLA.md under
"How to sign". -->

- [ ] I typed the CLA sentence in this description
- [ ] `make lint`, `make cover` and `make security` pass
- [ ] `make e2e AREA=...` passes for the areas the change touches (if it talks to a server or service)
- [ ] `README.md`, `docs/features/`, `internal/cli/guide.md` and the agent skill (`internal/cli/skill.md`, copied to `skills/komando/SKILL.md`) match the change; a new error code is in `docs/features/error-codes.md` (`KOMANDO_UPDATE_ERRCODES=1`)
- [ ] `CHANGELOG.md` has a line under `[Unreleased]` (if users will notice the change)
