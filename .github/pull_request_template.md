## What changes

<!-- One or two lines: what you added, removed or fixed, and why. -->

## Checks

- [ ] I have signed the [Contributor License Agreement](../CLA.md) (the bot asks on your first pull request)
- [ ] `make lint`, `make cover` and `make security` pass
- [ ] `make e2e AREA=...` passes for the areas the change touches (if it talks to a server or service)
- [ ] `README.md`, `docs/features/`, `internal/cli/guide.md` and the agent skill (`internal/cli/skill.md`, copied to `skills/komando/SKILL.md`) match the change; a new error code is in `docs/features/error-codes.md` (`KOMANDO_UPDATE_ERRCODES=1`)
- [ ] `CHANGELOG.md` has a line under `[Unreleased]` (if users will notice the change)
