# Install, update, remove

komando is one program file. This page shows how to install it on macOS,
Linux and Windows, keep it up to date, turn on tab completion, and remove
it again.

## Install on macOS or Linux

Open a terminal (on macOS the **Terminal** app) and paste:

```bash
curl -fsSL https://raw.githubusercontent.com/sgnd/komando/main/install.sh | sh
```

Then check that it works:

```bash
komando version
```

It says `command not found`? The installer put komando in a folder your
terminal does not look in yet. Run the `export PATH=...` line it printed,
and add that line to `~/.zshrc` (macOS) or `~/.bashrc` (Linux) so it stays.

Want to read the script first? Download it, read it, then run it:

```bash
curl -fsSLO https://raw.githubusercontent.com/sgnd/komando/main/install.sh
sh install.sh
```

`KOMANDO_INSTALL_DIR=DIR` picks the folder, and `KOMANDO_VERSION=v0.14.0`
picks one version (`KOMANDO_VERSION=v0.14.0 sh install.sh`).

## Install on Windows

1. Download `komando_windows_amd64.zip` (or `komando_windows_arm64.zip` on
   an ARM computer) from [Releases](https://github.com/sgnd/komando/releases).
2. Unpack `komando.exe` into a folder on your `PATH`.
3. Open PowerShell and run `komando version`.

What is different on Windows:

- komando keeps its data in `%USERPROFILE%\.komando`. It gives that folder
  an access list of its own: only your user and the system can open it.
  `komando doctor` warns when a file inside lets anyone else in.
- The vault key goes into Windows Credential Manager (see
  [Where komando keeps its data](settings.md#where-komando-keeps-its-data)).
- Paths use Windows form, for example a SQLite file
  `sqlite://C:\data\app.db`.
- Browser sign-ins (VPN and cloud logins) open your default browser, as on
  macOS and Linux.

You can also run the Linux version inside
[WSL](https://learn.microsoft.com/windows/wsl/install), with the macOS and
Linux steps above.

## Other ways to install

- With Go installed: `go install github.com/sgnd/komando/cmd/komando@latest`.
- Check that a downloaded archive was built by komando's release workflow:

  ```bash
  gh attestation verify komando_linux_amd64.tar.gz --repo sgnd/komando
  ```

## Update

```bash
komando update --dry-run   # is there a newer version? (changes nothing)
komando update             # install the newest release
```

`update` checks that the release is signed by the komando project,
downloads the release for this computer, checks it against the release's
signed checksums, runs the new program once to make sure it works here,
and only then puts it in place. If anything fails, the old komando stays.
Your servers, secrets and history in `~/.komando` stay as they are.

After an update, run `komando guide install` again (without `sudo`), so
your AI agents get the skill of the new version. Until then
`komando doctor` says the skill is from another version.

- komando is in a folder only root may change, such as `/usr/local/bin`?
  Run `sudo komando update`. As root it writes nothing in `~/.komando`.
- On Windows the running `komando.exe` is renamed aside (Windows does not
  let a running program be replaced) and the new one takes its name.
- `komando update v0.11.0` installs that version. Going back to an older
  version asks you first, because an older komando may lack safety checks
  the newer one has. An AI agent needs `--yes` and your "Allow once".
- `update` takes only a komando version. `komando update web1` is an
  error that points at `komando pkg upgrade web1`, which updates the
  packages on that server.
- Without a version, `update` never goes back, even when the newest
  release is older than the komando you run.
- A komando you built yourself from a commit between releases is not
  replaced (`SOURCE_BUILD`): build it again instead. One built at a release
  tag (`go install ...@v0.14.0`) counts as that release.
- Run as you, the update is written to the audit log like any other change.
- `update` installs only a release signed with the komando project's key,
  which is built into komando. The release workflow signs `checksums.txt`
  (as `checksums.txt.sig`), so someone who replaced a release's files
  cannot make `update` install them. An unsigned release stops with
  `RELEASE_SIGNATURE_NOT_FOUND`, a wrong signature with
  `RELEASE_SIGNATURE_INVALID`; nothing is changed. Do not work around either for a new release: report it
  ([SECURITY.md](../../SECURITY.md)). Releases up to 0.13.0 have no
  signature, so `komando update v0.13.0` stops too; to go back to one of
  them, use the install line with `KOMANDO_VERSION=v0.13.0`.
- To check the signed build provenance of a download as well, use
  `gh attestation verify` (see
  [Other ways to install](#other-ways-to-install)).
- It uses `HTTPS_PROXY`. `sudo` drops that variable; keep it with
  `sudo --preserve-env=HTTPS_PROXY komando update`.
- `--timeout` (default 10 minutes) limits the whole update. When GitHub
  answers with an error, it tries twice more.

Installed with `sudo` and the install line? Update the same way:
`curl -fsSL https://raw.githubusercontent.com/sgnd/komando/main/install.sh | sudo sh`.
Without `sudo` the installer cannot write there, puts the new version in
`~/.local/bin`, and your terminal may keep running the old one.
`komando version` shows which one runs.

## Tab completion

Press Tab to complete commands, flags and the names of your servers,
conns, groups and tags. Turn it on once, then open a new terminal:

```bash
echo 'source <(komando completion zsh)' >> ~/.zshrc          # zsh (macOS)
echo 'eval "$(komando completion bash)"' >> ~/.bashrc        # bash (Linux)
echo 'eval "$(komando completion bash)"' >> ~/.bash_profile  # bash on macOS
```

For fish and PowerShell, see `komando completion --help`.

## Remove komando

1. Stop what komando still runs. `komando status` lists it;
   `komando vpn down --all` and `komando tunnel stop --all` stop it.
2. Take the skill and the guard out of your AI agents:
   `komando guide uninstall` (add `--project` in a folder where you ran
   `guide install --project`).
3. Keep a copy of `~/.komando` if you may need your servers or secrets
   again (see [Move to another computer](import.md#move-to-another-computer)),
   then delete the folder. Is the vault key in the system keychain? If you
   keep the copy, first run `komando secret keychain --off`, or the copy
   cannot be opened later. Otherwise remove the keychain item named
   `komando vault ...` (macOS: the Keychain Access app; Windows:
   Credential Manager).
4. Delete the program: `rm "$(command -v komando)"` (with `sudo` when it is
   in `/usr/local/bin`; on Windows delete `komando.exe`), and the
   `export PATH=...` line you added, if any.

## Troubleshooting

| Error | What it means | What to do |
|-------|---------------|------------|
| `NOT_WRITABLE` (exit 8) | komando's folder belongs to root | run the `sudo` command the hint gives |
| `VERSION_NOT_FOUND` (exit 3) | no such release, or none for this computer | see the [list of releases](https://github.com/sgnd/komando/releases) |
| `RELEASES_UNREACHABLE` (exit 4) | GitHub cannot be reached | check the internet connection and `HTTPS_PROXY` |
| `TIMEOUT` (exit 7) | the download took longer than `--timeout`; nothing changed | `komando update --timeout 30m` |
| `CHECKSUM_MISMATCH`, `BAD_RELEASE` (exit 1) | the download is damaged or does not run here; nothing changed | try again; report it if it happens again |
| `SOURCE_BUILD` | this komando was built from source between releases | build it again from source |
