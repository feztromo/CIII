# CIII (C3)

> If things don't work, think of trying to look inside a coconut without breaking it. That's what CoCoCode is.
---

> [!WARNING]
> This project is heavily vibe-coded, albeit not very smooth sailing vibes. Treat this tool as you would with a nuke, or git push --force in other words. If you manage to hack someone using C3, consider me impressed, but please also make a pull request. I've neither the time, money or skill to make this safe. You have been warned... have fun :D   

CIII is a peer-to-peer tool for collaborative coding. It uses Yjs to synchronize files between teammates on Linux, as well on Windows and macOS.

There is no dedicated host! Peers connect directly, but one participant usually needs a reachable endpoint when connecting across different networks.

## Quick Start

Requires Node.js 22 or newer.

Clone C3 **inside your project directory**, as a `c3/` subfolder. C3 always treats the parent of its own directory as the project root.

```bash
# From your project directory
git clone https://github.com/feztromo/CIII.git c3
echo c3/ >> .gitignore

cd c3
npm install
node c3.js config
node c3.js
```

Keep `c3/` in your project's `.gitignore`. It contains C3 itself, its dependencies, configuration, and local session state. It is not part of the shared project files.

The `config` command is optional. C3 works without it. If you run it before your project has a `.git` directory, the backend is set to `none`.

## Invite Others

Once your session is running, C3 prints a join command when it has a reachable address to share.

Send that command to your teammates. They can join with:

```bash
node c3.js join "c3://..."
```

You can print the invite command again at any time:

```bash
node c3.js share
```

## Commands

| Command | Description |
|---|---|
| `node c3.js` | Start or resume the local session |
| `node c3.js connect` | Alias of running with no command |
| `node c3.js join <invite>` | Join an existing session |
| `node c3.js share` | Print the session invite command |
| `node c3.js config` | Configure C3 |
| `node c3.js peer <multiaddr>` | Manually add a peer address |

## Configuration

Run `node c3.js config` to configure:

- **Backend:** `git` or `none`. Git is selected by default when the project root contains a Git repository.
- **Port:** TCP and UDP listening port. Defaults to `8443`.
- **Advertise endpoint:** An optional reachable address and port for other peers to connect to.

### Flags

| Flag | Description |
|---|---|
| `--dir <path>` | Set the project root |
| `--port <number>` | Override the listening port |
| `--advertise <host:port>` | Set the address advertised to peers |
| `--prune` | On resume, remove local files that are not present in the session |
| `--yes` | Skip confirmation prompts |
| `--force-push` | Allow a force push when enabled in configuration |

Joining a session always adopts its file state, regardless of `--prune`. The flag only affects resuming an existing session.

### Environment

| Variable | Description |
|---|---|
| `C3_KEY` | Set the session key |

## Saving Work

C3 can use Git to publish completed sessions.

When the last peer leaves, C3 asks whether to publish the session. With the Git backend enabled, it commits and pushes the changes. You can use `--yes` to skip the confirmation prompt.

There are three relevant outcomes:

- **Saved:** Changes are committed and pushed.
- **Nothing changed:** C3 prints `nothing changed (already committed)` when there are no changes to publish.
- **No Git repository:** C3 prints `nothing to publish: no git repo in <path>` when the Git backend cannot find a repository at the project root.

The session status line shows the active backend as `-- git` or `-- none`. Check this when starting a session to make sure the expected backend is active.

If other peers are still connected when you leave, C3 keeps the local state and does not publish yet.

Starting a new Git-backed session resets the project working tree to `HEAD` and runs `git clean -fd`. Untracked, non-ignored files may be removed. Ignored paths such as `c3/` are left alone. Make sure any local work you want to keep is committed before starting a fresh session.

## Session Recovery

Running `node c3.js` with no command resumes the local session from `c3/.c3/`. It does **not** re-join an existing session.

If the repository has changed underneath a saved session, for example through `git pull`, `git reset`, or `git checkout`, the saved state may be older than `HEAD`. If C3 detects a generation mismatch before loading the state, it discards the stale state automatically. If the mismatch is detected after loading, C3 warns about it.

To discard the local session and re-join:

```bash
# Linux / macOS, from the c3/ directory
rm -rf .c3
```

```cmd
:: Windows CMD, from the c3\ directory
rmdir /s /q .c3
```

Then run:

```bash
node c3.js join "c3://..."
```

This deletes the peer identity, session key, cached peers, configuration, and local session state. You will need the original invite again, or a fresh invite from a peer that is still connected. The session key is stored in `.c3/s/<name>/key` and in the invite.

## How It Works

- **Synchronization:** Yjs handles collaborative document state and synchronization.
- **Connections:** Peers establish direct TCP connections and exchange advertised network addresses over authenticated connections.
- **NAT traversal:** UDP hole punching can help establish direct connections between peers behind NAT.
- **Encryption:** ECDH establishes shared secrets, HMAC authenticates the handshake, and HKDF derives per-direction keys. Payloads are encrypted with AES-256-GCM.
- **Persistence:** Local snapshots and an operation log allow sessions to resume from `c3/.c3/`.
- **File safety:** C3 filters internal and ignored files, rejects unsafe paths, and silently ignores files larger than 16 MiB.

## Reachability

C3 attempts to establish direct peer-to-peer connections. Successful connections depend on network reachability.

For peers on different networks, at least one reachable advertised endpoint is usually needed. Possible options include:

- IPv6 connectivity.
- Port forwarding for IPv4.
- Connecting through a peer that is already reachable.

UDP is a latency optimisation on top of an established TCP session, not a way to establish one.

Direct peer-to-peer connections may expose IP addresses to other participants.

## Troubleshooting

- **No invite command:** Configure a reachable address using `--advertise <host:port>`.
- **Cannot connect:** Check the advertised address, firewall rules, and port forwarding.
- **Joined but received no state:** The host must stay running until the joiner's file count matches. If the host exits too early, the joiner waits up to 45 seconds before exiting without modifying local files. Re-join using a fresh invite.
- **Host publishes nothing on first exit:** A freshly seeded session has no edits. The publish prompt may report `0 changed path(s)` followed by `nothing changed (already committed)`. This is expected because the session content already matches `HEAD`.
- **Unexpected old files:** Check whether C3 resumed an existing local session. Use the session recovery steps if the repository changed underneath it.
- **Nothing to publish:** Check the active backend in the status line and confirm that the project root contains a Git repository.
- **Files missing from sync:** Check the ignore rules and the 16 MiB file-size limit.
