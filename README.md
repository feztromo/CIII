# CIII (C3)

> If things don't work, think of trying to look inside a coconut without breaking it. That's what CoCoCode is. (Well, maybe not. Let's just call it C3)
---

> [!WARNING]
> This project is heavily vibe-coded, and the sailing hasn't exactly been smooth. Treat this tool like a nuke, or `git push --force`, if you prefer. C3 can modify your working tree, synchronize files from other participants, and publish changes to Git. If you manage to hack someone using C3, consider me impressed. But please also make a pull request. I have neither the time, money, nor skill to guarantee that this is safe. Back up your work, understand what you're running, and don't expose it to networks you don't trust. You have been warned... have fun :D   

CIII is a peer-to-peer tool for collaborative coding. It uses Yjs to synchronize files between teammates on Linux, as well on Windows and macOS.

There is no dedicated host! Peers connect directly, but one participant usually needs a reachable endpoint when connecting across different networks. An easy fix to this is to use something like Tailscale or ZeroTier.


## Quick Start

Requires **Node.js 22 or newer**.

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

**Keep the entire invite intact.** It contains the session key and the addresses required to connect. Anyone holding it can join the session, read its contents, and make changes.

Never post invites in public channels or share them with people you don't trust.

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
| `--lan-only` | Restrict networking to the local network |
| `--all-ifaces` | Include addresses from all network interfaces |
| `--name <name>` | Set the session name |
| `--invite <invite>` | Supply an invite |
| `--prune` | On resume, remove local files that are not present in the session |
| `--yes` | Skip confirmation prompts |
| `--force-push` | Allow a force push when enabled in configuration |

Joining a session always adopts its file state, regardless of `--prune`. The flag only affects resuming an existing session.

For IPv6 addresses, use square brackets when specifying an advertised endpoint:

```bash
node c3.js --advertise "[2001:db8::1]:8443"
```

### Environment

| Variable | Description |
|---|---|
| `C3_KEY` | Set the session key |
| `C3_DEBUG` | Enable debug output |

## Networking and Reachability

C3 uses direct peer-to-peer connections. There is no central relay server or dedicated infrastructure handling your project data.

This means connectivity depends on the network configuration of the participants.

### IPv6: The easiest way to connect across networks

C3 advertises global IPv6 addresses automatically.

If the hosting peer has a globally reachable IPv6 address, other peers can connect without port forwarding or a third-party service.

Check the invite command:

- `/ip6/...` indicates an IPv6 address.
- `/ip4/10...` indicates a private IPv4 address and is not reachable from the public internet.
- Other private or non-routable addresses are similarly unsuitable for cross-network hosting.

If your invite only contains private addresses, other networks will not be able to dial you directly.

### Hosting and joining are not symmetrical

A peer behind carrier-grade NAT (CGNAT), or one with only a private campus address, can still **join** a session hosted by someone with a reachable address.

However, that peer generally cannot host a cross-network session itself.

For cross-network sessions, start the session from a peer with a globally reachable address.

C3 warns at startup when its advertised addresses are not dialable.

### Other connectivity options

If global IPv6 isn't available, you may need:

- **IPv4 port forwarding:** Forward the configured TCP port through your router.
- **An existing reachable peer:** Peers connected to the same reachable hub can exchange updates indirectly.

Indirect synchronization is not connection forwarding or a relay service. Each peer maintains its own connections, and the hub periodically distributes state vectors. Updates can therefore take approximately 8 seconds per hop to propagate through an indirect connection.

### UDP

UDP is a latency optimization on top of an established TCP session.

C3 does not use UDP hole punching to establish connections. It has no STUN-based discovery of public reflexive addresses.

In other words, UDP cannot rescue a TCP connection that cannot be established in the first place.

### Network changes

If your network changes or your temporary IPv6 address rotates, previously generated invites may become stale.

If C3 reports:

```text
network address changed -- any invite already printed is stale
```

Run:

```bash
node c3.js share
```

Then distribute the new invite.

## Security Considerations

C3 is experimental software. Do not assume that encryption makes it safe to expose.

### Network exposure

The listener binds to all interfaces by default.

If your machine has a globally reachable IPv6 address, the listening port may be reachable from the public internet.

Consider the following precautions:

- Use `--lan-only` when you only need local network collaboration.
- Configure your firewall to restrict incoming connections.
- Avoid exposing C3 on untrusted networks.
- Only share invites with trusted participants.

### Session keys

The invite contains the session key.

Anyone holding the invite can join the session, read shared files, and write changes.

Treat invites as credentials, not ordinary connection URLs.

To rotate access, create a new session with a different `--name`, or remove the local session state and establish a new session with a fresh key.

### Direct connections and IP addresses

Direct peer-to-peer connections can expose participants' IP addresses to other participants.

Keep this in mind when collaborating with people you don't personally know.

### Encryption

C3 uses:

- ECDH to establish shared secrets.
- HMAC to authenticate the handshake.
- HKDF to derive per-direction encryption keys.
- AES-256-GCM to encrypt payloads.

Encryption protects communication, but it does not make an untrusted participant safe. Anyone with a valid invite is authorized to participate in the shared session.

## Saving Work

C3 can use Git to publish completed sessions.

When the last peer leaves, C3 asks whether to publish the session. With the Git backend enabled, it commits and pushes the changes.

You can use `--yes` to skip the confirmation prompt.

There are three relevant outcomes:

- **Saved:** Changes are committed and pushed.
- **Nothing changed:** C3 prints `nothing changed (already committed)` when there are no changes to publish.
- **No Git repository:** C3 prints `nothing to publish: no git repo in <path>` when the Git backend cannot find a repository at the project root.

The session status line shows the active backend as `-- git` or `-- none`. Check this when starting a session to make sure the expected backend is active.

If other peers are still connected when you leave, C3 keeps the local state and does not publish yet.

> [!CAUTION]
> Starting a new Git-backed session resets the project working tree to `HEAD` and runs `git clean -fd`.
>
> Untracked, non-ignored files may be removed. Ignored paths such as `c3/` are left alone.
>
> Make sure any local work you want to keep is committed before starting a fresh session.

## Session Recovery

Running `node c3.js` with no command resumes the local session from `c3/.c3/`.

It does **not** re-join an existing session.

If the repository has changed underneath a saved session, for example through `git pull`, `git reset`, or `git checkout`, the saved state may be older than `HEAD`.

If C3 detects a generation mismatch before loading the state, it discards the stale state automatically. If the mismatch is detected after loading, it warns about it.

### Re-joining a session

To discard the local session and re-join:

Linux / macOS, from the `c3/` directory:

```bash
rm -rf .c3
```

Windows CMD, from the `c3\` directory:

```cmd
rmdir /s /q .c3
```

Then run:

```bash
node c3.js join "c3://..."
```

This deletes the peer identity, session key, cached peers, configuration, and local session state.

You will need the original invite again, or a fresh invite from a peer that is still connected.

The session key is stored in `.c3/s/<name>/key` and in the invite.

## How It Works

- **Synchronization:** Yjs handles collaborative document state and synchronization.
- **Connections:** Peers establish direct TCP connections and exchange advertised network addresses over authenticated connections.
- **NAT traversal:** C3 does not implement STUN-based public address discovery or UDP hole punching for connection establishment.
- **Encryption:** ECDH establishes shared secrets, HMAC authenticates the handshake, and HKDF derives per-direction keys. Payloads are encrypted with AES-256-GCM.
- **Persistence:** Local snapshots and an operation log allow sessions to resume from `c3/.c3/`.
- **File safety:** C3 filters internal and ignored files, rejects unsafe paths, and silently ignores files larger than 16 MiB.
- **Indirect synchronization:** Peers periodically exchange state vectors, allowing updates to propagate through a mutually connected peer without forwarding connections.

## Limitations

C3 is designed for collaborative coding, not as a general-purpose file synchronization system.

Be aware of the following limitations:

| Limitation | Behavior |
|---|---|
| Maximum file size | Files larger than 16 MiB are ignored |
| Initial seeding | Limited to 10,000 files and 200 MB |
| Symbolic links | Never followed |
| Binary detection | Files containing a NUL byte are treated as binary |
| UTF-16 files | May be classified as binary because they contain NUL bytes |
| Network reachability | Requires at least one dialable peer for cross-network hosting |
| Invite length | Invites can be long because they contain every advertised address |
| Indirect synchronization | Updates can take approximately 8 seconds per hop |

**Copy invites completely.** Since an invite carries every advertised address, truncating it can prevent peers from connecting.

## Troubleshooting

| Symptom | Possible cause / solution |
|---|---|
| No invite command | Configure a reachable address using `--advertise <host:port>` |
| Cannot connect | Check the advertised address, firewall rules, and port forwarding |
| Works on the same network but hangs across networks | The host probably has no dialable address. Check for `/ip6/` in the invite |
| Invite suddenly stops working | The network address may have changed. Run `share` again |
| Joined but received no state | The host must stay running until the joiner's file count matches. If the host exits too early, the joiner waits up to 45 seconds before exiting without modifying local files. Re-join using a fresh invite |
| Edits take approximately 1 second to appear | This may be editor autosave behavior (`files.autoSaveDelay`), rather than C3 synchronization latency |
| `instant watching unavailable -- polling only` | Recursive `fs.watch` is unavailable on that platform. C3 falls back to 8-second polling |
| Unexpected old files | Check whether C3 resumed an existing local session. Use the session recovery steps if the repository changed underneath it |
| Nothing to publish | Check the active backend in the status line and confirm that the project root contains a Git repository |
| Host publishes nothing on first exit | A freshly seeded session has no edits. The publish prompt may report `0 changed path(s)` followed by `nothing changed (already committed)`. This is expected |
| Files missing from sync | Check ignore rules, file-size limits, and initial seeding limits |

## Contributing

Found a bug? Have an idea? Managed to break something in a particularly impressive way?

Pull requests are welcome!

Just remember that C3 is experimental software. Test your changes carefully, and please don't make it even more dangerous than it already is.

Happy collaborating! :D
