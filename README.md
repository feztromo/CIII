# CIII *(c3)*

> If things don't work, think of trying to look inside a coconut without breaking it. That's what CoCoCode is.

This project is a peer-to-peer tool for live collaborative coding. It synchronizes project files between cross-platform teammates over encrypted connections, without a central server.

Requires **Node.js 22 or newer**

## Quick Start

Clone c3 into your project and install dependencies:

```bash
git clone https://github.com/feztromo/c3.git c3
echo c3/ >> .gitignore
cd c3 && npm install
node c3.js config
```

Start or join a session:

```bash
node c3.js connect
```

## Invite Others

Start a session, then generate a single-use invite:

```bash
node c3.js invite
```

Share the printed `c3://join/...` link with your teammate. They can join using:

```bash
node c3.js join "c3://join/..."
```

After the first successful connection, peers cache each other's addresses. Future sessions can usually reconnect without an invite.

## Commands

| Command | Description |
|---|---|
| `node c3.js config` | Configure the session and archive backend |
| `node c3.js connect` | Start or join a session |
| `node c3.js invite` | Generate a single-use invite |
| `node c3.js join <url>` | Join using an invite link |
| `node c3.js export <dir>` | Export shared files |
| `node c3.js doctor` | Check configuration and connectivity |

## Configuration

Configure the session name, key, port, and optional reachable endpoint.

| Option | Description |
|---|---|
| `C3_KEY` | Set the session key via environment variable |
| `--name <name>` | Set the session name |
| `--key <key>` | Set the session key |
| `--port <n>` | Set the listening TCP port (default: `8443`) |
| `--advertise <host:port>` | Specify the reachable endpoint |
| `--peer <multiaddr>` | Add a peer address |
| `--seed` | Publish this directory into an empty session |
| `--ttl <hours>` | Set invite lifetime (default: `24`) |
| `--uses <n>` | Set invite use count (default: `1`) |
| `--yes` | Confirm publishing without prompting |
| `--archive <type>` | Select `git`, `folder:<path>`, or `none` |

Advanced options can be configured in `c3/.c3/config.json`.

## Saving Work

Choose an archive backend during configuration:

- **`git`** Commit changes and push to `origin`.
- **`folder`** Save timestamped snapshots to a directory.
- **`none`** Disable automatic archiving; use `export` to save a copy.

Unsaved state can be restored when reconnecting. Keep `c3/` in your project's `.gitignore` to avoid committing C3's configuration and session state.

## How It Works

- **Discovery:** Invites and cached peer addresses, shared over authenticated connections.
- **Sync:** Yjs synchronizes file changes between connected peers.
- **Networking:** TCP connections using libp2p; reachable peers accept connections and help outbound-only peers join.
- **Encryption:** Noise secures transport; AES-256-GCM encrypts session payloads.
- **File safety:** Rejects unsafe paths, symlink escapes, and files larger than 16 MiB.

## Reachability

At least one participant must have an inbound-reachable endpoint, such as:

- A public IPv6 address with the c3 port allowed through the firewall.
- An IPv4 port forward with a stable hostname.
- Another reachable participant already in the session.

Outbound-only peers can connect through a reachable participant. If every peer is behind inbound-blocking NAT, cross-network connections cannot be established until a reachable peer returns.

Direct peer-to-peer connections may reveal IP addresses to connected peers. Use a participant-owned relay or VPN if IP privacy is important.

## Troubleshooting

- **Check setup:** Run `node c3.js doctor`.
- **Session mismatch:** Ensure all peers use the same session name and key.
- **Installation:** Verify `npm install` completed and Node.js 22 or newer is installed.
- **Invite issues:** Start `node c3.js connect` on a reachable peer before running `node c3.js invite`.
- **Port conflicts:** Specify another port with `--port`.
- **Connection issues:** Check the advertised endpoint, firewall rules, and ensure at least one peer has a reachable address.
