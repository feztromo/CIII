# CIII (C3)

> If things don't work, think of trying to look inside a coconut without breaking it. That's what CoCoCode is. (Well, maybe not. Let's just call it C3)
---
> [!WARNING]
> This project is heavily vibe-coded, and the sailing hasn't exactly been smooth. Treat this tool like a nuke, or `git push --force`, if you prefer. C3 can modify your working tree, synchronize files from other participants, and publish changes to Git. If you manage to hack someone using C3, consider me impressed. But please also make a pull request. I have neither the time, money, nor skill to guarantee that this is safe. Back up your work, understand what you're running, and don't expose it to networks you don't trust. You have been warned... have fun :D

CIII is a peer-to-peer tool for collaborative coding. It uses Yjs to synchronize files between teammates on Linux, as well as Windows and macOS.

There is no dedicated host! Peers connect directly, but one participant usually needs a reachable endpoint when connecting across different networks. In those cases you can use a Cloudflare tunnel (`--tunnel cloudflare` or `--tunnel named`), a mesh VPN such as Tailscale or ZeroTier, a public IPv6 address, or port forwarding.

## Requirements

- **Node.js 22 or newer**
- **cloudflared** (optional, only for `--tunnel`)

## Install Node

**Linux**
```bash
# Arch
sudo pacman -S nodejs npm
# Ubuntu/Debian
sudo apt install -y nodejs npm
```

**Windows**
```powershell
winget install OpenJS.NodeJS.LTS
```

**macOS**
```bash
brew install node@22
```
Or download from <https://nodejs.org>, also remember to update to Node.js 22 or newer if it isn't already.


## Install cloudflared (optional)

**Linux**
```bash
# Arch
sudo pacman -S cloudflared
# Ubuntu/Debian
sudo apt install cloudflared
```

**Windows**
```powershell
winget install --id Cloudflare.cloudflared
```

**macOS**
```bash
brew install cloudflared
```

## Quick start

Clone CIII into your project:

```bash
git clone https://github.com/feztromo/CIII.git c3
cd c3
npm install
```

Keep `c3/` out of Git if you use it:

```bash
echo c3/ >> .gitignore
```

Run inside `c3/`:

```bash
node c3.js
```

A typical project tree looks like this:

```
my-project/
├── .git/
├── .gitignore
├── src/
│   └── main.js
├── package.json
└── c3/                 <-- CIII lives here
    ├── c3.js
    ├── package.json
    └── .c3/            <-- Created automatically after starting a session
        ├── config.json
        ├── identity.json
        └── s/
```

C3 uses the parent of `c3/` as the project root. Use `--dir` for another root:

```bash
node c3.js --dir ../my-project
```

## Join, share, resume

The host prints an invite. Share the whole line.

```bash
# Join a session
node c3.js join "c3://..."

# Print the invite again
node c3.js share

# Resume the local session (same name/key)
node c3.js
```

Peers on the same LAN discover each other automatically over UDP `8444` (IPv4 and IPv6, even when C3 ports differ). Cross-network recovery needs at least one reachable peer (global IPv6, public address, or tunnel) and a fresh invite.

## Tunnels

**Quick tunnel** (no account):

```bash
node c3.js --tunnel cloudflare
```

**Named tunnel** (stable hostname):

1. Create a named tunnel in Cloudflare Zero Trust.
2. Point its public hostname at `http://localhost:8443` (or your `--port`).
3. Run:

```powershell
$env:C3_TUNNEL_TOKEN = "<token>"   # or set tunnelToken in config
node c3.js --tunnel named --tunnel-host c3.example.com
```

Only the peer running the tunnel needs `cloudflared`.

**Mesh VPN** (Tailscale, ZeroTier)

Install the VPN on every peer, then advertise the VPN address:

```bash
node c3.js --advertise 100.x.y.z:8443
```

C3 may warn that the VPN address looks private or carrier-grade NAT, but that is expected and it still works inside the VPN.

## Commands

| Command | Description |
|---|---|
| `node c3.js` | Start or resume a session |
| `node c3.js join <invite>` | Join a session |
| `node c3.js share` | Print the invite |
| `node c3.js config` | Configure backend / port / tunnel |
| `node c3.js peer <ma>` | Add a peer address manually |
| `node c3.js --help` | Show usage |

## Flags

`--dir <path>`, `--port <n>`, `--advertise <host:port>`, `--tunnel cloudflare|named`, `--tunnel-host <host>`, `--lan-only`, `--all-ifaces`, `--prune`, `--yes`, `--force-push`, `--autosave <seconds>`, `--help`

Flags may come before the command.

## Environment

- `C3_KEY` — session key (prefer the invite)
- `C3_TUNNEL_TOKEN` — named tunnel token
- `C3_DISC_PORT` — LAN discovery port (default `8444`)
- `C3_DEBUG` — debug output
- `NO_COLOR` — disable colors

## Config

`node c3.js config` sets the backend (`git` or `none`), port (default `8443`), optional advertise address, and tunnel mode (none / quick / named).

Extra ignore patterns go in `c3/.c3/ignore`, one per line. `*` and `?` wildcards are supported.

## Autosave

Synced changes are written to disk immediately (typically within 40 ms). A background autosave also retries any files that are still dirty every second, so a temporarily locked file is saved as soon as it becomes writable. Every document update is appended to the local session log immediately, and a full state snapshot is written once changes have been idle for the autosave interval.

Change the interval with `--autosave <seconds>` (for example `--autosave 0.5`); `--autosave 0` disables the periodic retry/snapshot timer (immediate writes still happen). This is local saving, not a Git commit.

## Publishing

With the Git backend, the last peer leaving is asked to commit and push. `--yes` skips the prompt. `--force-push` permits a configured force push.

> [!CAUTION]
> Starting a fresh Git-backed session resets the working tree to `HEAD` and runs `git clean -fd`. Commit anything you want to keep first.

## Limits

- Max file size: 16 MiB
- Initial seed: 10,000 files / 200 MB
- Symlinks are never followed
- Files containing NUL bytes are treated as binary
- Indirect sync: roughly 2 seconds per hop

## Troubleshooting

- **General fix** - nuking `.c3` may resolve the problem caused by old session config
- **No invite** - use `--tunnel cloudflare` or `--advertise`
- **Can't connect across networks** - the host needs global IPv6, a public IP, a tunnel, or a mesh VPN address
- **Invite stopped working** - the network changed; run `share` again
- **Joined but no state** - the host must stay running until file counts match
- **Unexpected peers** - check for leftover `c3` processes, then restart
