# CIII (c3)

> If things don't work, think of trying to look inside a coconut without breaking it. That's what CoCoCode is.

CIII is a peer-to-peer tool for collaborative coding. It uses WebRTC to sync files between teammates on Windows, Linux, and macOS.

No dedicated host or port forwarding is required. Peers discover each other through signaling servers and connect directly.

## Quick start

```bash
# Clone into your project
cd my-project
git clone https://github.com/feztromo/ciii.git c3
echo c3/ >> .gitignore

# Install dependencies
cd c3 && npm install

# Configure and connect
node c3.js config
node c3.js connect
```

## Invite others

Share the session name and key outside of CIII.

```bash
node c3.js connect --name "myproject" --key <key>
```

Anyone using the same name and key joins the same session. If already configured, `node c3.js connect` is enough.

## Commands

| Command | Description |
|---|---|
| `node c3.js config` | Configure session and archive settings |
| `node c3.js connect` | Join or start a session |
| `node c3.js export [dir]` | Export files to a directory |
| `node c3.js doctor` | Check setup and connectivity |

## Saving work

Choose an archive backend during configuration.

| Backend | Behaviour |
|---|---|
| `git` | Commits and pushes to `origin` |
| `folder` | Saves timestamped snapshots to a directory |
| `none` | Does not save automatically |

When the last peer leaves, CIII offers to archive the session. If others are still connected, the state remains local and is restored on the next run.

## Configuration

| Variable | Description |
|---|---|
| `C3_KEY` | Set the session key through the environment |
| `C3_SIGNALING` | Additional signaling URLs, comma-separated |
| `C3_VERBOSE=1` | Enable debug output |

## How it works

- **Discovery:** Signaling servers find peers using a shared room hash.
- **Sync:** WebRTC data channels sync edits using Yjs.
- **Encryption:** Session traffic is encrypted end to end using the session key. Signaling servers do not receive file contents.
- **Networking:** ICE and STUN handle connection setup across networks. Direct connections may fail on restrictive networks. TURN can be configured as a relay.
- **File safety:** Paths and symlinks are checked, and oversized or unsafe writes are rejected.

## File layout

```
my-project/
├── .git/
├── src/
├── c3/                 <-- cloned repo
│   ├── c3.js           <-- main tool
│   ├── package.json
│   └── .c3/            <-- created when you run it
│       ├── config.json
│       ├── id
│       └── <hash>/
│           ├── key
│           ├── state.bin
│           └── state.gen
```

Add `c3/` to your project's `.gitignore`. Its configuration and session state are stored in `c3/.c3/`.

## Troubleshooting

- Run `node c3.js doctor`.
- Verify that all peers use the same session name and key.
- Make sure `npm install` completed successfully.
- If direct WebRTC connections fail on a restrictive network, configure a TURN relay.