# CIII (c3)

> If things don't work, think of trying to look inside a coconut without breaking it. That's what CoCoCode is.


Live coding with your team. No central server. Use it on the same Wi-Fi or over the internet.

Clone it into your project and set it up once, then connect. When you leave it can save your work to git or a folder.

## Quick start

```bash
# 1. Clone it into your project
cd my-project
git clone https://github.com/you/ciii.git c3
echo "c3/" >> .gitignore

# 2. Install (once)
cd c3 && npm install

# 3. Set it up (interactive wizard)
node c3.js config

# 4. Connect
node c3.js connect
```

## Invite others

**Same Wi-Fi:** nothing extra needed.

```bash
node c3.js connect   # finds peers automatically
```

**Remote peers:** share your session key. If you use a relay then share its URL too.

```bash
# You run this (or host relay.js on a VPS)
node c3.js connect

# They run this
node c3.js connect --name "myproject" --key <key>
```

If you have a public IP or a router with UPnP your laptop becomes a relay by itself. If not you can run `node relay.js` on any VPS. A VPS is just a rented server.

## Commands

| Command | What it does |
|---------|--------------|
| `node c3.js config` | Pick an archive backend and set a name and key |
| `node c3.js connect` | Start or join a session |
| `node c3.js export [dir]` | Copy the current files to a folder |
| `node c3.js doctor` | Check your setup and connection |

## Archive backends

| Backend | What happens when you leave |
|---------|-----------------------------|
| `git` | Commits and pushes to origin |
| `folder` | Saves a dated copy in `/path/to/folder/snapshots/` |
| `none` | Nothing is saved. Use `export` to keep a copy |

## Environment variables

| Variable | What it does |
|----------|--------------|
| `C3_KEY` | Session key so you are not asked for it |
| `C3_SIGNALING` | Relay URLs split by commas |
| `C3_VERBOSE=1` | Show all debug output |
| `C3_NO_LAN=1` | Turn off LAN discovery |
| `C3_NO_UPNP=1` | Turn off UPnP port mapping |

## How it works

- **LAN:** Peers find each other with a UDP broadcast and connect directly over WebSocket.
- **Internet:** It connects to all known relays at once. Peers also share their relay lists.
- **Sync:** Edits sync with Yjs (a CRDT). Everything is encrypted with AES-256-GCM.
- **Safety:** Every file path and symlink is checked before anything is written to disk.

## File layout (after clone)

```
my-project/
├── .git/
├── src/
├── c3/                 <-- cloned repo
│   ├── c3.js           <-- main tool
│   ├── relay.js        <-- optional public relay
│   ├── package.json
│   └── .c3/            <-- created when you run it
│       ├── config.json
│       ├── id
│       └── <hash>/
│           ├── key
│           ├── state.bin
│           └── state.gen
```

Nothing in `c3/` is tracked by your main repo. Add `c3/` to `.gitignore`.
