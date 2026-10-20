# CIII (c3)

> If things don't work, think of trying to look inside a coconut without breaking it. That's what CoCoCode is.

CIII is a peer-to-peer tool for live collaborative coding. It syncs project files between teammates on Windows, Linux, and macOS.

Peers discover each other through a distributed hash table (DHT) and connect directly. There is no dedicated host or manual port forwarding. Connections are encrypted.

Requires **Node.js 22 or newer**.

## Quick start

Clone CIII into your project, then install and configure it:

```bash
cd my-project
git clone https://github.com/feztromo/ciii.git c3
echo c3/ >> .gitignore
cd c3
npm install
node c3.js config
node c3.js connect
```

The configuration wizard lets you choose how sessions are archived and set a session name and key.

## Invite others

Share the session name and key with your teammates outside of CIII. They clone CIII into their project, install dependencies, and connect using the same details:

```bash
node c3.js connect --name "my_project" --key <key>
```

Peers using the same name and key join the same session. Once configured, `node c3.js connect` is enough.

## Commands

| Command | Description |
|---|---|
| `node c3.js config` | Configure the session and archive backend |
| `node c3.js connect` | Start or join a session |
| `node c3.js export [dir]` | Export shareable files to a directory |
| `node c3.js doctor` | Check configuration and DHT connectivity |

## Saving work

Choose an archive backend during configuration.

| Backend | Behaviour |
|---|---|
| `git` | Commits changes and pushes to `origin` |
| `folder` | Saves timestamped snapshots to a directory |
| `none` | Does not archive automatically. Use `export` to keep a copy |

When the last peer leaves, CIII asks whether to publish the session. If others are still connected, the current state is kept locally instead. Unsaved state can be restored when reconnecting.

## Configuration

| Option | Description |
|---|---|
| `C3_KEY` | Provide the session key through an environment variable |
| `--name <name>` | Set the session name when connecting |
| `--key <key>` | Set the session key when connecting |
| `--yes` | Confirm publishing without prompting |
| `--archive <type>` | Select `git`, `folder:<path>`, or `none` during configuration |

Advanced options can be set in `c3/.c3/config.json`. For example, `verify` runs a command before publishing:

```json
{
  "verify": "npm test"
}
```

## How it works

- **Discovery:** Hyperswarm uses a distributed hash table to find peers with the same session name and key.
- **Sync:** Yjs keeps file changes in sync between connected peers.
- **Networking:** Hyperswarm establishes direct peer-to-peer connections across networks without manual port forwarding.
- **Encryption:** Peer connections are encrypted. The session name and key determine the room peers join.
- **File safety:** CIII rejects unsafe paths, symlink escapes, and files larger than 16 MiB. Common generated folders and sensitive file patterns are ignored by default.

## File layout

```text
my-project/
├── .git/
├── src/
└── c3/                 # cloned repository
    ├── c3.js
    ├── package.json
    └── .c3/             # created during setup
        ├── config.json
        ├── id
        └── <hash>/
            ├── key
            ├── state.bin
            └── state.gen
```

Keep `c3/` in your project's `.gitignore`. Configuration and session state live in `c3/.c3/` and should not be committed to your project repository.

## Troubleshooting

- Run `node c3.js doctor` to check the setup.
- Make sure every peer uses the same session name and key.
- Check that `npm install` completed and that Node.js 22 or newer is installed.
- If the DHT cannot be reached, check whether your network or firewall blocks outbound UDP.