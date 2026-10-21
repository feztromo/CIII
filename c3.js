// CIII (c3) -- P2P live session (git | folder | none).
// Clone this folder into your project, add "c3/" to .gitignore, then:
//   npm install
//   node c3.js config
//   node c3.js connect
// No host. No ports. No IPs. Peers find each other through a DHT
// (same trick as BitTorrent) and sync directly, hole-punched, encrypted.
// Node 22+.
//
// Wire protocol v2 (binary, length-prefixed). Not compatible with older
// c3 versions: everyone in a session must run this version.

import * as Y from 'yjs'
import Hyperswarm from 'hyperswarm'
import chokidar from 'chokidar'
import ignore from 'ignore'
import { execFileSync, spawnSync } from 'node:child_process'
import readline from 'node:readline/promises'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import os from 'node:os'
import crypto from 'node:crypto'

const argv = process.argv.slice(2)
const cmd = argv[0]
const flag = n => { const i = argv.indexOf('--' + n); return (i >= 0 && argv[i + 1]) ? argv[i + 1] : undefined }
const has = n => argv.includes('--' + n)

const IS_WIN = process.platform === 'win32'

const c3Dir = path.dirname(fileURLToPath(import.meta.url))
const SESSION_DIR = path.join(c3Dir, '.c3')
const CONFIG_FILE = path.join(SESSION_DIR, 'config.json')
const ID_FILE = path.join(SESSION_DIR, 'id')
const STATE_ROOT = SESSION_DIR

const workDir = path.resolve(c3Dir, '..')
const c3Rel = path.relative(workDir, c3Dir).split(path.sep).join('/')
const c3InsideWork = !c3Rel.startsWith('..') && !path.isAbsolute(c3Rel)
const c3Name = path.basename(c3Dir)

const MAX_FILE = 16 << 20
const MAX_FRAME = 1 << 29          // 512 MB hard cap on a single wire frame
const SEED_FILES = 10_000
const SEED_BYTES = 200 << 20
const PEER_WAIT_MS = 2500          // only waited when no peer answers sooner
const WRITE_DEBOUNCE_MS = 40       // coalesce bursts of remote edits per file
const PROTOCOL = 'c3v2'            // mixed into the topic so old clients never meet new ones

const sleep = ms => new Promise(r => setTimeout(r, ms))
const die = m => { console.error(m); process.exit(1) }
const mkdirp = a => fs.mkdirSync(a, { recursive: true })
const atomicWrite = (abs, data) => {
  fs.writeFileSync(abs + '.tmp-' + process.pid, data)
  fs.renameSync(abs + '.tmp-' + process.pid, abs)
}

const C = IS_WIN ? { r:'', d:'', red:'', grn:'', yel:'', cyn:'' } : { r:'\x1b[0m', d:'\x1b[2m', red:'\x1b[31m', grn:'\x1b[32m', yel:'\x1b[33m', cyn:'\x1b[36m' }
const ui = {
  set(msg) { if (process.stdout.isTTY) process.stdout.write(`\r\x1b[K* c3${C.r} ${msg}`) },
  clear() { if (process.stdout.isTTY) process.stdout.write('\r\x1b[K') },
  say(...a) { this.clear(); console.log(`* c3${C.r}`, ...a) },
  warn(...a) { this.clear(); console.error(`! warning${C.r}`, ...a) }
}
const onceWarned = new Set()
function warnOnce(key, ...a) { if (!onceWarned.has(key)) { onceWarned.add(key); ui.warn(...a) } }

const git = (...a) => execFileSync('git', a, { cwd: workDir, encoding: 'utf8', maxBuffer: 1 << 26 }).trim()
const gitOk = (...a) => { try { return git(...a) } catch { return null } }

// git check-ignore spawns a process, so remember the answers.
// The cache is cleared whenever .gitignore changes (see the watcher).
const ignoredCache = new Map()
const isGitIgnored = rel => {
  let v = ignoredCache.get(rel)
  if (v === undefined) {
    try { git('check-ignore', '-q', rel); v = true } catch { v = false }
    if (ignoredCache.size > 50_000) ignoredCache.clear()
    ignoredCache.set(rel, v)
  }
  return v
}

const readId = () => { try { return fs.readFileSync(ID_FILE, 'utf8').trim() } catch { return null } }
const ensureId = () => { mkdirp(SESSION_DIR); if (!readId()) atomicWrite(ID_FILE, crypto.randomUUID()); return readId() }
const stateDir = id => { const d = path.join(STATE_ROOT, crypto.createHash('sha1').update(id).digest('hex')); mkdirp(d); return d }
const canonUrl = u => u.replace(/^[a-z+]+:\/\//, '').replace(/^[^@]+@/, '').replace(/\.git$/, '').replace(/^([^/]+):/, '$1/')

function safeRel(rel) {
  if (typeof rel !== 'string' || rel === '') return null
  const abs = path.resolve(workDir, rel)
  if (abs !== workDir && !abs.startsWith(workDir + path.sep)) return null
  const norm = path.relative(workDir, abs).split(path.sep).join('/')
  if (norm === '.git' || norm.startsWith('.git/')) return null
  if (c3InsideWork && (norm === c3Rel || norm.startsWith(c3Rel + '/'))) return null
  return norm
}
function symlinkEscape(abs) {
  let cur = workDir
  try {
    for (const part of path.relative(workDir, abs).split(path.sep)) {
      cur = path.join(cur, part)
      if (fs.lstatSync(cur).isSymbolicLink()) return true
    }
  } catch {}
  return false
}

const DEFAULT_IGNORE = ['node_modules/', 'dist/', 'build/', 'out/', '.env*', '*.pem', 'id_rsa*', '*.log', '.DS_Store', 'Thumbs.db', 'desktop.ini']
function rulesMatcher() {
  const ig = ignore().add(DEFAULT_IGNORE)
  const f = path.join(SESSION_DIR, 'ignore')
  if (fs.existsSync(f)) ig.add(fs.readFileSync(f, 'utf8'))
  // true = shareable. Never throws on odd paths.
  return rel => { try { return !ig.ignores(rel) } catch { return true } }
}
// dirOk lets us skip whole ignored directories (node_modules etc.) without reading them.
function walkTree(isShareable, dirOk = () => true) {
  const out = []
  const walk = (abs, rel) => {
    for (const e of fs.readdirSync(abs, { withFileTypes: true })) {
      if (e.name === '.git') continue
      if (c3InsideWork && e.name === c3Name && abs === workDir) continue
      const r = rel ? rel + '/' + e.name : e.name
      if (e.isDirectory()) { if (dirOk(r)) walk(path.join(abs, e.name), r) }
      else if (e.isFile() && isShareable(r)) out.push(r)
    }
  }
  walk(workDir, '')
  return out
}

// ---------- archive backends ----------
function makeBackend(config) {
  const rules = rulesMatcher()
  if (config.backend === 'git') {
    return {
      kind: 'git',
      excluded: null,
      identity() {
        const u = gitOk('remote', 'get-url', 'origin')
        if (u) return canonUrl(u)
        return readId() ?? die('No origin remote and no .c3/id -- pass --name or run c3 config.')
      },
      prepare() {
        gitOk('fetch')
        const up = gitOk('rev-parse', '--abbrev-ref', '@{u}')
        if (up) git('reset', '--hard', up)
      },
      listShareable() { return git('ls-files', '-z').split('\0').filter(Boolean).filter(rules) },
      isShareable(rel) { return rules(rel) && !isGitIgnored(rel) },
      generation() { return gitOk('rev-parse', 'HEAD') ?? 'no-head' },
      save(touched, meta, { publish = true } = {}) {
        const paths = [...touched].filter(r => fs.existsSync(path.join(workDir, r)) || files.has(r) || !!gitOk('ls-files', '--', r))
        for (let i = 0; i < paths.length; i += 500) git('add', '-A', '--', ...paths.slice(i, i + 500))
        if (!git('status', '--porcelain')) return { saved: false }
        const idc = gitOk('config', 'user.name') ? [] : ['-c', 'user.name=c3', '-c', 'user.email=c3@localhost']
        git(...idc, 'commit', '-m', meta.message)
        if (!publish) return { saved: true, pushed: false }
        try { git('push'); return { saved: true, pushed: true } }
        catch {
          try { git('pull', '--rebase'); git('push'); return { saved: true, pushed: true } }
          catch { gitOk('rebase', '--abort'); return { saved: true, pushed: false } }
        }
      },
    }
  }
  if (config.backend === 'folder') {
    const archive = path.resolve(workDir, config.archive)
    const lock = path.join(archive, '.c3-lock')
    const insideWork = archive.startsWith(workDir + path.sep)
    const relArchive = insideWork ? path.relative(workDir, archive).split(path.sep).join('/') : null
    const inArchive = rel => !!relArchive && (rel === relArchive || rel.startsWith(relArchive + '/'))
    const dirOk = d => !inArchive(d) && rules(d + '/')
    return {
      kind: 'folder',
      excluded: relArchive,
      identity: () => readId() ?? die('folder backend needs .c3/id -- run c3 config or pass --name'),
      prepare() {
        mkdirp(path.join(archive, 'snapshots'))
        if (archive === workDir) die('archive path cannot be the working dir itself; use backend "none" for that')
        if (insideWork) ui.say('archive folder is inside the working tree (excluded from sync).')
      },
      listShareable() { return walkTree(r => this.isShareable(r), dirOk) },
      isShareable(rel) {
        if (inArchive(rel)) return false
        return rules(rel)
      },
      generation() { try { return fs.readFileSync(path.join(archive, 'gen'), 'utf8').trim() } catch { return '0' } },
      save(touched, meta) {
        if (fs.existsSync(lock)) {
          try {
            const l = JSON.parse(fs.readFileSync(lock, 'utf8'))
            if (Date.now() - l.ts < 2 * 3600_000 && !(l.host === os.hostname() && l.pid === process.pid))
              return { saved: false, blocked: `archive locked by ${l.host}` }
          } catch {}
        }
        atomicWrite(lock, JSON.stringify({ host: os.hostname(), pid: process.pid, ts: Date.now() }))
        try {
          const ts = new Date().toISOString().replace(/[:.]/g, '-')
          const snap = path.join(archive, 'snapshots', ts)
          const list = walkTree(r => this.isShareable(r), dirOk)
          for (const rel of list) {
            mkdirp(path.dirname(path.join(snap, rel)))
            fs.copyFileSync(path.join(workDir, rel), path.join(snap, rel))
          }
          atomicWrite(path.join(archive, 'gen'), String(Number(this.generation()) + 1))
          fs.appendFileSync(path.join(archive, '.c3-session-log'), `${ts}  ${meta.user}  ${list.length}f  ${touched.size}c${meta.verifyFailed ? ' FAIL' : ''}\n`)
          return { saved: true, pushed: true, snapshot: snap }
        } finally { fs.rmSync(lock, { force: true }) }
      },
    }
  }
  if (config.backend === 'none') {
    return {
      kind: 'none',
      excluded: null,
      identity: () => readId() ?? die('backend "none" has no identity channel -- pass --name or run c3 config'),
      prepare() {},
      listShareable() { return walkTree(rules, d => rules(d + '/')) },
      isShareable: rules,
      generation: () => 'static',
      save() { return { saved: false, exported: false } },
    }
  }
  die('Unknown backend: ' + config.backend)
}

// ---------- Yjs state ----------
const doc = new Y.Doc()
const files = doc.getMap('files')   // path -> { id, bin }
const texts = doc.getMap('texts')   // id -> Y.Text
const blobs = doc.getMap('blobs')   // id -> Uint8Array (raw bytes, no base64)
const touched = new Set()
let backend = null

// id -> path index, so content events don't scan every file
const idToPath = new Map()
const pathOf = id => idToPath.get(id)

function applyDiff(t, next) {
  const cur = t.toString()
  if (cur === next) return false
  let s = 0
  while (s < cur.length && s < next.length && cur[s] === next[s]) s++
  let e = 0
  while (e < cur.length - s && e < next.length - s && cur[cur.length - 1 - e] === next[next.length - 1 - e]) {
    e++
  }
  if (cur.length - s - e > 0) t.delete(s, cur.length - s - e)
  if (next.length - s - e > 0) t.insert(s, next.slice(s, next.length - e))
  return true
}

const asBuf = u => Buffer.from(u.buffer, u.byteOffset, u.byteLength)

function syncFromDisk(rel, seed = false) {
  const norm = safeRel(rel)
  // when seeding, listShareable() has already filtered; skip the per-file git spawn
  if (!norm || (!seed && !backend.isShareable(norm))) return
  let buf
  try { buf = fs.readFileSync(path.join(workDir, norm)) } catch { return }
  doc.transact(() => {
    const entry = files.get(norm)
    if (!entry) {
      const bin = buf.includes(0)
      const id = crypto.randomUUID()
      files.set(norm, { id, bin })
      if (bin) blobs.set(id, new Uint8Array(buf))
      else texts.set(id, new Y.Text(buf.toString('utf8')))
      if (!seed) touched.add(norm)
    } else if (entry.bin) {
      const cur = blobs.get(entry.id)
      if (!cur || Buffer.compare(asBuf(cur), buf) !== 0) {
        blobs.set(entry.id, new Uint8Array(buf))
        if (!seed) touched.add(norm)
      }
    } else {
      const t = texts.get(entry.id)
      if (t && applyDiff(t, buf.toString('utf8')) && !seed) touched.add(norm)
    }
  }, 'disk')
}

function removeFromDoc(rel) {
  doc.transact(() => {
    const entry = files.get(rel)
    if (!entry) return
    touched.add(rel)
    files.delete(rel); texts.delete(entry.id); blobs.delete(entry.id)
  }, 'disk')
}

const lastWritten = new Map()

function writeToDisk(rawRel) {
  const entry = files.get(rawRel)
  if (!entry) return
  const rel = safeRel(rawRel)
  if (!rel || rel !== rawRel) { warnOnce('unsafe-' + rawRel, 'blocked unsafe path from peer:', rawRel); return }
  const abs = path.join(workDir, rel)
  if (symlinkEscape(abs)) { warnOnce('symlink', 'blocked symlink escape:', rel); return }
  let data
  if (entry.bin) {
    const b = blobs.get(entry.id)
    data = b ? asBuf(b) : Buffer.alloc(0)
  } else {
    data = Buffer.from(texts.get(entry.id)?.toString() ?? '', 'utf8')
  }
  if (data.length > MAX_FILE) { warnOnce('big-' + rel, 'blocked oversized file from peer:', rel); return }
  try {
    if (fs.existsSync(abs) && Buffer.compare(fs.readFileSync(abs), data) === 0) return
    mkdirp(path.dirname(abs))
    atomicWrite(abs, data)
    lastWritten.set(rel, Date.now())
  } catch (err) { warnOnce('write-' + rel, 'write failed:', rel, err.message) }
}

// Debounced writes: a peer typing fast produces one disk write per file per
// WRITE_DEBOUNCE_MS instead of one per keystroke.
const pendingWrites = new Map()
function scheduleWrite(rel) {
  clearTimeout(pendingWrites.get(rel))
  pendingWrites.set(rel, setTimeout(() => { pendingWrites.delete(rel); writeToDisk(rel) }, WRITE_DEBOUNCE_MS))
}
function cancelWrite(rel) {
  clearTimeout(pendingWrites.get(rel))
  pendingWrites.delete(rel)
}
function flushWrites() {
  for (const [rel, t] of pendingWrites) { clearTimeout(t); writeToDisk(rel) }
  pendingWrites.clear()
}

const remote = tx => tx.origin !== 'disk' && tx.origin !== 'restore'

files.observe(ev => {
  // keep the id index current for every kind of change (local, remote, restore)
  for (const [key, change] of ev.keys) {
    if (change.action === 'delete') {
      const old = change.oldValue
      if (old?.id && idToPath.get(old.id) === key) idToPath.delete(old.id)
    } else {
      const entry = files.get(key)
      if (change.action === 'update' && change.oldValue?.id && change.oldValue.id !== entry?.id) idToPath.delete(change.oldValue.id)
      if (entry?.id) idToPath.set(entry.id, key)
    }
  }
  if (!remote(ev.transaction)) return
  for (const [rawRel, change] of ev.keys) {
    const rel = safeRel(rawRel)
    if (!rel) { warnOnce('unsafe-' + rawRel, 'blocked unsafe path from peer:', rawRel); continue }
    if (change.action === 'delete') {
      touched.add(rel)
      cancelWrite(rel)
      fs.rmSync(path.join(workDir, rel), { force: true })
    } else { touched.add(rel); scheduleWrite(rawRel) }
  }
})
const onContent = evs => {
  if (!remote(evs[0].transaction)) return
  for (const ev of evs) {
    const ids = ev.target === texts || ev.target === blobs ? [...ev.keys.keys()] : [ev.path[0]]
    for (const id of ids) { const p = pathOf(id); if (p) { touched.add(p); scheduleWrite(p) } }
  }
}
texts.observeDeep(onContent)
blobs.observeDeep(onContent)

function reconcile() {
  for (const rel of files.keys()) writeToDisk(rel)
  if (backend.kind !== 'git' || files.size === 0) return
  for (const rel of backend.listShareable())
    if (!files.has(rel)) fs.rmSync(path.join(workDir, rel), { force: true })
}

// ---------- wire protocol v2: [u32 length][u8 type][payload] ----------
// length covers the type byte plus the payload. Raw bytes, no base64, no JSON
// except for the tiny heartbeat.
const T_UPDATE = 1   // incremental Yjs update
const T_STATE = 2    // diff reply to a state vector (also an update)
const T_VECTOR = 3   // "here is what I already have, send me the rest"
const T_HELLO = 4    // heartbeat / awareness, JSON payload

function frame(type, payload) {
  const body = payload ? asBuf(payload) : Buffer.alloc(0)
  const head = Buffer.allocUnsafe(5)
  head.writeUInt32BE(body.length + 1, 0)
  head[4] = type
  return Buffer.concat([head, body])
}
function makeDecoder(onMsg, onBad) {
  let chunks = []
  let have = 0
  let need = null
  return data => {
    try {
      chunks.push(data); have += data.length
      for (;;) {
        if (need === null) {
          if (have < 4) return
          const head = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks)
          chunks = [head]
          need = head.readUInt32BE(0)
          if (need < 1 || need > MAX_FRAME) throw new Error('bad frame length')
        }
        if (have < 4 + need) return
        const all = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks)
        const body = all.subarray(4, 4 + need)
        const rest = all.subarray(4 + need)
        chunks = rest.length ? [rest] : []
        have = rest.length
        need = null
        onMsg(body[0], body.subarray(1))
      }
    } catch { onBad() }
  }
}

// ---------- connect ----------
async function connect() {
  let config
  try { config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) }
  catch {
    if (flag('name') || flag('key') || process.env.C3_KEY)
      config = { backend: fs.existsSync(path.join(workDir, '.git')) ? 'git' : 'none' }
    else die('No config. Run `c3 config`, or bootstrap with --name and --key.')
  }
  ensureId()
  backend = makeBackend(config)

  const name = flag('name') ?? config.name
  const identity = name ?? backend.identity()
  const sdir = stateDir(identity)
  const keyFile = path.join(sdir, 'key')
  let key = flag('key') ?? process.env.C3_KEY ?? (fs.existsSync(keyFile) ? fs.readFileSync(keyFile, 'utf8').trim() : null)
  if (!key) die('No session key. Get it from the host:\n  c3 connect --key <key>' + (name ? ` --name "${name}"` : ''))
  if (key.length < 20) ui.warn('key looks low-entropy -- prefer a generated one.')
  if (flag('key')) { atomicWrite(keyFile, key); fs.chmodSync(keyFile, 0o600) }

  // Topic: same name+key = same swarm on any machine. The DHT sees only this hash.
  const topic = crypto.createHash('sha256').update(PROTOCOL + '\0' + identity + '\0' + key).digest()

  const me = {
    name: gitOk('config', 'user.name') ?? (os.userInfo().username || 'unknown'),
    email: gitOk('config', 'user.email') ?? `${os.userInfo().username}@${os.hostname()}`,
  }
  const meId = crypto.randomBytes(8).toString('hex') // unique per process

  const swarm = new Hyperswarm()
  const conns = new Set()
  const awareness = new Map() // id -> { name, email, ts }
  const othersAlive = () => {
    let n = 0
    for (const [k] of awareness) if (k !== meId) n++
    return n
  }

  const broadcast = payload => {
    for (const conn of conns) { try { conn.write(payload) } catch {} }
  }
  const helloFrame = () => frame(T_HELLO, Buffer.from(JSON.stringify({ id: meId, name: me.name, email: me.email })))

  // resolves as soon as the first state diff from any peer has been applied
  let stateReceived
  const stateP = new Promise(r => { stateReceived = r })

  swarm.on('connection', conn => {
    conns.add(conn)
    conn._c3PeerId = null   // set when their first heartbeat arrives
    conn.on('data', makeDecoder((type, payload) => {
      if (type === T_UPDATE || type === T_STATE) {
        try { Y.applyUpdate(doc, payload, 'remote') } catch {}
        if (type === T_STATE) stateReceived()
      } else if (type === T_VECTOR) {
        // send only what the peer is missing
        try { conn.write(frame(T_STATE, Y.encodeStateAsUpdate(doc, payload))) } catch {}
      } else if (type === T_HELLO) {
        try {
          const m = JSON.parse(payload.toString('utf8'))
          awareness.set(m.id, { name: m.name, email: m.email, ts: Date.now() })
          conn._c3PeerId = m.id   // remember who owns this socket
        } catch {}
      }
    }, () => conn.destroy()))
    conn.on('close', () => {
      conns.delete(conn)
      if (conn._c3PeerId) awareness.delete(conn._c3PeerId)  // instant goodbye
    })
    conn.on('error', () => conns.delete(conn))
    try {
      // hello first so the peer counts us before our state diff lands
      conn.write(helloFrame())
      conn.write(frame(T_VECTOR, Y.encodeStateVector(doc)))
    } catch {}
  })

  // announce + look for peers with the same topic
  swarm.join(topic, { server: true, client: true })
  const earlyExit = () => { swarm.destroy().catch(() => {}).finally(() => process.exit(0)) }
  process.once('SIGINT', earlyExit)
  process.once('SIGTERM', earlyExit)

  backend.prepare()

  // broadcast local changes (registered before seeding so a seed reaches early joiners)
  doc.on('update', (update, origin) => {
    if (origin === 'remote' || origin === 'restore') return
    if (conns.size === 0) return
    broadcast(frame(T_UPDATE, update))
  })

  // crash-state restore with generation guard
  const stateFile = path.join(sdir, 'state.bin')
  const genFile = path.join(sdir, 'state.gen')
  let restored = false
  if (fs.existsSync(stateFile)) {
    const genThen = fs.existsSync(genFile) ? fs.readFileSync(genFile, 'utf8').trim() : null
    if (genThen && genThen !== backend.generation()) {
      ui.say('Saved session state predates latest archive -- discarding.')
      fs.rmSync(stateFile, { force: true })
    } else {
      Y.applyUpdate(doc, fs.readFileSync(stateFile), 'restore')
      for (const rel of files.keys()) touched.add(rel)
      restored = true
      ui.say('Restored unsaved state from last run.')
    }
  }
  let persistTimer
  const persist = () => {
    clearTimeout(persistTimer)
    persistTimer = setTimeout(() => {
      try { atomicWrite(stateFile, Y.encodeStateAsUpdate(doc)); atomicWrite(genFile, backend.generation()) } catch {}
    }, 3000)
  }
  doc.on('update', persist)

  ui.set('looking for peers through the DHT...')
  // Go as soon as a peer hands us state. Otherwise wait for the DHT lookup to
  // finish plus a short grace period, then assume we are the host.
  await Promise.race([
    stateP,
    swarm.flush().catch(() => {}).then(() => sleep(PEER_WAIT_MS)),
  ])

  if (!restored) {
    if (othersAlive() === 0 && files.size === 0) {
      const seed = backend.listShareable()
      let bytes = 0
      for (const rel of seed) { try { bytes += fs.statSync(path.join(workDir, rel)).size } catch {} }
      if (!config.forceSeed && (seed.length > SEED_FILES || bytes > SEED_BYTES))
        die(`Refusing to seed ${seed.length} files / ${(bytes / 1e6).toFixed(0)} MB. Trim c3/.c3/ignore, or set "forceSeed": true in config.`)
      ui.say(`No peers -- hosting from this directory (${seed.length} files).`)
      // one transaction = one Yjs update for the whole seed
      doc.transact(() => { for (const rel of seed) syncFromDisk(rel, true) }, 'disk')
    } else {
      ui.say(othersAlive() ? `Joined session with ${othersAlive()} peer(s).` : 'No peers yet -- waiting.')
      if (othersAlive() > 0) reconcile()
    }
  }

  const hb = setInterval(() => {
    broadcast(helloFrame())
    const now = Date.now()
    for (const [k, v] of awareness) if (now - v.ts > 12000) awareness.delete(k)
  }, 4000)

  // ---- file watcher: filter at the watcher so ignored trees are never walked ----
  const watchRules = rulesMatcher()
  const loadGitignore = () => {
    if (backend.kind !== 'git') return null
    try { return ignore().add(fs.readFileSync(path.join(workDir, '.gitignore'), 'utf8')) } catch { return null }
  }
  // Root .gitignore only, and only used to prune whole paths from the watcher.
  // isShareable (with real git check-ignore) stays the final authority.
  let rootGitignore = loadGitignore()

  const relOf = p => path.relative(workDir, p).split(path.sep).join('/')
  const watcherIgnored = p => {
    const r = relOf(p)
    if (!r) return false
    if (r === '.git' || r.startsWith('.git/')) return true
    if (c3InsideWork && (r === c3Rel || r.startsWith(c3Rel + '/'))) return true
    if (backend.excluded && (r === backend.excluded || r.startsWith(backend.excluded + '/'))) return true
    try {
      if (!watchRules(r) || !watchRules(r + '/')) return true
      if (rootGitignore && rootGitignore.ignores(r + '/')) return true
    } catch {}
    return false
  }
  const onGitignoreChange = r => {
    if (r === '.gitignore') { ignoredCache.clear(); rootGitignore = loadGitignore() }
  }
  chokidar.watch(workDir, {
    ignoreInitial: true,
    ignored: watcherIgnored,
    awaitWriteFinish: { stabilityThreshold: 50, pollInterval: 25 },
  })
    .on('add', p => { const r = relOf(p); onGitignoreChange(r); syncFromDisk(r) })
    .on('change', p => {
      const r = relOf(p)
      onGitignoreChange(r)
      const recent = lastWritten.get(r)
      if (recent && Date.now() - recent < 500) return
      if (pendingWrites.has(r)) return   // a newer remote version is about to land
      syncFromDisk(r)
    })
    .on('unlink', p => { const r = relOf(p); if (backend.isShareable(r)) removeFromDoc(r) })

  const sessionMessage = () => {
    const trailers = [...awareness.values()]
      .filter(u => u.email && u.email !== me.email)
      .map(u => `Co-authored-by: ${u.name} <${u.email}>`)
    return `Session snapshot ${new Date().toISOString()}` + (trailers.length ? '\n\n' + trailers.join('\n') : '')
  }
  const verifyOk = () => {
    if (!config.verify) return true
    ui.say('Running verify:', config.verify)
    return spawnSync(config.verify, { shell: true, cwd: workDir, stdio: 'inherit', timeout: 120_000 }).status === 0
  }
  async function confirmSave() {
    if (has('yes')) return true
    if (!process.stdin.isTTY) return false
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
    const a = (await rl.question(`Publish ${touched.size} changed path(s) to archive? [y/N] `)).trim().toLowerCase()
    rl.close()
    return a === 'y' || a === 'yes'
  }

  let leaving = false
  async function leave() {
    if (leaving) return
    leaving = true
    clearTimeout(persistTimer)
    clearInterval(hb)
    flushWrites()   // make sure the last remote edits reach disk before we save
    ui.clear()
    try {
      if (othersAlive() > 0) {
        atomicWrite(stateFile, Y.encodeStateAsUpdate(doc))
        atomicWrite(genFile, backend.generation())
        ui.say(`Others still in session (${othersAlive()}) -- keeping local state, not saving.`)
      } else if (touched.size === 0) {
        ui.say('Nothing changed -- nothing to save.')
        fs.rmSync(stateFile, { force: true })
      } else if (!(await confirmSave())) {
        atomicWrite(stateFile, Y.encodeStateAsUpdate(doc))
        atomicWrite(genFile, backend.generation())
        ui.say('Skipped publishing. Reconnect to retry, or `c3 export <dir>`.')
      } else {
        const verifyFailed = !verifyOk()
        if (verifyFailed && backend.kind === 'git') {
          ui.warn('Verify failed -- committing locally, NOT pushing.')
          backend.save(touched, { user: me.name, message: sessionMessage() }, { publish: false })
          atomicWrite(stateFile, Y.encodeStateAsUpdate(doc))
          atomicWrite(genFile, backend.generation())
        } else {
          const r = backend.save(touched, { user: me.name, message: sessionMessage(), verifyFailed })
          if (r.blocked) ui.warn(r.blocked)
          else if (!r.saved && r.exported === false && backend.kind === 'none')
            ui.say('No archive -- run `c3 export <dir>` to keep a copy.')
          else if (r.pushed === false) {
            ui.warn('Could not publish -- commit kept locally.')
            atomicWrite(stateFile, Y.encodeStateAsUpdate(doc))
            atomicWrite(genFile, backend.generation())
          } else {
            fs.rmSync(stateFile, { force: true })
            ui.say(r.snapshot ? `Snapshot written: ${r.snapshot}` : 'Saved and pushed.')
          }
        }
      }
    } catch (err) {
      try { atomicWrite(stateFile, Y.encodeStateAsUpdate(doc)); atomicWrite(genFile, backend.generation()) } catch {}
      console.error('Save failed -- state kept locally:', err.message)
    } finally {
      try { await swarm.destroy() } catch {}
      process.exit(0)
    }
  }

  const tick = setInterval(() => {
    const n = othersAlive()
    ui.set(`live - ${n} peer${n === 1 ? '' : 's'} - ${files.size} files - ${backend.kind}`)
  }, 2000)

  // swap the startup-only exit handlers for the real ones
  process.off('SIGINT', earlyExit)
  process.off('SIGTERM', earlyExit)
  ui.say('Ready. Ctrl+C to leave.')
  process.on('SIGINT', () => { clearInterval(tick); leave() })
  process.on('SIGTERM', () => { clearInterval(tick); leave() })
}

// ---------- config ----------
async function configCmd() {
  const isGit = fs.existsSync(path.join(workDir, '.git'))
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  const ask = async (q, def) => {
    if (!process.stdin.isTTY) return def
    const a = (await rl.question(`${C.cyn}?${C.r} ${q}${def ? ` [${C.yel}${def}${C.r}] ` : ': '}`)).trim()
    return a || def
  }
  ui.clear()
  console.log(`c3 config -- ${workDir}`)

  let raw = flag('archive')
  let kind, archivePath
  if (raw?.startsWith('folder:')) { kind = 'folder'; archivePath = raw.slice(7) }
  else if (['git','folder','none'].includes(raw)) { kind = raw }

  if (!kind) {
    const choice = await ask(`Backend archive
  1) git    - this project IS a git repo (snapshots become commits)
  2) folder - external path / NAS / server (dated snapshots)
  3) none   - no auto-archive (use export)
  Pick 1/2/3`, isGit ? '1' : '2')
    kind = { '1': 'git', '2': 'folder', '3': 'none' }[choice] || choice
  }
  if (!['git','folder','none'].includes(kind)) die('Backend must be git, folder:<path>, or none.')

  if (kind === 'git' && !isGit) die('No .git here -- git backend needs a repo.')
  if (kind === 'folder') {
    archivePath ??= await ask('Archive folder path (absolute or relative, e.g. /mnt/nas/c3-archive)', 'archive')
    archivePath = path.resolve(workDir, archivePath)
    if (archivePath === workDir) die('Archive path cannot be the working directory itself.')
  }
  const name = flag('name') ?? await ask('Session name (for invites)', path.basename(workDir))

  ensureId()
  const probe = makeBackend({ backend: kind, archive: archivePath })
  const identity = name || probe.identity()
  const keyFile = path.join(stateDir(identity), 'key')
  const existing = fs.existsSync(keyFile) ? fs.readFileSync(keyFile, 'utf8').trim() : null

  let key = flag('key')
  if (!key) {
    const c = (await ask(`Session key: new / paste${existing ? ' / keep' : ''}`, 'new')).toLowerCase()
    if (c === 'keep' && existing) key = existing
    else if (c === 'paste') key = (await rl.question('Paste key: ')).trim()
    else key = crypto.randomBytes(16).toString('base64url')
  }
  if (key.length < 20) ui.warn('low-entropy key -- prefer a generated one.')
  atomicWrite(keyFile, key); fs.chmodSync(keyFile, 0o600)

  const config = { backend: kind, name }
  if (archivePath) config.archive = archivePath
  atomicWrite(CONFIG_FILE, JSON.stringify(config, null, 2))

  if (kind === 'git') {
    const ex = path.join(workDir, '.git', 'info', 'exclude')
    mkdirp(path.dirname(ex))
    const cur = fs.existsSync(ex) ? fs.readFileSync(ex, 'utf8') : ''
    const line = c3Name + '/'
    if (!cur.split('\n').includes(line)) fs.appendFileSync(ex, '\n' + line + '\n')
  }
  rl.close()

  ui.clear()
  console.log(`Config written: ${CONFIG_FILE}`)
  console.log('Key and state stay inside the c3 folder (not pushed).')
  console.log('')
  console.log('Invite teammates (share in chat):')
  console.log(`  node c3.js connect --name "${name}" --key ${key}`)
}

// ---------- export ----------
function exportCmd() {
  const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'))
  backend = makeBackend(config)
  const dest = path.resolve(argv.slice(1).find(a => !a.startsWith('--')) ?? 'c3-export-' + new Date().toISOString().replace(/[:.]/g, '-'))
  let n = 0
  for (const rel of backend.listShareable()) {
    mkdirp(path.dirname(path.join(dest, rel)))
    fs.copyFileSync(path.join(workDir, rel), path.join(dest, rel)); n++
  }
  ui.say(`Exported ${n} files to ${dest}`)
}

// ---------- doctor ----------
async function doctor() {
  let config = null
  if (fs.existsSync(CONFIG_FILE)) { try { config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) } catch {} }

  const lines = []
  let failed = false
  const ok = (n, c, hint) => {
    if (!c) failed = true
    lines.push(`${c ? `${C.grn}+${C.r}` : `${C.red}-${C.r}`} ${n}${c ? '' : ` -- ${hint}`}`)
  }
  ok('Node 22+', Number(process.version.slice(1).split('.')[0]) >= 22, 'upgrade Node')
  ok('project config', fs.existsSync(CONFIG_FILE), 'run `c3 config`')
  let isIgnored = false
  try { execFileSync('git', ['check-ignore', '-q', 'c3/'], { cwd: workDir }); isIgnored = true } catch { isIgnored = false }
  ok('c3 ignored by git', isIgnored, `add "${c3Name}/" to .gitignore`)
  if (config) {
    try {
      backend = makeBackend(config)
      const identity = config.name ?? backend.identity()
      ok('identity resolved', !!identity, 'pass --name or set one in config')
      ok('session key present', fs.existsSync(path.join(stateDir(identity), 'key')), 'run `c3 config`')
    } catch (e) { ok('identity resolved', false, e.message) }
  }
  // DHT smoke test: join a throwaway topic and see if the DHT responds
  ok('DHT reachable', await new Promise(res => {
    const s = new Hyperswarm()
    const t = setTimeout(() => { s.destroy().catch(() => {}); res(false) }, 8000)
    try {
      const d = s.join(crypto.randomBytes(32))
      d.on('update', () => { clearTimeout(t); s.destroy().catch(() => {}); res(true) })
      s.flush().catch(() => {})
    } catch {
      clearTimeout(t); res(false)
    }
  }), 'no DHT response -- check firewall allows outbound UDP')
  ui.clear()
  console.log(lines.join('\n'))
  console.log(failed ? 'Some checks failed.' : 'All good.')
}

// ---------- dispatch ----------
const usage = `usage: node c3.js <command> [flags]

Commands:
  config    interactive wizard (once per project)
  connect   join/start live session
  export    copy tree to directory (save for backend "none")
  doctor    diagnose config, key, and DHT connectivity

Flags:
  --name <n>        session name
  --key <k>         session key
  --yes             auto-confirm publish
  --archive <type>  set backend (git | folder:<path> | none)

How it works:
  Peers find each other through a distributed hash table (the same
  trick BitTorrent uses), then sync directly peer-to-peer. Every
  connection is encrypted end to end. No host, no ports, no IPs,
  no signaling servers. Same session name + key on any machine
  = same room.

Advanced options (edit .c3/config.json directly):
  "verify": "npm test"    run this command before publishing
`

if (cmd === 'config') await configCmd()
else if (cmd === 'connect') await connect()
else if (cmd === 'export') exportCmd()
else if (cmd === 'doctor') await doctor()
else die(usage)