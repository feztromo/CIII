#!/usr/bin/env node
// CIII (c3) -- P2P live session (git | folder | none).
// Put c3.js and net.js in c3/, add "c3/" to .gitignore, then:
//   npm install
//   node c3.js config
//   node c3.js connect
//   node c3.js share            <- paste once to the other peer
//   node c3.js peer "<ma>"      <- paste their share line here
// No host. No DHT. No third-party relay. Every peer listens, dials, relays,
// and holds a full replica. First contact needs one pasted address per pair
// (no firewall rules); after that peers punch UDP and reconnect on their own.
// Payloads are AES-256-GCM with the session key over TCP, WebSocket, or UDP.
// Node 22+.
import * as Y from 'yjs'
import readline from 'node:readline/promises'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import os from 'node:os'
import crypto from 'node:crypto'
import net from 'node:net'
import dgram from 'node:dgram'
import { loadKey, makeNode, joinCall, joinResponder, sync, addrsOf, toMa, tokenKey, tokenTopic } from './net.js'

const argv = process.argv.slice(2)
const cmd = argv[0]
const flagVals = n => {
  const out = []
  for (let i = 0; i < argv.length; i++) if (argv[i] === '--' + n && argv[i + 1]) out.push(argv[++i])
  return out
}
const flag = n => flagVals(n)[0]
const has = n => argv.includes('--' + n)
const IS_WIN = process.platform === 'win32'
const c3Dir = path.dirname(fileURLToPath(import.meta.url))
const SESSION_DIR = path.join(c3Dir, '.c3')
const CONFIG_FILE = path.join(SESSION_DIR, 'config.json')
const workDir = path.resolve(c3Dir, '..')
const c3Rel = path.relative(workDir, c3Dir).split(path.sep).join('/')
const c3InsideWork = !c3Rel.startsWith('..') && !path.isAbsolute(c3Rel)
const c3Name = path.basename(c3Dir)
const DEFAULT_PORT = 8443
const MAX_FILE = 16 << 20
const MAX_FRAME = 256 << 20
const SEED_FILES = 10_000
const SEED_BYTES = 200 << 20
const PEER_WAIT_MS = 5000
const STATE_WAIT_MS = 12000
const WRITE_DEBOUNCE_MS = 40
const SCAN_MS = 8000            // polling is only a fallback; fs.watch is instant
const sleep = ms => new Promise(r => setTimeout(r, ms))
const die = m => { console.error(m); process.exit(1) }
const mkdirp = a => fs.mkdirSync(a, { recursive: true })
const chmod = (f, m) => { try { fs.chmodSync(f, m) } catch {} }
const atomicWrite = (abs, data) => {
  const tmp = abs + '.tmp-' + process.pid + '-' + crypto.randomBytes(4).toString('hex')
  fs.writeFileSync(tmp, data)
  fs.renameSync(tmp, abs)
}
const C = IS_WIN ? { r:'', d:'', red:'', grn:'', yel:'', cyn:'' } : { r:'\x1b[0m', d:'\x1b[2m', red:'\x1b[31m', grn:'\x1b[32m', yel:'\x1b[33m', cyn:'\x1b[36m' }
const ui = {
  set(msg) { if (process.stdout.isTTY) process.stdout.write(`\r\x1b[K* c3 ${msg}`) },
  clear() { if (process.stdout.isTTY) process.stdout.write('\r\x1b[K') },
  say(...a) { this.clear(); console.log('* c3', ...a) },
  warn(...a) { this.clear(); console.error('! warning', ...a) }
}
const onceWarned = new Set()
function warnOnce(key, ...a) { if (!onceWarned.has(key)) { onceWarned.add(key); ui.warn(...a) } }
const git = (...a) => execFileSync('git', a, { cwd: workDir, encoding: 'utf8', maxBuffer: 1 << 26 }).trim()
const gitOk = (...a) => { try { return git(...a) } catch { return null } }
const readConfig = () => { try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) } catch { return null } }

// ---------- session paths ----------
const sidOf = name => crypto.createHash('sha256').update('c3sid\0' + name).digest()
const sdirOf = name => {
  const d = path.join(SESSION_DIR, 's', sidOf(name).toString('hex').slice(0, 32))
  mkdirp(d)
  chmod(d, 0o700)
  return d
}
const readKey = sdir => { try { return fs.readFileSync(path.join(sdir, 'key'), 'utf8').trim() } catch { return null } }
const writeKey = (sdir, key) => { atomicWrite(path.join(sdir, 'key'), key); chmod(path.join(sdir, 'key'), 0o600) }
const peersFile = sdir => path.join(sdir, 'peers.json')
const readPeers = sdir => {
  try {
    const a = JSON.parse(fs.readFileSync(peersFile(sdir), 'utf8'))
    return Array.isArray(a) ? a.filter(x => typeof x === 'string' && x.length < 500).slice(0, 64) : []
  } catch { return [] }
}
const invitesFile = sdir => path.join(sdir, 'invites.json')
const readInvites = sdir => {
  try {
    const a = JSON.parse(fs.readFileSync(invitesFile(sdir), 'utf8'))
    return Array.isArray(a) ? a.filter(x => x && typeof x.tpc === 'string' && typeof x.sk === 'string') : []
  } catch { return [] }
}
const writeInvites = (sdir, a) => { atomicWrite(invitesFile(sdir), JSON.stringify(a.slice(-32), null, 2)); chmod(invitesFile(sdir), 0o600) }
const readIdentity = () => {
  try { const j = JSON.parse(fs.readFileSync(path.join(SESSION_DIR, 'identity.key'), 'utf8')); if (/^[0-9a-f]{16}$/.test(j.id)) return j } catch {}
  return null
}
const lanAddrs = (id, port, ws) => {
  const out = []
  for (const list of Object.values(os.networkInterfaces())) {
    for (const i of list || []) {
      if (i.family !== 'IPv4' || i.internal || i.address.startsWith('169.254.')) continue
      const ma = toMa(`${i.address}:${port}`, id)
      if (ma) out.push(ma)
      if (ws) { const mw = toMa(`${i.address}:${ws}`, id, true); if (mw) out.push(mw) }
    }
  }
  return out
}

// ---------- ignores ----------
const DEFAULT_IGNORE = ['.git', '.c3', 'node_modules', 'dist', 'build', 'out', '.env*', '*.pem', 'id_rsa*', '*.log', '.DS_Store', 'Thumbs.db', 'desktop.ini', '*.tmp', '*.tmp-*']
let customRules = []
function globRe(p) {
  if (p.endsWith('/')) p = p.slice(0, -1)
  let r = ''
  for (let i = 0; i < p.length; i++) {
    const ch = p[i]
    if (ch === '*') { if (p[i + 1] === '*') { r += '.*'; i++ } else r += '[^/]*' }
    else if (ch === '?') r += '[^/]'
    else r += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  }
  return new RegExp('(^|/)' + r + '(/|$)')
}
const DEFAULT_RULES = DEFAULT_IGNORE.map(globRe)
function loadIgnoreRules() {
  let lines = []
  try { lines = fs.readFileSync(path.join(SESSION_DIR, 'ignore'), 'utf8').split(/\r?\n/) } catch {}
  customRules = lines.map(l => l.trim()).filter(l => l && !l.startsWith('#')).map(globRe)
}
const ignoredCache = new Map()
const isGitIgnored = rel => {
  let v = ignoredCache.get(rel)
  if (v === undefined) {
    v = gitOk('check-ignore', '-q', '--', rel) !== null
    if (ignoredCache.size > 50_000) ignoredCache.clear()
    ignoredCache.set(rel, v)
  }
  return v
}
let backend = null
function safeRel(rel) {
  if (typeof rel !== 'string' || rel === '') return null
  const abs = path.resolve(workDir, rel)
  if (abs !== workDir && !abs.startsWith(workDir + path.sep)) return null
  const norm = path.relative(workDir, abs).split(path.sep).join('/')
  if (norm === '.git' || norm.startsWith('.git/')) return null
  if (c3InsideWork && (norm === c3Rel || norm.startsWith(c3Rel + '/'))) return null
  if (backend?.excluded && (norm === backend.excluded || norm.startsWith(backend.excluded + '/'))) return null
  return norm
}
function shouldIgnore(rel) {
  if (!rel) return false
  rel = rel.split(path.sep).join('/')
  if (rel === '.git' || rel.startsWith('.git/')) return true
  if (rel === '.c3' || rel.startsWith('.c3/')) return true
  if (c3InsideWork && (rel === c3Rel || rel.startsWith(c3Rel + '/'))) return true
  if (backend?.excluded && (rel === backend.excluded || rel.startsWith(backend.excluded + '/'))) return true
  if (DEFAULT_RULES.some(re => re.test(rel))) return true
  if (customRules.some(re => re.test(rel))) return true
  if (backend?.kind === 'git' && isGitIgnored(rel)) return true
  return false
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
function walkTree() {
  const out = []
  const walk = (abs, rel) => {
    let ents
    try { ents = fs.readdirSync(abs, { withFileTypes: true }) } catch { return }
    for (const e of ents) {
      const r = rel ? rel + '/' + e.name : e.name
      if (shouldIgnore(r)) continue
      if (e.isDirectory()) walk(path.join(abs, e.name), r)
      else if (e.isFile()) out.push(r)
    }
  }
  walk(workDir, '')
  return out
}

// ---------- Yjs state ----------
const doc = new Y.Doc()
const files = doc.getMap('files')
const texts = doc.getMap('texts')
const blobs = doc.getMap('blobs')
const touched = new Set()
const idToPath = new Map()
const lastWritten = new Map()
const diskMeta = new Map()
const pendingWrites = new Map()
const pathOf = id => idToPath.get(id)
const asBuf = u => Buffer.from(u.buffer, u.byteOffset, u.byteLength)
const remote = tx => tx.origin !== 'disk' && tx.origin !== 'restore'

function applyDiff(t, next) {
  const cur = t.toString()
  if (cur === next) return false
  let s = 0
  while (s < cur.length && s < next.length && cur[s] === next[s]) s++
  let e = 0
  while (e < cur.length - s && e < next.length - s && cur[cur.length - 1 - e] === next[next.length - 1 - e]) e++
  if (cur.length - s - e > 0) t.delete(s, cur.length - s - e)
  if (next.length - s - e > 0) t.insert(s, next.slice(s, next.length - e))
  return true
}
function syncFromDisk(rel, seed = false) {
  const norm = safeRel(rel)
  if (!norm || norm !== rel || shouldIgnore(norm)) return
  let data
  try { data = fs.readFileSync(path.join(workDir, norm)) } catch { return }
  if (data.length > MAX_FILE) { warnOnce('big-' + norm, 'skipped oversized file:', norm); return }
  const bin = data.includes(0)
  doc.transact(() => {
    const entry = files.get(norm)
    if (!entry) {
      const id = crypto.randomUUID()
      files.set(norm, { id, bin })
      if (bin) blobs.set(id, new Uint8Array(data))
      else texts.set(id, new Y.Text(data.toString('utf8')))
      if (!seed) touched.add(norm)
      return
    }
    if (entry.bin !== bin) {
      files.set(norm, { id: entry.id, bin })
      if (bin) { texts.delete(entry.id); blobs.set(entry.id, new Uint8Array(data)) }
      else { blobs.delete(entry.id); texts.set(entry.id, new Y.Text(data.toString('utf8'))) }
      if (!seed) touched.add(norm)
      return
    }
    if (bin) {
      const cur = blobs.get(entry.id)
      if (!cur || Buffer.compare(asBuf(cur), data) !== 0) {
        blobs.set(entry.id, new Uint8Array(data))
        if (!seed) touched.add(norm)
      }
    } else {
      const t = texts.get(entry.id)
      if (t && applyDiff(t, data.toString('utf8')) && !seed) touched.add(norm)
    }
  }, 'disk')
}
function removeFromDoc(rel) {
  doc.transact(() => {
    const entry = files.get(rel)
    if (!entry) return
    touched.add(rel)
    files.delete(rel)
    texts.delete(entry.id)
    blobs.delete(entry.id)
  }, 'disk')
}
function writeToDisk(rawRel) {
  const entry = files.get(rawRel)
  if (!entry) return
  const rel = safeRel(rawRel)
  if (!rel || rel !== rawRel) { warnOnce('unsafe-' + rawRel, 'blocked unsafe path from peer:', rawRel); return }
  if (shouldIgnore(rel)) { warnOnce('ignored-' + rel, 'blocked ignored path from peer:', rel); return }
  const abs = path.join(workDir, rel)
  if (symlinkEscape(abs)) { warnOnce('symlink-' + rel, 'blocked symlink escape:', rel); return }
  let data
  if (entry.bin) { const b = blobs.get(entry.id); data = b ? asBuf(b) : Buffer.alloc(0) }
  else data = Buffer.from(texts.get(entry.id)?.toString() ?? '', 'utf8')
  if (data.length > MAX_FILE) { warnOnce('big-' + rel, 'blocked oversized file from peer:', rel); return }
  try {
    if (fs.existsSync(abs) && Buffer.compare(fs.readFileSync(abs), data) === 0) return
    mkdirp(path.dirname(abs))
    atomicWrite(abs, data)
    lastWritten.set(rel, Date.now())
    try { const st = fs.statSync(abs); diskMeta.set(rel, st.mtimeMs + ':' + st.size) } catch {}
  } catch (err) { warnOnce('write-' + rel, 'write failed:', rel, err.message) }
}
function scheduleWrite(rel) {
  clearTimeout(pendingWrites.get(rel))
  pendingWrites.set(rel, setTimeout(() => { pendingWrites.delete(rel); writeToDisk(rel) }, WRITE_DEBOUNCE_MS))
}
function cancelWrite(rel) { clearTimeout(pendingWrites.get(rel)); pendingWrites.delete(rel) }
function flushWrites() { for (const [rel, t] of pendingWrites) { clearTimeout(t); writeToDisk(rel) } pendingWrites.clear() }
files.observe(ev => {
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
    if (!rel || rel !== rawRel) { warnOnce('unsafe-' + rawRel, 'blocked unsafe path from peer:', rawRel); continue }
    if (shouldIgnore(rel)) { warnOnce('ignored-' + rel, 'blocked ignored path from peer:', rel); continue }
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
  for (const rel of [...files.keys()]) writeToDisk(rel)
  if (backend.kind === 'git' && files.size) {
    const keep = new Set(files.keys())
    for (const rel of walkTree()) if (!keep.has(rel)) fs.rmSync(path.join(workDir, rel), { force: true })
  }
}

// ---------- archive backends ----------
function makeBackend(config) {
  if (config.backend === 'git') {
    return {
      kind: 'git',
      excluded: null,
      prepare() {
        gitOk('fetch')
        // never start a session on a detached HEAD
        if (gitOk('rev-parse', '--abbrev-ref', 'HEAD') === 'HEAD') {
          for (const b of ['master', 'main']) {
            if (gitOk('rev-parse', '--verify', '--quiet', 'refs/heads/' + b)) {
              try { git('checkout', b); break } catch {}
            }
          }
        }
      },
      generation: () => gitOk('rev-parse', 'HEAD') ?? 'no-head',
      save(paths, meta) {
        const list = [...paths]
        for (let i = 0; i < list.length; i += 500) git('add', '-A', '--', ...list.slice(i, i + 500))
        if (gitOk('status', '--porcelain') === '') return { saved: false }
        const idc = gitOk('config', 'user.name') && gitOk('config', 'user.email') ? [] : ['-c', 'user.name=c3', '-c', 'user.email=c3@localhost']
        git(...idc, 'commit', '-m', meta.message)
        // last writer wins: integrate the remote with conflicts resolved to OUR
        // tree, then push. Never uses rebase, never leaves a half-applied merge.
        try { git('push'); return { saved: true, pushed: true } } catch {}
        try {
          gitOk('fetch')
          git('merge', '-X', 'ours', '--no-edit', '@{u}')
        } catch {
          try { gitOk('merge', '--abort') } catch {}
          if (config.forcePush !== false) {
            try { git('push', '--force'); return { saved: true, pushed: true, forced: true } } catch {}
          }
          return { saved: true, pushed: false }
        }
        try { git('push'); return { saved: true, pushed: true } } catch { return { saved: true, pushed: false } }
      }
    }
  }
  if (config.backend === 'folder') {
    const archive = path.resolve(workDir, config.archive)
    if (archive === workDir) die('Archive path cannot be the working directory itself.')
    const lock = path.join(archive, '.c3-lock')
    const insideWork = archive.startsWith(workDir + path.sep)
    const relArchive = insideWork ? path.relative(workDir, archive).split(path.sep).join('/') : null
    return {
      kind: 'folder',
      excluded: relArchive,
      prepare() { mkdirp(path.join(archive, 'snapshots')) },
      generation() { try { return fs.readFileSync(path.join(archive, 'gen'), 'utf8').trim() } catch { return '0' } },
      save(paths, meta) {
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
          const list = walkTree()
          for (const rel of list) {
            mkdirp(path.dirname(path.join(snap, rel)))
            fs.copyFileSync(path.join(workDir, rel), path.join(snap, rel))
          }
          atomicWrite(path.join(archive, 'gen'), String(Number(this.generation()) + 1))
          fs.appendFileSync(path.join(archive, '.c3-session-log'), `${ts}  ${meta.user}  ${list.length}f  ${paths.size}c\n`)
          return { saved: true, pushed: true, snapshot: snap }
        } finally { fs.rmSync(lock, { force: true }) }
      }
    }
  }
  if (config.backend === 'none') {
    return { kind: 'none', excluded: null, prepare() {}, generation: () => 'static', save: () => ({ saved: false, exported: false }) }
  }
  die('Unknown backend: ' + config.backend)
}

// ---------- invites ----------
function parseInvite(s) {
  const m = String(s || '').trim().match(/^c3:\/\/join\/([A-Za-z0-9_-]+)$/)
  if (!m) return null
  try {
    const j = JSON.parse(Buffer.from(m[1], 'base64url').toString('utf8'))
    if (j.v !== 5 || typeof j.t !== 'string' || j.t.length < 16 || !Array.isArray(j.a)) return null
    return { t: j.t, a: j.a.filter(x => typeof x === 'string').slice(0, 12) }
  } catch { return null }
}
const inviteUrl = (token, addrs) =>
  'c3://join/' + Buffer.from(JSON.stringify({ v: 5, t: token, a: addrs })).toString('base64url')

// ---------- connect ----------
async function connect(invite) {
  const cfg0 = readConfig() ?? {}
  mkdirp(SESSION_DIR)
  const ident = await loadKey(path.join(SESSION_DIR, 'identity.key'))
  let name = null, sKey = null, sdir = null, cfg = cfg0

  const wantPort = Number(flag('port') ?? (invite ? 0 : cfg0.port ?? DEFAULT_PORT))
  if (wantPort !== 0 && (!Number.isInteger(wantPort) || wantPort < 1 || wantPort > 65535)) die('Bad --port.')
  const wantWs = Number(flag('ws') ?? cfg0.wsPort ?? 0)
  if (wantWs && (!Number.isInteger(wantWs) || wantWs < 1 || wantWs > 65535)) die('Bad --ws port.')
  const advertise = String(flag('advertise') ?? cfg0.advertise ?? '').trim()
  if (advertise && !toMa(advertise, 'x')) die('--advertise must be host:port.')
  const wantUdp = !has('no-udp') && cfg0.udp !== false

  const n = await makeNode(ident, wantPort, { wsPort: wantWs, udp: wantUdp })
  const port = n.port || wantPort
  const me = {
    name: gitOk('config', 'user.name') ?? (os.userInfo().username || 'peer'),
    email: gitOk('config', 'user.email') ?? ''
  }
  const peers = new Set()
  let leaving = false
  let peerTimer = null, snapTimer = null, scanTimer = null, tick = null, dialTimer = null, addrsTimer = null
  let started = false
  let watcher = null
  const askedPeers = flagVals('peer').length > 0
  const peerCount = () => new Set(n.getConnections().map(c => c.remotePeer.toString())).size
  const addPeer = a => {
    if (!sdir) return
    if (typeof a !== 'string' || a.length > 500 || !/\/p2p\//.test(a)) return
    if (a.includes(`/p2p/${n.peerId}`)) return
    if (peers.has(a) || peers.size >= 64) return
    peers.add(a)
    clearTimeout(peerTimer)
    peerTimer = setTimeout(() => {
      try { atomicWrite(peersFile(sdir), JSON.stringify([...peers].slice(0, 64))); chmod(peersFile(sdir), 0o600) } catch {}
    }, 1000)
  }
  const dialPeers = () => {
    if (leaving) return
    // pick up addresses added by `node c3.js peer ...` while running
    for (const a of readPeers(sdir)) addPeer(a)
    const live = new Set(n.getConnections().map(c => c.remotePeer.toString()))
    let count = 0
    for (const a of peers) {
      if (count >= 8) break
      const m = a.match(/\/p2p\/([^/]+)$/)
      if (!m || live.has(m[1])) continue
      try { n.dial(a).catch(() => {}) } catch {}
      count++
    }
  }
  const waitFor = async (ms, cond) => {
    const until = Date.now() + ms
    while (Date.now() < until) { if (cond()) return true; await sleep(200) }
    return cond()
  }

  if (invite) {
    const res = await joinCall(n, invite)
    if (!res?.ok || typeof res.name !== 'string' || typeof res.key !== 'string') {
      await n.stop().catch(() => {})
      die('Could not join: no peer accepted the invite.')
    }
    name = res.name
    sKey = res.key
    sdir = sdirOf(name)
    writeKey(sdir, sKey)
    atomicWrite(path.join(sdir, 'name'), JSON.stringify({ name }))
    cfg = { ...cfg0, name, port }
    if (wantWs) cfg.wsPort = wantWs
    if (!cfg.backend) cfg.backend = fs.existsSync(path.join(workDir, '.git')) ? 'git' : 'none'
    if (advertise) cfg.advertise = advertise
    atomicWrite(CONFIG_FILE, JSON.stringify(cfg, null, 2))
    chmod(CONFIG_FILE, 0o600)
    for (const a of invite.a) addPeer(a)
    ui.say(`joined session "${name}"`)
  } else {
    name = flag('name') ?? cfg0.name ?? die('No session name. Run `c3 config`.')
    sdir = sdirOf(name)
    sKey = flag('key') ?? process.env.C3_KEY ?? readKey(sdir)
    if (!sKey) die(`No session key. Run \`c3 config\`, or join with an invite:\n  node c3.js join "c3://join/..."`)
    if (flag('key')) writeKey(sdir, sKey)
    cfg = { ...cfg0, name, port }
    if (wantWs) cfg.wsPort = wantWs
    if (!cfg.backend) cfg.backend = fs.existsSync(path.join(workDir, '.git')) ? 'git' : 'none'
    if (advertise) cfg.advertise = advertise
    atomicWrite(path.join(sdir, 'name'), JSON.stringify({ name }))
    for (const a of readPeers(sdir)) addPeer(a)
    for (const a of (cfg.peers ?? [])) addPeer(a)
    for (const a of flagVals('peer')) addPeer(a)
  }
  if (sKey.length < 20) ui.warn('key looks low-entropy -- prefer a generated one.')

  loadIgnoreRules()
  backend = makeBackend(cfg)
  backend.prepare()

  // ---------- persistence ----------
  const stateFile = path.join(sdir, 'state.bin')
  const genFile = path.join(sdir, 'state.gen')
  const logFile = path.join(sdir, 'oplog')
  function appendLog(update) {
    try {
      const h = Buffer.allocUnsafe(4)
      h.writeUInt32BE(update.length, 0)
      fs.appendFileSync(logFile, Buffer.concat([h, Buffer.from(update)]))
    } catch {}
  }
  function snapshotNow() {
    try {
      atomicWrite(stateFile, Y.encodeStateAsUpdate(doc))
      atomicWrite(genFile, backend.generation())
      fs.rmSync(logFile, { force: true })
    } catch {}
  }
  function scheduleSnapshot() { clearTimeout(snapTimer); snapTimer = setTimeout(snapshotNow, 5000) }
  function removeState() { for (const f of [stateFile, genFile, logFile]) { try { fs.rmSync(f, { force: true }) } catch {} } }
  function restoreState() {
    if (!fs.existsSync(stateFile)) return false
    try {
      const genThen = fs.existsSync(genFile) ? fs.readFileSync(genFile, 'utf8').trim() : null
      if (genThen && genThen !== backend.generation()) {
        ui.say('Saved session state predates latest archive -- discarding.')
        removeState()
        return false
      }
      Y.applyUpdate(doc, fs.readFileSync(stateFile), 'restore')
      if (fs.existsSync(logFile)) {
        const b = fs.readFileSync(logFile)
        let off = 0
        while (off + 4 <= b.length) {
          const len = b.readUInt32BE(off)
          off += 4
          if (len < 1 || len > MAX_FRAME || off + len > b.length) break
          try { Y.applyUpdate(doc, b.subarray(off, off + len), 'restore') } catch {}
          off += len
        }
      }
      for (const rel of files.keys()) touched.add(rel)
      ui.say('Restored unsaved state from last run.')
      return true
    } catch { removeState(); return false }
  }
  const restored = restoreState()

  // ---------- join responder + encrypted sync ----------
  joinResponder(n, () => readInvites(sdir), (entry, nonce, replay) => {
    const list = readInvites(sdir)
    const inv = list.find(x => x.tpc === entry.tpc)
    if (!inv) return null
    if (!replay) {
      if (!(inv.exp > Date.now()) || (inv.used ?? 0) >= (inv.uses ?? 1)) return null
      inv.used = (inv.used ?? 0) + 1
      writeInvites(sdir, list)
      ui.say('invite token used.')
    }
    return { name, key: sKey }
  })
  sync(n, name, sKey, doc, advertise, addrs => {
    for (const a of addrs) addPeer(a)
    dialPeers()
  })

  doc.on('update', (update, origin) => {
    if (origin === 'restore') return
    appendLog(update)
    scheduleSnapshot()
  })

  // ---------- disk watcher ----------
  let lastGitignore = 0
  function scan() {
    try {
      let m = 0
      try { m = fs.statSync(path.join(workDir, '.gitignore')).mtimeMs } catch {}
      if (m !== lastGitignore) { lastGitignore = m; ignoredCache.clear() }
      const list = walkTree()
      const present = new Set(list)
      const now = Date.now()
      for (const rel of list) {
        if (pendingWrites.has(rel)) continue
        if ((lastWritten.get(rel) ?? 0) > now - 500) continue
        let st
        try { st = fs.statSync(path.join(workDir, rel)) } catch { continue }
        const sig = st.mtimeMs + ':' + st.size
        if (diskMeta.get(rel) === sig) continue
        diskMeta.set(rel, sig)
        syncFromDisk(rel)
      }
      for (const rel of [...files.keys()]) {
        if (present.has(rel) || pendingWrites.has(rel)) continue
        if ((lastWritten.get(rel) ?? 0) > now - 500) continue
        removeFromDoc(rel)
      }
    } catch {}
  }
  function quick(rel) {
    if (!rel) return
    const now = Date.now()
    if (pendingWrites.has(rel)) return
    if ((lastWritten.get(rel) ?? 0) > now - 300) return
    let st
    try { st = fs.statSync(path.join(workDir, rel)) } catch {
      if (files.has(rel)) removeFromDoc(rel)
      return
    }
    if (!st.isFile()) return
    const sig = st.mtimeMs + ':' + st.size
    if (diskMeta.get(rel) === sig) return
    diskMeta.set(rel, sig)
    syncFromDisk(rel)
  }
  function startScan() {
    if (started) return
    started = true
    scan()
    try {
      watcher = fs.watch(workDir, { recursive: true }, (_evt, file) => {
        if (!file) return
        const rel = String(file).split(path.sep).join('/')
        if (!rel) return
        if (rel === '.git' || rel.startsWith('.git/')) return
        if (rel === '.c3' || rel.startsWith('.c3/')) return
        if (c3InsideWork && (rel === c3Rel || rel.startsWith(c3Rel + '/'))) return
        quick(rel)
      })
      watcher.on('error', () => {})
    } catch {
      ui.warn('instant file watching unavailable -- using polling (slower)')
    }
    scanTimer = setInterval(scan, SCAN_MS)
  }
  function seedFromDisk() {
    const seed = walkTree()
    let bytes = 0
    for (const rel of seed) { try { bytes += fs.statSync(path.join(workDir, rel)).size } catch {} }
    if (!cfg.forceSeed && (seed.length > SEED_FILES || bytes > SEED_BYTES))
      die(`Refusing to seed ${seed.length} files / ${(bytes / 1e6).toFixed(0)} MB. Trim c3/.c3/ignore, or set "forceSeed": true in config.`)
    ui.say(`Seeding ${seed.length} files into the session.`)
    doc.transact(() => { for (const rel of seed) syncFromDisk(rel, true) }, 'disk')
    startScan()
  }

  // ---------- leave ----------
  async function confirmSave() {
    if (has('yes')) return true
    if (!process.stdin.isTTY) return false
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
    const a = (await rl.question(`Publish ${touched.size} changed path(s) to archive? [y/N] `)).trim().toLowerCase()
    rl.close()
    return a === 'y' || a === 'yes'
  }
  async function leave() {
    if (leaving) return
    leaving = true
    clearInterval(scanTimer); clearTimeout(snapTimer); clearTimeout(peerTimer); clearInterval(tick); clearInterval(dialTimer); clearInterval(addrsTimer)
    try { watcher?.close() } catch {}
    flushWrites()
    snapshotNow()
    ui.clear()
    try {
      const others = peerCount()
      if (others > 0) {
        ui.say(`Others still in session (${others}) -- keeping local state, not saving.`)
      } else if (touched.size === 0) {
        ui.say('Nothing changed -- nothing to save.')
        removeState()
      } else if (!(await confirmSave())) {
        ui.say('Skipped publishing. Reconnect to retry, or `c3 export <dir>`.')
      } else {
        const r = backend.save(touched, { user: me.name, message: `Session snapshot ${new Date().toISOString()}` })
        if (r.blocked) ui.warn(r.blocked)
        else if (backend.kind === 'none') ui.say('No archive -- run `c3 export <dir>` to keep a copy.')
        else if (r.pushed === false) ui.warn('Could not publish -- commit kept locally.')
        else if (r.saved === false) { ui.say('Nothing changed -- nothing to save.'); removeState() }
        else { removeState(); ui.say(r.forced ? 'Saved and pushed (remote overwritten).' : r.snapshot ? `Snapshot written: ${r.snapshot}` : 'Saved and pushed.') }
      }
    } catch (err) {
      console.error('Save failed -- state kept locally:', err.message)
    } finally {
      try { await n.stop() } catch {}
      process.exit(0)
    }
  }

  // ---------- boot ----------
  n.addEventListener('peer:connect', evt => {
    const id = evt?.detail?.toString?.() ?? 'peer'
    ui.say(`peer ${id.slice(0, 8)} connected`)
    dialPeers()
  })
  n.addEventListener('peer:disconnect', () => ui.set(`live - ${peerCount()} peer(s)`))

  const addrsFile = path.join(sdir, 'addrs.json')
  const writeAddrs = () => {
    try {
      atomicWrite(addrsFile, JSON.stringify({ id: n.peerId.toString(), addrs: addrsOf(n, advertise), port, wsPort: n.wsPort || 0, udpPort: n.udpPort || 0 }))
      chmod(addrsFile, 0o600)
    } catch {}
  }
  addrsTimer = setInterval(writeAddrs, 5000)
  writeAddrs()

  dialPeers()
  dialTimer = setInterval(dialPeers, 10000)
  ui.set('looking for peers...')
  await sleep(PEER_WAIT_MS)
  if ((invite || askedPeers || peerCount() > 0) && files.size === 0)
    await waitFor(STATE_WAIT_MS, () => files.size > 0)

  if (restored && files.size > 0) {
    ui.say('Ready from local state.')
    reconcile()
    startScan()
  } else if (files.size > 0) {
    ui.say(`Joined session with ${peerCount()} peer(s).`)
    reconcile()
    startScan()
  } else if ((invite || askedPeers || peerCount() > 0) && !has('seed')) {
    ui.say('No state from any peer yet -- keeping this directory as-is.')
    ui.say('If this really is a new session, pass --seed to publish it.')
    startScan()
  } else {
    seedFromDisk()
  }

  tick = setInterval(() => {
    const p = peerCount()
    const tags = [backend.kind]
    if (advertise) tags.push('advertised')
    if (n.wsPort) tags.push('ws')
    if (n.udpPort) tags.push('punch')
    ui.set(`live - ${p} peer${p === 1 ? '' : 's'} - ${files.size} files - ${tags.join(' - ')}`)
  }, 2000)
  ui.say('Ready. Ctrl+C to leave.')
  const bye = () => { clearInterval(tick); clearInterval(dialTimer); clearInterval(addrsTimer); leave() }
  process.on('SIGINT', bye)
  process.on('SIGTERM', bye)
}

// ---------- config ----------
async function configCmd() {
  const isGit = fs.existsSync(path.join(workDir, '.git'))
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  const ask = async (q, def) => {
    if (!process.stdin.isTTY) return def
    const a = (await rl.question(`${C.cyn}?${C.r} ${q}${def ? ` [${C.yel}${def}${C.r}]` : ':'} `)).trim()
    return a || def
  }
  ui.clear()
  console.log(`c3 config -- ${workDir}`)
  let raw = flag('archive')
  let kind, archivePath
  if (raw?.startsWith('folder:')) { kind = 'folder'; archivePath = raw.slice(7) }
  else if (['git', 'folder', 'none'].includes(raw)) kind = raw
  if (!kind) {
    const choice = await ask(`Backend archive
  1) git    - this project IS a git repo (snapshots become commits)
  2) folder - external path / NAS / server (dated snapshots)
  3) none   - no auto-archive (use export)
  Pick 1/2/3`, isGit ? '1' : '2')
    kind = { '1': 'git', '2': 'folder', '3': 'none' }[choice] || choice
  }
  if (!['git', 'folder', 'none'].includes(kind)) die('Backend must be git, folder:<path>, or none.')
  if (kind === 'git' && !isGit) die('No .git here -- git backend needs a repo.')
  if (kind === 'folder') {
    archivePath ??= await ask('Archive folder path (absolute or relative, e.g. /mnt/nas/c3-archive)', 'archive')
    archivePath = path.resolve(workDir, archivePath)
    if (archivePath === workDir) die('Archive path cannot be the working directory itself.')
  }
  const name = flag('name') ?? await ask('Session name (for invites)', path.basename(workDir))
  if (!name) die('Session name is required.')
  const sdir = sdirOf(name)
  const existing = readKey(sdir)
  let key = flag('key')
  if (!key) {
    const c = (await ask(`Session key: new / paste${existing ? ' / keep' : ''}`, 'new')).toLowerCase()
    if (c === 'keep' && existing) key = existing
    else if (c === 'paste') key = (await rl.question('Paste key: ')).trim()
    else key = crypto.randomBytes(32).toString('base64url')
  }
  if (!key) die('No key provided.')
  if (key.length < 20) ui.warn('low-entropy key -- prefer a generated one.')
  writeKey(sdir, key)
  const port = Number(flag('port') ?? await ask('Listening TCP/UDP port', String(DEFAULT_PORT)))
  if (!Number.isInteger(port) || port < 1 || port > 65535) die('Bad port.')
  const wsAns = String(flag('ws') ?? await ask('WebSocket port (blank = off, needs "npm i ws")', '')).trim()
  const wsPort = wsAns ? Number(wsAns) : 0
  if (wsPort && (!Number.isInteger(wsPort) || wsPort < 1 || wsPort > 65535)) die('Bad WebSocket port.')
  const advertise = String(flag('advertise') ?? await ask('Reachable host:port (blank = LAN/invite only)', '')).trim()
  if (advertise && !toMa(advertise, 'x')) die('Advertise must be host:port.')
  const cfg = { backend: kind, name, port }
  if (archivePath) cfg.archive = archivePath
  if (advertise) cfg.advertise = advertise
  if (wsPort) cfg.wsPort = wsPort
  atomicWrite(CONFIG_FILE, JSON.stringify(cfg, null, 2))
  chmod(CONFIG_FILE, 0o600)
  atomicWrite(path.join(sdir, 'name'), JSON.stringify({ name }))
  if (kind === 'git') {
    const ex = path.join(workDir, '.git', 'info', 'exclude')
    mkdirp(path.dirname(ex))
    const cur = fs.existsSync(ex) ? fs.readFileSync(ex, 'utf8') : ''
    if (!cur.split('\n').includes(c3Name + '/')) fs.appendFileSync(ex, '\n' + c3Name + '/\n')
  }
  rl.close()
  ui.clear()
  console.log(`Config written: ${CONFIG_FILE}`)
  console.log('Key and state stay inside the c3 folder (not pushed).')
  console.log('')
  console.log('Start the session on one machine:')
  console.log('  node c3.js connect')
  console.log('')
  console.log('Then swap addresses once (no firewall rules, no invites):')
  console.log('  node c3.js share                 -> paste to the other peer')
  console.log('  node c3.js peer "<their peer:>"  -> paste their line here')
  console.log('')
  console.log('Every later session is just `node c3.js connect` on both sides.')
  if (wsPort) console.log('WebSocket path is available at /c3 on port ' + wsPort + '.')
}

// ---------- invite ----------
function inviteCmd() {
  const cfg = readConfig() ?? die('No config. Run `c3 config`.')
  const name = flag('name') ?? cfg.name ?? die('No session name.')
  const sdir = sdirOf(name)
  if (!readKey(sdir)) die('No session key. Run `c3 config`.')
  let addrs = []
  try { addrs = JSON.parse(fs.readFileSync(path.join(sdir, 'addrs.json'), 'utf8')).addrs ?? [] } catch {}
  addrs = addrs.filter(a => typeof a === 'string' && /\/p2p\//.test(a)).slice(0, 12)
  if (!addrs.length) {
    const id = readIdentity()?.id
    if (!id) die('No running endpoint. Start `node c3.js connect` first.')
    addrs = lanAddrs(id, Number(cfg.port ?? DEFAULT_PORT), cfg.wsPort || 0).slice(0, 6)
  }
  if (!addrs.length) die('No endpoint known. Start `node c3.js connect` first (or set "advertise").')
  const ttl = Number(flag('ttl') ?? 24) * 3600000
  const uses = Number(flag('uses') ?? 1)
  const token = crypto.randomBytes(24).toString('base64url')
  const list = readInvites(sdir)
  list.push({ tpc: tokenTopic(token), sk: tokenKey(token).toString('base64'), exp: Date.now() + ttl, uses, used: 0 })
  writeInvites(sdir, list)
  const url = inviteUrl(token, addrs)
  ui.clear()
  console.log(`Invite for "${name}" (${uses} use${uses === 1 ? '' : 's'}, expires in ${Math.round(ttl / 3600000)}h):`)
  console.log('')
  console.log('  ' + url)
  console.log('')
  console.log('Peer runs (double quotes, works in cmd and PowerShell):')
  console.log(`  node c3.js join "${url}"`)
  console.log('')
  if (addrs.some(a => a.includes('/ws'))) console.log('Includes a WebSocket endpoint (needs "npm i ws" on the joining peer).')
  console.log('The token burns on use. The session key travels only inside the encrypted channel.')
}

// ---------- share / peer ----------
function shareCmd() {
  const cfg = readConfig() ?? die('No config. Run `c3 config`.')
  const sdir = sdirOf(cfg.name)
  const key = readKey(sdir) ?? die('No session key. Run `c3 config`.')
  let addrs = []
  try { addrs = JSON.parse(fs.readFileSync(path.join(sdir, 'addrs.json'), 'utf8')).addrs ?? [] } catch {}
  if (!addrs.length) {
    const id = readIdentity()?.id ?? die('Run `node c3.js connect` once so this peer has an identity.')
    addrs = lanAddrs(id, Number(cfg.port ?? DEFAULT_PORT), cfg.wsPort || 0)
  }
  addrs = addrs.filter(a => typeof a === 'string' && /\/p2p\//.test(a) && !a.includes('/ip4/127.0.0.1/')).slice(0, 4)
  if (!addrs.length) die('No LAN address found. Start `node c3.js connect` and try again.')
  ui.clear()
  console.log(`Share for "${cfg.name}" -- paste this whole block to the other peer:`)
  console.log('')
  console.log(`  name: ${cfg.name}`)
  console.log(`  key:  ${key}`)
  addrs.forEach(a => console.log(`  peer: ${a}`))
  console.log('')
  console.log('They join with:')
  console.log(`  node c3.js connect --name="${cfg.name}" --key="${key}" --peer="${addrs[0]}"`)
  console.log('')
  console.log('Then they run `node c3.js share` and you paste their "peer:" line into:')
  console.log('  node c3.js peer "<their peer:>"')
  console.log('')
  console.log('No firewall rules needed: TCP fails, UDP punching takes over.')
}

function peerCmd() {
  const cfg = readConfig() ?? die('No config. Run `c3 config`.')
  const sdir = sdirOf(cfg.name)
  const ma = String(argv[1] || '').trim()
  if (!/^\/(ip4|ip6|dns)\/.+\/p2p\/[^/]+$/.test(ma)) {
    die('usage: node c3.js peer "/ip4/10.49.96.41/tcp/8443/p2p/<peerid>"')
  }
  const list = readPeers(sdir)
  if (!list.includes(ma)) list.push(ma)
  atomicWrite(peersFile(sdir), JSON.stringify(list.slice(0, 64), null, 2))
  chmod(peersFile(sdir), 0o600)
  ui.say(`peer added: ${ma}`)
  ui.say('A running `connect` picks it up within ~10s; TCP fails, UDP punching takes over.')
}

// ---------- export ----------
function exportCmd() {
  const cfg = readConfig() ?? die('No config. Run `c3 config`.')
  backend = makeBackend(cfg)
  const arg = argv.slice(1).find(a => !a.startsWith('--'))
  const dest = path.resolve(arg ?? ('c3-export-' + new Date().toISOString().replace(/[:.]/g, '-')))
  let n = 0
  for (const rel of walkTree()) {
    mkdirp(path.dirname(path.join(dest, rel)))
    fs.copyFileSync(path.join(workDir, rel), path.join(dest, rel))
    n++
  }
  ui.say(`Exported ${n} files to ${dest}`)
}

// ---------- doctor ----------
async function doctor() {
  const cfg = readConfig()
  const lines = []
  let failed = false
  const ok = (n, c, hint) => {
    if (!c) failed = true
    lines.push(`${c ? C.grn + '+' + C.r : C.red + '-' + C.r} ${n}${c ? '' : ' -- ' + hint}`)
  }
  const tcpFree = p => new Promise(res => {
    const s = net.createServer()
    s.once('error', () => res(false))
    s.listen(p, () => s.close(() => res(true)))
  })
  const udpFree = p => new Promise(res => {
    const s = dgram.createSocket('udp4')
    s.once('error', () => res(false))
    s.bind(p, () => s.close(() => res(true)))
  })
  ok('Node 22+', Number(process.version.slice(1).split('.')[0]) >= 22, 'upgrade Node')
  ok('project config', !!cfg, 'run `c3 config`')
  ok('identity key', !!readIdentity(), 'run `connect` once')
  let isIgnored = false
  try { execFileSync('git', ['check-ignore', '-q', c3Name + '/'], { cwd: workDir, stdio: 'ignore' }); isIgnored = true } catch {}
  ok('c3 ignored by git', isIgnored, `add "${c3Name}/" to .gitignore`)
  let wsInstalled = false
  try { await import('ws'); wsInstalled = true } catch {}
  if (wsInstalled) lines.push(`${C.grn}+${C.r} ws package`)
  else lines.push(`${C.cyn}i${C.r} ws package not installed (optional, npm i ws)`)
  if (cfg) {
    try {
      const sdir = sdirOf(cfg.name)
      ok('session name present', !!cfg.name, 'run `c3 config`')
      ok('session key present', !!readKey(sdir), 'run `c3 config`')
      const port = Number(cfg.port ?? DEFAULT_PORT)
      ok(`tcp port ${port} bindable`, await tcpFree(port), 'running connect may already hold it')
      ok(`udp port ${port} bindable`, await udpFree(port), 'something else holds UDP; punching disabled')
      if (cfg.wsPort) ok(`ws port ${cfg.wsPort} bindable`, await tcpFree(cfg.wsPort), 'running connect may already hold it')
      let addrs = []
      try { addrs = JSON.parse(fs.readFileSync(path.join(sdir, 'addrs.json'), 'utf8')).addrs ?? [] } catch {}
      ok('running endpoint known', addrs.length > 0, 'run `connect`, then `invite`')
      ok('cached peers', readPeers(sdir).length > 0, 'run `share`/`peer` once, then peers are cached')
    } catch (e) { ok('config valid', false, e.message) }
  }
  lines.push(`${C.cyn}i${C.r} discovery: pasted peers + cached multiaddrs (no DHT)`)
  lines.push(`${C.cyn}i${C.r} transports: tcp${cfg?.wsPort ? ' + websocket' : ''} + udp punching`)
  ui.clear()
  console.log(lines.join('\n'))
  console.log(failed ? 'Some checks failed.' : 'All good.')
}

// ---------- dispatch ----------
const usage = `usage: node c3.js <command> [flags]
Commands:
  config    interactive wizard (once per project)
  connect   join/start live session
  share     print name + key + this peer's addresses (paste once)
  peer <ma> add a peer multiaddr (no restart needed)
  invite    mint a single-use invite link
  join <u>  join from an invite link
  export    copy tree to directory (save for backend "none")
  doctor    diagnose config, key, ports, reachability
Flags:
  --name <n>        session name
  --key <k>         session key
  --peer <ma>       peer multiaddr (repeatable)
  --port <n>        listening TCP+UDP port (default 8443)
  --ws <port>       also listen for WebSocket peers (needs: npm i ws)
  --advertise <h:p> reachable endpoint shared with session peers
  --no-udp          disable UDP hole punching
  --seed            publish this directory into an empty session
  --ttl <hours>     invite lifetime (default 24)
  --uses <n>        invite use count (default 1)
  --yes             auto-confirm publish
  --archive <type>  set backend (git | folder:<path> | none)
How it works:
  No host, no DHT, no central service. Every peer is a full replica,
  listener, dialer, and gossip relay. First contact needs one pasted
  address per pair (share/peer or an invite); after that peers reconnect
  and punch UDP through default-deny firewalls like ufw. Payloads use
  AES-256-GCM with the session key. Same session name + key = same room.
  On Windows cmd use double quotes: node c3.js join "c3://join/..."
Config options (c3/.c3/config.json):
  "verify": "npm test"      run before publishing
  "forcePush": false        disable last-writer force push fallback
  "wsPort": 9443            default WebSocket port
  "udp": false              disable UDP hole punching
  "advertise": "host:port"  reachable endpoint to share
`
loadIgnoreRules()
if (cmd === 'config') await configCmd()
else if (cmd === 'connect') await connect(null)
else if (cmd === 'share') shareCmd()
else if (cmd === 'peer') peerCmd()
else if (cmd === 'invite') inviteCmd()
else if (cmd === 'join') {
  const inv = parseInvite(argv[1])
  if (!inv) die('Bad invite. Expected: c3://join/...')
  await connect(inv)
}
else if (cmd === 'export') exportCmd()
else if (cmd === 'doctor') await doctor()
else die(usage)