// CIII (c3) -- P2P live session (git | folder | none).
// Clone this folder into your project, add "c3/" to .gitignore, then:
//   npm install
//   node c3.js config
//   node c3.js connect
// Node 22+.

process.on('warning', w => {
  if (w.name === 'ExperimentalWarning' && w.message.includes('localStorage')) return
  console.warn(w)
})

import * as Y from 'yjs'
import chokidar from 'chokidar'
import ignore from 'ignore'
import { execFileSync, spawnSync } from 'node:child_process'
import readline from 'node:readline/promises'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import os from 'node:os'
import crypto from 'node:crypto'
import dgram from 'node:dgram'
import { createServer } from 'node:http'
import { WebSocketServer, WebSocket } from 'ws'

const argv = process.argv.slice(2)
const cmd = argv[0]
const flag = n => { const i = argv.indexOf('--' + n); return (i >= 0 && argv[i + 1]) ? argv[i + 1] : undefined }
const flags = n => {
  const out = []
  for (let i = 0; i < argv.length - 1; i++) if (argv[i] === '--' + n && argv[i + 1]) out.push(argv[i + 1])
  return out
}
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
const SEED_FILES = 10_000
const SEED_BYTES = 200 << 20
const LAN_DISCOVER_PORT = 42424
const LAN_MCAST = '239.255.42.42'
const LAN_DISCOVER_MS = 3000

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
const isGitIgnored = rel => { try { git('check-ignore', '-q', rel); return true } catch { return false } }

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
  return rel => !ig.ignores(rel)
}
function walkTree(isShareable) {
  const out = []
  const walk = (abs, rel) => {
    for (const e of fs.readdirSync(abs, { withFileTypes: true })) {
      if (e.name === '.git') continue
      if (c3InsideWork && e.name === c3Name) continue
      const r = rel ? rel + '/' + e.name : e.name
      if (e.isDirectory()) walk(path.join(abs, e.name), r)
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
    return {
      kind: 'folder',
      identity: () => readId() ?? die('folder backend needs .c3/id -- run c3 config or pass --name'),
      prepare() {
        mkdirp(path.join(archive, 'snapshots'))
        if (archive === workDir) die('archive path cannot be the working dir itself; use backend "none" for that')
        if (insideWork) ui.say('archive folder is inside the working tree (excluded from sync).')
      },
      listShareable() { return walkTree(r => this.isShareable(r)) },
      isShareable(rel) {
        if (relArchive && (rel === relArchive || rel.startsWith(relArchive + '/'))) return false
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
          const list = walkTree(r => this.isShareable(r))
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
      identity: () => readId() ?? die('backend "none" has no identity channel -- pass --name or run c3 config'),
      prepare() {},
      listShareable() { return walkTree(rules) },
      isShareable: rules,
      generation: () => 'static',
      save() { return { saved: false, exported: false } },
    }
  }
  die('Unknown backend: ' + config.backend)
}

// ---------- Yjs state ----------
const doc = new Y.Doc()
const files = doc.getMap('files')
const texts = doc.getMap('texts')
const blobs = doc.getMap('blobs')
const touched = new Set()
let backend = null

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

function syncFromDisk(rel, seed = false) {
  const norm = safeRel(rel)
  if (!norm || !backend.isShareable(norm)) return
  let buf
  try { buf = fs.readFileSync(path.join(workDir, norm)) } catch { return }
  doc.transact(() => {
    const entry = files.get(norm)
    if (!entry) {
      const bin = buf.includes(0)
      const id = crypto.randomUUID()
      files.set(norm, { id, bin })
      if (bin) blobs.set(id, buf.toString('base64'))
      else texts.set(id, new Y.Text(buf.toString('utf8')))
      if (!seed) touched.add(norm)
    } else if (entry.bin) {
      const b64 = buf.toString('base64')
      if (blobs.get(entry.id) !== b64) { blobs.set(entry.id, b64); if (!seed) touched.add(norm) }
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
  const data = entry.bin ? Buffer.from(blobs.get(entry.id) ?? '', 'base64') : Buffer.from(texts.get(entry.id)?.toString() ?? '', 'utf8')
  if (data.length > MAX_FILE) { warnOnce('big-' + rel, 'blocked oversized file from peer:', rel); return }
  try {
    if (fs.existsSync(abs) && Buffer.compare(fs.readFileSync(abs), data) === 0) return
    mkdirp(path.dirname(abs))
    atomicWrite(abs, data)
    lastWritten.set(rel, Date.now())
  } catch (err) { warnOnce('write-' + rel, 'write failed:', rel, err.message) }
}

const pathOf = id => { for (const [p, e] of files) if (e.id === id) return p }
const remote = tx => tx.origin !== 'disk' && tx.origin !== 'restore'

files.observe(ev => {
  if (!remote(ev.transaction)) return
  for (const [rawRel, change] of ev.keys) {
    const rel = safeRel(rawRel)
    if (!rel) { warnOnce('unsafe-' + rawRel, 'blocked unsafe path from peer:', rawRel); continue }
    if (change.action === 'delete') { touched.add(rel); fs.rmSync(path.join(workDir, rel), { force: true }) }
    else { touched.add(rel); writeToDisk(rawRel) }
  }
})
const onContent = evs => {
  if (!remote(evs[0].transaction)) return
  for (const ev of evs) {
    const ids = ev.target === texts || ev.target === blobs ? [...ev.keys.keys()] : [ev.path[0]]
    for (const id of ids) { const p = pathOf(id); if (p) { touched.add(p); writeToDisk(p) } }
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

// ---------- network ----------
class Mesh {
  constructor(room, key, doc) {
    this.room = room
    this.doc = doc
    this.connections = new Set()
    this.awareness = new Map()
    this.relayUrls = new Set()
    this.activeRelays = new Map()
    this.myEndpoints = new Set()
    this.server = null
    this.http = null
    this.port = 0
    this.encKey = crypto.createHash('sha256').update(key + '\0c3-v1').digest()
    this.me = null
    this.meId = null
    this.publicRelayUrl = null
    this.upnpClient = null
  }

  encrypt(obj) {
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encKey, iv)
    const ct = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()])
    return JSON.stringify({ iv: iv.toString('base64'), ct: ct.toString('base64'), tag: cipher.getAuthTag().toString('base64') })
  }
  decrypt(str) {
    let m; try { m = JSON.parse(str) } catch { return null }
    if (!m.iv || !m.ct || !m.tag) return null
    try {
      const d = crypto.createDecipheriv('aes-256-gcm', this.encKey, Buffer.from(m.iv, 'base64'))
      d.setAuthTag(Buffer.from(m.tag, 'base64'))
      return Buffer.concat([d.update(Buffer.from(m.ct, 'base64')), d.final()]).toString('utf8')
    } catch { return null }
  }

  async start() {
    this.http = createServer()
    this.server = new WebSocketServer({ noServer: true })
    await new Promise(res => this.http.listen(0, '0.0.0.0', res))
    this.port = this.http.address().port
    this.http.on('upgrade', (req, sock, head) => {
      if (req.url === '/' + this.room) {
        this.server.handleUpgrade(req, sock, head, ws => this.server.emit('connection', ws, req))
      } else {
        sock.destroy()
      }
    })
    this.server.on('connection', ws => this.add(ws))
    this.myEndpoints.add(`ws://localhost:${this.port}/${this.room}`)
    const ips = Object.values(os.networkInterfaces()).flat().filter(i => i?.family === 'IPv4' && !i.internal).map(i => i.address)
    ips.forEach(ip => this.myEndpoints.add(`ws://${ip}:${this.port}/${this.room}`))
    return ips
  }

  broadcast(obj) {
    if (this.connections.size === 0) return
    let payload
    try { payload = this.encrypt(obj) } catch { return }
    for (const ws of this.connections) if (ws.readyState === WebSocket.OPEN) ws.send(payload)
  }

  add(ws, isRelay = false, relayUrl = null) {
    if (ws._c3Added) return
    ws._c3Added = true
    this.connections.add(ws)
    ws.on('message', data => {
      const plain = this.decrypt(data.toString())
      if (!plain) return
      let m; try { m = JSON.parse(plain) } catch { return }
      if (m.t === 'u' || m.t === 's') {
        try { Y.applyUpdate(this.doc, new Uint8Array(Buffer.from(m.d, 'base64')), 'remote') } catch {}
      } else if (m.t === 'h') {
        this.awareness.set(m.id, { name: m.name, email: m.email, ts: Date.now() })
      } else if (m.t === 'ra' && Array.isArray(m.urls)) {
        for (const u of m.urls) {
          if (this.relayUrls.has(u)) continue
          this.relayUrls.add(u)
          this.connectRelay(u)
        }
      }
    })
    ws.on('close', () => {
      this.connections.delete(ws)
      if (isRelay && relayUrl) this.activeRelays.delete(relayUrl)
    })
    ws.on('error', () => {})
    try {
      ws.send(this.encrypt({ t: 's', d: Buffer.from(Y.encodeStateAsUpdate(this.doc)).toString('base64') }))
      ws.send(this.encrypt({ t: 'h', id: this.meId, name: this.me.name, email: this.me.email }))
      if (this.publicRelayUrl) ws.send(this.encrypt({ t: 'ra', urls: [this.publicRelayUrl] }))
    } catch {}
  }

  connectRelay(baseUrl) {
    if (this.activeRelays.has(baseUrl)) return
    const url = baseUrl.replace(/\/$/, '') + '/' + this.room
    if (this.myEndpoints.has(url)) return
    const ws = new WebSocket(url)
    this.activeRelays.set(baseUrl, ws)
    ws.on('open', () => this.add(ws, true, baseUrl))
    ws.on('close', () => this.activeRelays.delete(baseUrl))
    ws.on('error', () => this.activeRelays.delete(baseUrl))
  }

  connectPeer(url) {
    if (this.myEndpoints.has(url)) {
      ui.warn('Cannot connect to self:', url)
      return
    }
    ui.say(`Connecting to peer: ${url}`)
    const ws = new WebSocket(url)
    ws.on('open', () => this.add(ws))
    ws.on('error', err => ui.warn('Peer connection failed:', url, err.message || ''))
    ws.on('close', () => {})
  }

  othersAlive() {
    let n = 0
    for (const [k] of this.awareness) if (k !== this.meId) n++
    return n
  }

  destroy() {
    if (this.server) this.server.clients.forEach(c => c.close())
    if (this.http) this.http.close()
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

  const room = 'c3-' + crypto.createHash('sha256').update(identity + '\0' + key).digest('hex').slice(0, 24)

  const me = {
    name: gitOk('config', 'user.name') ?? (os.userInfo().username || 'unknown'),
    email: gitOk('config', 'user.email') ?? `${os.userInfo().username}@${os.hostname()}`,
  }
  const meId = crypto.randomBytes(4).toString('hex')

  const mesh = new Mesh(room, key, doc)
  mesh.me = me
  mesh.meId = meId
  const myIps = await mesh.start()

  console.log('')
  const directPeers = flags('peer')
  if (directPeers.length === 0) {
    console.log('Share one of these URLs with peers on the same network:')
    for (const ip of myIps) {
      console.log(`  --peer ws://${ip}:${mesh.port}/${room}`)
    }
    if (myIps.length === 0) console.log('  (no local IP found -- rely on relays)')
  }
  console.log('')

  for (const peerUrl of flags('peer')) {
    mesh.connectPeer(peerUrl)
  }

  for (const u of [...(config.signaling || []), ...(process.env.C3_SIGNALING ? process.env.C3_SIGNALING.split(',') : [])]) {
    const trimmed = u.trim()
    if (trimmed) mesh.relayUrls.add(trimmed)
  }
  for (const u of flags('signal')) mesh.relayUrls.add(u)
  for (const url of mesh.relayUrls) mesh.connectRelay(url)
  const relayMaintainer = setInterval(() => {
    for (const url of mesh.relayUrls) if (!mesh.activeRelays.has(url)) mesh.connectRelay(url)
  }, 10000)

  let lanSock
  const wantLan = !flags('peer').length && !flags('signal').length && !config.signaling && !process.env.C3_SIGNALING
  if (wantLan && !process.env.C3_NO_LAN) {
    const nodeId = crypto.randomBytes(4).toString('hex')
    let gotPeer = false
    try {
      lanSock = dgram.createSocket({ type: 'udp4', reuseAddr: true })
      lanSock.on('error', err => {
        if (err.code === 'EACCES' || err.code === 'EPERM') warnOnce('lan-blocked', 'UDP blocked by firewall. Use --peer or --signal instead.')
      })
      lanSock.on('message', (msg, rinfo) => {
        let d; try { d = JSON.parse(msg) } catch { return }
        if (d._ !== 'c3' || d.v !== 1 || d.room !== room || d.n === nodeId) return
        const url = `ws://${rinfo.address}:${d.port}/${room}`
        if (mesh.myEndpoints.has(url)) return
        gotPeer = true
        mesh.connectPeer(url)
      })
      lanSock.bind(LAN_DISCOVER_PORT, () => {
        try { lanSock.setBroadcast(true) } catch {}
        try { lanSock.addMembership(LAN_MCAST) } catch {}
      })
      const advertise = () => {
        const payload = JSON.stringify({ _: 'c3', v: 1, room, port: mesh.port, n: nodeId })
        try { lanSock.send(payload, LAN_DISCOVER_PORT, '255.255.255.255', () => {}) } catch {}
        try { lanSock.send(payload, LAN_DISCOVER_PORT, LAN_MCAST, () => {}) } catch {}
      }
      advertise()
      const iv = setInterval(advertise, 2000)
      ui.set('looking for peers...')
      await sleep(LAN_DISCOVER_MS)
      clearInterval(iv)
      if (!gotPeer) ui.say('No LAN peers found via UDP. If on same WiFi, share your --peer URL above.')
    } catch (err) {
      warnOnce('lan-fail', 'LAN discovery failed. Use --peer or --signal.')
    }
  }

  doc.on('update', (update, origin) => {
    if (origin === 'remote' || origin === 'restore') return
    mesh.broadcast({ t: 'u', d: Buffer.from(update).toString('base64') })
  })

  const hb = setInterval(() => {
    mesh.broadcast({ t: 'h', id: meId, name: me.name, email: me.email })
    const now = Date.now()
    for (const [k, v] of mesh.awareness) if (now - v.ts > 5000) mesh.awareness.delete(k)  // was 15000
  }, 1500)  // was 5000

  backend.prepare()

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

  if (!restored) {
    if (mesh.othersAlive() === 0 && files.size === 0) {
      const seed = backend.listShareable()
      let bytes = 0
      for (const rel of seed) { try { bytes += fs.statSync(path.join(workDir, rel)).size } catch {} }
      if (!config.forceSeed && (seed.length > SEED_FILES || bytes > SEED_BYTES))
        die(`Refusing to seed ${seed.length} files / ${(bytes / 1e6).toFixed(0)} MB. Trim c3/.c3/ignore, or set "forceSeed": true in config.`)
      ui.say(`No peers -- hosting from this directory (${seed.length} files).`)
      for (const rel of seed) syncFromDisk(rel, true)
    } else {
      ui.say(mesh.othersAlive() ? `Joined session with ${mesh.othersAlive()} peer(s).` : 'No peers -- resuming local state.')
      reconcile()
    }
  }

  const relOf = p => path.relative(workDir, p).split(path.sep).join('/')
  const watcherIgnored = p => {
    const r = relOf(p)
    return r === '.git' || r.startsWith('.git/') || (c3InsideWork && (r === c3Rel || r.startsWith(c3Rel + '/')))
  }
  chokidar.watch(workDir, { ignoreInitial: true, ignored: watcherIgnored, awaitWriteFinish: { stabilityThreshold: 150 } })
    .on('add', p => syncFromDisk(relOf(p)))
    .on('change', p => {
      const r = relOf(p)
      const recent = lastWritten.get(r)
      if (recent && Date.now() - recent < 500) return
      syncFromDisk(r)
    })
    .on('unlink', p => { const r = relOf(p); if (backend.isShareable(r)) removeFromDoc(r) })

  const sessionMessage = () => {
    const trailers = Array.from(mesh.awareness.values()).filter(u => u.email && u.email !== me.email).map(u => `Co-authored-by: ${u.name} <${u.email}>`)
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
    clearInterval(relayMaintainer)
    ui.clear()
    try {
      if (mesh.othersAlive() > 0) {
        atomicWrite(stateFile, Y.encodeStateAsUpdate(doc))
        atomicWrite(genFile, backend.generation())
        ui.say(`Others still in session (${mesh.othersAlive()}) -- keeping local state, not saving.`)
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
      if (lanSock) try { lanSock.close() } catch {}
      mesh.destroy()
      process.exit(0)
    }
  }

  const tick = setInterval(() => {
    const n = mesh.othersAlive()
    ui.set(`live - ${n} peer${n === 1 ? '' : 's'} - ${files.size} files - ${backend.kind}`)
  }, 2000)

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
  ui.say(`${C.cyn}c3 config${C.r} -- ${workDir}`)

  let raw = flag('archive')
  let kind, archivePath
  if (raw?.startsWith('folder:')) { kind = 'folder'; archivePath = raw.slice(7) }
  else if (['git','folder','none'].includes(raw)) { kind = raw }

  if (!kind) {
    const choice = await ask(`Archive backend?
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

  const verify = (await ask('Verify command before publishing (blank = none, e.g. "npm test")', '')).trim()
  const sig = (await ask('Relay URLs for remote peers (blank for LAN-only)\n  e.g. wss://relay.example.com:4444', '')).trim()
  const config = { backend: kind, name }
  if (archivePath) config.archive = archivePath
  if (verify) config.verify = verify
  if (sig) config.signaling = sig.split(',').map(s => s.trim()).filter(Boolean)
  atomicWrite(CONFIG_FILE, JSON.stringify(config, null, 2))

  if (kind === 'git') {
    const ex = path.join(workDir, '.git', 'info', 'exclude')
    mkdirp(path.dirname(ex))
    const cur = fs.existsSync(ex) ? fs.readFileSync(ex, 'utf8') : ''
    const line = c3Name + '/'
    if (!cur.split('\n').includes(line)) fs.appendFileSync(ex, '\n' + line + '\n')
  }
  rl.close()

  ui.say(`\nConfig written: ${CONFIG_FILE}`)
  ui.say('Key and state are inside the c3 folder (not pushed).')
  ui.say(`\nInvite others (share out-of-band):`)
  console.log(`  c3 connect --name "${name}" --key ${key}`)
  ui.say('On the same Wi-Fi everyone can just run:  c3 connect')
  if (sig) ui.say('Remote peers use the relay(s) in config automatically.')
  if (IS_WIN) ui.say('Windows: LAN discovery limited. Use --peer for same-room sync, or run inside WSL2.')
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
  ui.clear()
  console.log(lines.join('\n'))
  console.log(failed ? 'Some checks failed.' : 'All good.')
}

// ---------- dispatch ----------
const usage = `usage: c3.js <command> [flags]

Commands:
  config    interactive wizard (once per project)
  connect   join/start live session
  export    copy tree to directory (save for backend "none")
  doctor    diagnose config, key, and signaling

Flags:
  --name <n>        session name
  --key <k>         session key
  --signal <url>    add a relay (repeatable; also stored via config)
  --peer <url>      connect directly to a peer URL (repeatable)
  --lan             force LAN discovery even with --signal
  --yes             auto-confirm publish
  --archive <type>  set backend (git | folder:<path> | none)
`

if (cmd === 'config') await configCmd()
else if (cmd === 'connect') await connect()
else if (cmd === 'export') exportCmd()
else if (cmd === 'doctor') await doctor()
else die(usage)