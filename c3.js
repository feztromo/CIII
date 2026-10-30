#!/usr/bin/env node
// c3 -- P2P live session, single file. Node 22+, `yjs` is the only dependency.
// Every peer listens, dials, and relays for the others (no host, no DHT).
// First contact: one `share` / `peer` exchange. Afterwards peers retry
// automatically and punch UDP through default-deny firewalls like ufw.
//   node c3.js config
//   node c3.js connect
//   node c3.js share
//   node c3.js peer "<their peer: line>"
import * as Y from 'yjs'
import readline from 'node:readline/promises'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import os from 'node:os'
import net from 'node:net'
import dgram from 'node:dgram'
import crypto from 'node:crypto'

// ---------- cli ----------
const argv = process.argv.slice(2)
const cmd = argv[0]
const flag = n => {
  const i = argv.indexOf('--' + n)
  if (i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--')) return argv[i + 1]
  const eq = argv.find(a => a.startsWith('--' + n + '='))
  return eq ? eq.slice(n.length + 3) : undefined
}
const has = n => argv.includes('--' + n)
const IS_WIN = process.platform === 'win32'
const C = IS_WIN
  ? { r: '', d: '', red: '', grn: '', yel: '', cyn: '' }
  : { r: '\x1b[0m', d: '\x1b[2m', red: '\x1b[31m', grn: '\x1b[32m', yel: '\x1b[33m', cyn: '\x1b[36m' }
const ui = {
  set(m) { if (process.stdout.isTTY) process.stdout.write('\r\x1b[K* c3 ' + m) },
  clear() { if (process.stdout.isTTY) process.stdout.write('\r\x1b[K') },
  say(...a) { this.clear(); console.log('* c3', ...a) },
  warn(...a) { this.clear(); console.error('! warning', ...a) }
}
const dbg = (...a) => { if (process.env.C3_DEBUG) console.error(...a) }
const die = m => { console.error(m); process.exit(1) }
const sleep = ms => new Promise(r => setTimeout(r, ms))
const mkdirp = d => fs.mkdirSync(d, { recursive: true })
const atomicWrite = (f, d) => {
  const t = f + '.tmp-' + process.pid + '-' + crypto.randomBytes(4).toString('hex')
  fs.writeFileSync(t, d); fs.renameSync(t, f)
}
const chmod = (f, m) => { try { fs.chmodSync(f, m) } catch {} }
const git = (...a) => execFileSync('git', a, { cwd: workDir, encoding: 'utf8', maxBuffer: 1 << 26 }).trim()
const gitOk = (...a) => { try { return git(...a) } catch { return null } }

// ---------- paths ----------
const c3Dir = path.dirname(fileURLToPath(import.meta.url))
const SESSION_DIR = path.join(c3Dir, '.c3')
const CONFIG_FILE = path.join(SESSION_DIR, 'config.json')
const workDir = path.resolve(c3Dir, '..')
const c3Rel = path.relative(workDir, c3Dir).split(path.sep).join('/')
const c3InsideWork = !c3Rel.startsWith('..') && !path.isAbsolute(c3Rel)
const c3Name = path.basename(c3Dir)
const DEFAULT_PORT = 8443
const MAX_FILE = 16 << 20
const MAX_FRAME = 32 << 20
const CHUNK = 64 << 10
const SEED_FILES = 10_000
const SEED_BYTES = 200 << 20
const WRITE_DEBOUNCE_MS = 40
const SCAN_MS = 8000
const PEER_WAIT_MS = 4000
const STATE_WAIT_MS = 10000
const readConfig = () => { try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) } catch { return null } }
const sidOf = n => crypto.createHash('sha256').update('c3sid\0' + n).digest()
const sdirOf = n => { const d = path.join(SESSION_DIR, 's', sidOf(n).toString('hex').slice(0, 32)); mkdirp(d); chmod(d, 0o700); return d }
const readKey = s => { try { return fs.readFileSync(path.join(s, 'key'), 'utf8').trim() } catch { return null } }
const writeKey = (s, k) => { atomicWrite(path.join(s, 'key'), k); chmod(path.join(s, 'key'), 0o600) }
const peersFile = s => path.join(s, 'peers.json')
const readPeers = s => { try { const a = JSON.parse(fs.readFileSync(peersFile(s), 'utf8')); return Array.isArray(a) ? a.filter(x => typeof x === 'string' && x.length < 500).slice(0, 64) : [] } catch { return [] } }
const writePeers = (s, a) => { atomicWrite(peersFile(s), JSON.stringify(a.slice(0, 64), null, 2)); chmod(peersFile(s), 0o600) }

// ---------- identity ----------
function loadIdentity() {
  mkdirp(SESSION_DIR)
  const f = path.join(SESSION_DIR, 'identity.json')
  try {
    const j = JSON.parse(fs.readFileSync(f, 'utf8'))
    if (/^[0-9a-f]{16}$/.test(j.id)) return j
  } catch {}
  const j = { id: crypto.randomBytes(8).toString('hex') }
  atomicWrite(f, JSON.stringify(j)); chmod(f, 0o600)
  return j
}

// ---------- addresses ----------
const toMa = (host, port, id) => {
  const b = host.includes(':') ? '/ip6/' + host : (/^\d+\.\d+\.\d+\.\d+$/.test(host) ? '/ip4/' + host : '/dns/' + host)
  return b + '/tcp/' + port + '/p2p/' + id
}
const parseMa = s => {
  const m = String(s || '').match(/^\/(ip4|ip6|dns)\/([^/]+)\/tcp\/(\d+)\/p2p\/([0-9a-f]{16})$/)
  return m ? { host: m[2], port: Number(m[3]), id: m[4] } : null
}
const usableV4 = a => !a.startsWith('169.254.') && !a.startsWith('0.')
function lanAddrs(id, port) {
  const out = []
  if (!port) return out
  for (const list of Object.values(os.networkInterfaces())) {
    for (const i of list || []) {
      if (i.family !== 'IPv4' || i.internal || !usableV4(i.address)) continue
      out.push(toMa(i.address, port, id))
    }
  }
  out.push(toMa('127.0.0.1', port, id))
  return [...new Set(out)].slice(0, 16)
}

// ---------- wire ----------
const T_AUTH = 1, T_AUTH_OK = 2, T_HELLO = 3, T_VECTOR = 4, T_UPDATE = 5, T_ADDRS = 6
const frame = (type, payload) => {
  const p = payload || Buffer.alloc(0)
  const h = Buffer.allocUnsafe(5); h.writeUInt32BE(p.length + 1, 0); h[4] = type
  return Buffer.concat([h, p])
}
const seal = (key, type, payload) => {
  const iv = crypto.randomBytes(12)
  const c = crypto.createCipheriv('aes-256-gcm', key, iv); c.setAAD(Buffer.from([type]))
  const ct = Buffer.concat([c.update(payload || Buffer.alloc(0)), c.final()])
  return frame(type, Buffer.concat([iv, ct, c.getAuthTag()]))
}
const unseal = (key, type, body) => {
  if (body.length < 29) throw new Error('short frame')
  const d = crypto.createDecipheriv('aes-256-gcm', key, body.subarray(0, 12))
  d.setAAD(Buffer.from([type])); d.setAuthTag(body.subarray(body.length - 16))
  return Buffer.concat([d.update(body.subarray(12, body.length - 16)), d.final()])
}

// ---------- mesh ----------
class Mesh {
  constructor(ident, { port, psk, advertise, relay }) {
    this.id = ident.id
    this.peerId = { toString: () => this.id }
    this.wantPort = port
    this.port = 0
    this.psk = psk
    this.advertise = advertise
    this.relay = relay
    this.conns = new Set()
    this.events = new Map()
    this.stopped = false
    this.punchKey = null
    this.punchCtr = 0
    this.targets = new Map()
    this.udpPeers = new Map()
    this.replied = new Map()
  }
  on(t, fn) { if (!this.events.has(t)) this.events.set(t, new Set()); this.events.get(t).add(fn); return () => this.events.get(t)?.delete(fn) }
  addEventListener(t, fn) { this.on(t, fn) }
  removeEventListener(t, fn) { this.events.get(t)?.delete(fn) }
  emit(t, detail) { for (const fn of this.events.get(t) || []) try { fn({ detail }) } catch (e) { dbg('[mesh] handler', e?.message) } }
  addrs() {
    const out = lanAddrs(this.id, this.port)
    if (this.advertise) {
      const m = String(this.advertise).match(/^\[([^\]]+)\]:(\d+)$/) || String(this.advertise).match(/^([^:]+):(\d+)$/)
      if (m && Number(m[2])) out.push(toMa(m[1], Number(m[2]), this.id))
    }
    return [...new Set(out)].slice(0, 16)
  }
  getConnections() { return [...this.conns].filter(c => c.ready).map(c => ({ remotePeer: { toString: () => c.peerId } })) }
  peerCount() { const s = new Set(); for (const c of this.conns) if (c.ready) s.add(c.peerId); return s.size }

  async start() {
    this.server = net.createServer(sock => this.attach(sock, null))
    const listen = p => new Promise((res, rej) => {
      const onErr = e => { this.server.off('error', onErr); rej(e) }
      this.server.once('error', onErr)
      this.server.listen(p, () => { this.server.off('error', onErr); res() })
    })
    try { await listen(this.wantPort) } catch {
      dbg('[mesh] listen failed on', this.wantPort); await listen(0)
    }
    this.port = this.server.address().port
    this.server.on('error', () => {})
    try {
      this.udp = dgram.createSocket({ type: 'udp4', reuseAddr: true })
      this.udp.on('message', (d, r) => this.onUdp(d, r))
      this.udp.on('error', () => {})
      await new Promise((res, rej) => {
        const onErr = e => { this.udp.off('error', onErr); rej(e) }
        this.udp.once('error', onErr)
        this.udp.bind(this.port, () => { this.udp.off('error', onErr); res() })
      })
      this.udpTimer = setInterval(() => this.tick(), 1000); this.udpTimer.unref?.()
    } catch { this.udp = null }
    dbg('[mesh] listening', this.port, 'udp', this.udp ? 'on' : 'off', 'id', this.id)
  }
  async stop() {
    this.stopped = true
    clearInterval(this.udpTimer)
    try { this.server?.close() } catch {}
    try { this.udp?.close() } catch {}
    for (const c of this.conns) try { c.sock.destroy() } catch {}
    this.conns.clear()
  }

  // punching
  addTarget(host, port) {
    if (!this.udp || !port) return
    if (host === '127.0.0.1' && port === this.port) return
    if (this.targets.size >= 32) return
    this.targets.set(host + ':' + port, { host, port })
  }
  punchPacket() {
    const b = Buffer.allocUnsafe(24)
    b.write('C3PU', 0, 'ascii')
    b.writeUInt32BE(this.punchCtr++ >>> 0, 4)
    crypto.createHmac('sha256', this.punchKey).update(b.subarray(0, 8)).digest().subarray(0, 16).copy(b, 8)
    return b
  }
  validPunch(d) {
    if (d.length !== 24 || d.toString('ascii', 0, 4) !== 'C3PU') return false
    const m = crypto.createHmac('sha256', this.punchKey).update(d.subarray(0, 8)).digest().subarray(0, 16)
    return crypto.timingSafeEqual(m, d.subarray(8, 24))
  }
  sendPunch(host, port) {
    if (!this.punchKey || !this.udp) return
    try { this.udp.send(this.punchPacket(), port, host) } catch {}
  }
  tick() {
    if (!this.punchKey) return
    const now = Date.now()
    for (const t of this.targets.values()) this.sendPunch(t.host, t.port)
    for (const p of this.udpPeers.values()) { this.sendPunch(p.host, p.port); if (now - p.ts > 25000) this.udpPeers.delete(p.host + ':' + p.port) }
    if (this.replied.size > 512) this.replied.clear()
  }
  onUdp(d, r) {
    if (!this.punchKey) return
    const now = Date.now()
    if (this.validPunch(d)) {
      const k = r.address + ':' + r.port
      if (!this.replied.has(k) || now - this.replied.get(k) > 500) {
        this.replied.set(k, now); this.sendPunch(r.address, r.port)
      }
      return
    }
    if (d.length < 6) return
    const len = d.readUInt32BE(0)
    if (len !== d.length - 4 || d[4] < 1 || d[4] > 30) return
    const k = r.address + ':' + r.port
    let p = this.udpPeers.get(k)
    if (!p) {
      p = { host: r.address, port: r.port, ts: now, conn: null }
      this.udpPeers.set(k, p)
      p.conn = this.newConn({ write: b => { try { this.udp.send(b, p.port, p.host) } catch {} }, destroy: () => {}, on: () => {} }, { host: r.address, port: r.port })
      p.conn.key = Buffer.alloc(32)
      this.sendHello(p.conn)
    }
    p.ts = now
    try { this.onFrame(p.conn, d[4], d.subarray(5)) } catch (e) { dbg('[mesh] udp frame', e?.message) }
  }

  // connections
  newConn(sock, hp) {
    const c = { sock, hp, key: null, peerId: null, ready: false, buf: Buffer.alloc(0), udp: !!hp && sock.on === undefined ? true : false }
    sock.on('data', d => this.onData(c, d))
    sock.on('close', () => { this.conns.delete(c); if (c.ready) this.emit('peer:disconnect', { toString: () => c.peerId }) })
    sock.on('error', () => {})
    this.conns.add(c)
    return c
  }
  attach(sock, hp) {
    sock.setNoDelay?.(true); sock.setKeepAlive?.(true, 10000)
    const c = this.newConn(sock, hp)
    this.startAuth(c, false)
  }
  startAuth(c, outbound) {
    c.ecdh = crypto.createECDH('prime256v1'); c.ecdh.generateKeys()
    c.nonce = crypto.randomBytes(16)
    const mode = outbound ? 1 : 0
    const proof = crypto.createHmac('sha256', this.psk).update(Buffer.concat([Buffer.from('c3auth\0'), Buffer.from([mode]), c.ecdh.getPublicKey(), c.nonce])).digest()
    c.sock.write(frame(T_AUTH, Buffer.concat([Buffer.from([mode]), c.ecdh.getPublicKey(), c.nonce, proof])))
  }
  onAuth(c, p) {
    if (p[0] !== 1 || p.length !== 114) throw new Error('auth len')
    const cpub = p.subarray(1, 66), cnonce = p.subarray(66, 82), proof = p.subarray(82, 114)
    const exp = crypto.createHmac('sha256', this.psk).update(Buffer.concat([Buffer.from('c3auth\0'), Buffer.from([1]), cpub, cnonce])).digest()
    if (!crypto.timingSafeEqual(proof, exp)) throw new Error('bad proof')
    const shared = c.ecdh.computeSecret(cpub)
    const salt = crypto.createHash('sha256').update(Buffer.concat([cpub, c.ecdh.getPublicKey(), cnonce, c.nonce])).digest()
    c.key = Buffer.from(crypto.hkdfSync('sha256', shared, salt, Buffer.from('c3conn'), 32))
    const ok = crypto.createHmac('sha256', this.psk).update(Buffer.concat([Buffer.from('c3ok\0'), c.ecdh.getPublicKey(), c.nonce])).digest()
    c.sock.write(frame(T_AUTH_OK, Buffer.concat([c.ecdh.getPublicKey(), c.nonce, ok])))
    c.sock.setTimeout?.(0)
    this.sendHello(c)
  }
  onAuthOk(c, p) {
    if (p.length !== 113) throw new Error('auth ok len')
    const spub = p.subarray(0, 65), snonce = p.subarray(65, 81), proof = p.subarray(81, 113)
    const exp = crypto.createHmac('sha256', this.psk).update(Buffer.concat([Buffer.from('c3ok\0'), spub, snonce])).digest()
    if (!crypto.timingSafeEqual(proof, exp)) throw new Error('bad ok')
    const shared = c.ecdh.computeSecret(spub)
    const salt = crypto.createHash('sha256').update(Buffer.concat([c.ecdh.getPublicKey(), spub, c.nonce, snonce])).digest()
    c.key = Buffer.from(crypto.hkdfSync('sha256', shared, salt, Buffer.from('c3conn'), 32))
    c.sock.setTimeout?.(0)
    this.sendHello(c)
  }
  onData(c, d) {
    c.buf = Buffer.concat([c.buf, d])
    try {
      while (c.buf.length >= 4) {
        const len = c.buf.readUInt32BE(0)
        if (len < 1 || len > MAX_FRAME) throw new Error('len')
        if (c.buf.length < 4 + len) return
        const body = c.buf.subarray(4, 4 + len)
        c.buf = c.buf.subarray(4 + len)
        this.onFrame(c, body[0], body.subarray(1))
      }
    } catch (e) { dbg('[mesh] frame', e?.message); try { c.sock.destroy() } catch {} }
  }
  onFrame(c, type, body) {
    if (type === T_AUTH) return this.onAuth(c, body)
    if (type === T_AUTH_OK) return this.onAuthOk(c, body)
    if (!c.key) throw new Error('unauth')
    const plain = unseal(c.key, type, body)
    if (type === T_HELLO) {
      let h; try { h = JSON.parse(plain.toString('utf8')) } catch { return }
      if (!h || typeof h.id !== 'string' || h.id === this.id) { try { c.sock.destroy() } catch {}; return }
      if (c.peerId && c.peerId !== h.id) return
      const first = !c.peerId
      c.peerId = h.id
      if (Array.isArray(h.addrs)) for (const a of h.addrs.slice(0, 16)) { const p = parseMa(a); if (p) this.addTarget(p.host, p.port) }
      if (first) { c.ready = true; this.emit('peer:connect', { toString: () => h.id }) }
      if (Array.isArray(h.addrs)) this.emit('addrs', h.addrs)
      return
    }
    if (type === T_VECTOR || type === T_UPDATE || type === T_ADDRS) {
      this.emit('message', { conn: c, type, payload: plain })
      if (this.relay) for (const o of this.conns) {
        if (o === c || !o.ready || o.peerId === c.peerId) continue
        try { o.sock.write(frame(type, seal(o.key, type, plain))) } catch {}
      }
    }
  }
  sendHello(c) {
    const h = JSON.stringify({ id: this.id, addrs: this.addrs(), relay: this.relay, port: this.port })
    try { c.sock.write(frame(T_HELLO, seal(c.key, T_HELLO, Buffer.from(h)))) } catch {}
  }
  sendAll(type, payload, except) {
    for (const c of this.conns) {
      if (c === except || !c.ready) continue
      try { c.sock.write(frame(type, seal(c.key, type, payload))) } catch {}
    }
  }
  async dial(ma) {
    const a = parseMa(ma)
    if (!a || a.id === this.id || this.stopped) return false
    for (const c of this.conns) if (c.hp && c.hp.host === a.host && c.hp.port === a.port) return true
    this.addTarget(a.host, a.port)
    return new Promise(res => {
      const sock = net.connect({ host: a.host, port: a.port })
      sock.setTimeout(6000, () => { try { sock.destroy() } catch {} })
      sock.once('connect', () => {
        sock.setTimeout(0)
        sock.setNoDelay(true); sock.setKeepAlive(true, 10000)
        const c = this.newConn(sock, { host: a.host, port: a.port })
        this.startAuth(c, true)
        res(true)
      })
      sock.once('error', () => { try { sock.destroy() } catch {}; res(false) })
    })
  }
}

// ---------- file mirror ----------
const doc = new Y.Doc()
const files = doc.getMap('files')
const texts = doc.getMap('texts')
const blobs = doc.getMap('blobs')
const touched = new Set()
const idToPath = new Map()
const lastWritten = new Map()
const diskMeta = new Map()
const pendingWrites = new Map()
const remote = tx => tx.origin !== 'disk' && tx.origin !== 'restore'
const asBuf = u => Buffer.from(u.buffer, u.byteOffset, u.byteLength)

const DEFAULT_IGNORE = ['.git', '.c3', 'node_modules', 'dist', 'build', 'out', '.env*', '*.pem', 'id_rsa*', '*.log', '.DS_Store', 'Thumbs.db', 'desktop.ini', '*.tmp', '*.tmp-*']
let customRules = []
function loadIgnores() {
  let lines = []
  try { lines = fs.readFileSync(path.join(SESSION_DIR, 'ignore'), 'utf8').split(/\r?\n/) } catch {}
  const res = [...DEFAULT_IGNORE, ...lines.map(l => l.trim()).filter(l => l && !l.startsWith('#'))]
    .map(p => {
      p = p.replace(/\/$/, '')
      let r = ''
      for (let i = 0; i < p.length; i++) {
        const ch = p[i]
        if (ch === '*') { if (p[i + 1] === '*') { r += '.*'; i++ } else r += '[^/]*' }
        else if (ch === '?') r += '[^/]'
        else r += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&')
      }
      return new RegExp('(^|/)' + r + '(/|$)')
    })
  customRules = res
}
const ignoredCache = new Map()
const isGitIgnored = rel => {
  let v = ignoredCache.get(rel)
  if (v === undefined) {
    try { execFileSync('git', ['check-ignore', '-q', '--', rel], { cwd: workDir, stdio: 'ignore' }); v = true } catch { v = false }
    if (ignoredCache.size > 50000) ignoredCache.clear()
    ignoredCache.set(rel, v)
  }
  return v
}
let backend = null
function shouldIgnore(rel) {
  if (!rel) return false
  rel = rel.split(path.sep).join('/')
  if (rel === '.git' || rel.startsWith('.git/')) return true
  if (rel === '.c3' || rel.startsWith('.c3/')) return true
  if (c3InsideWork && (rel === c3Rel || rel.startsWith(c3Rel + '/'))) return true
  if (backend?.excluded && (rel === backend.excluded || rel.startsWith(backend.excluded + '/'))) return true
  if (customRules.some(re => re.test(rel))) return true
  if (backend?.kind === 'git' && isGitIgnored(rel)) return true
  return false
}
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
function symlinkEscape(abs) {
  let cur = workDir
  try { for (const part of path.relative(workDir, abs).split(path.sep)) { cur = path.join(cur, part); if (fs.lstatSync(cur).isSymbolicLink()) return true } } catch {}
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
function applyDiff(t, next) {
  const cur = t.toString()
  if (cur === next) return false
  let s = 0; while (s < cur.length && s < next.length && cur[s] === next[s]) s++
  let e = 0; while (e < cur.length - s && e < next.length - s && cur[cur.length - 1 - e] === next[next.length - 1 - e]) e++
  if (cur.length - s - e > 0) t.delete(s, cur.length - s - e)
  if (next.length - s - e > 0) t.insert(s, next.slice(s, next.length - e))
  return true
}
function syncFromDisk(rel, seed = false) {
  const norm = safeRel(rel)
  if (!norm || norm !== rel || shouldIgnore(norm)) return
  let data
  try { data = fs.readFileSync(path.join(workDir, norm)) } catch { return }
  if (data.length > MAX_FILE) { return }
  const bin = data.includes(0)
  doc.transact(() => {
    const entry = files.get(norm)
    if (!entry) {
      const id = crypto.randomUUID(); files.set(norm, { id, bin })
      if (bin) blobs.set(id, new Uint8Array(data)); else texts.set(id, new Y.Text(data.toString('utf8')))
      if (!seed) touched.add(norm); return
    }
    if (entry.bin !== bin) {
      files.set(norm, { id: entry.id, bin })
      if (bin) { texts.delete(entry.id); blobs.set(entry.id, new Uint8Array(data)) } else { blobs.delete(entry.id); texts.set(entry.id, new Y.Text(data.toString('utf8'))) }
      if (!seed) touched.add(norm); return
    }
    if (bin) { const cur = blobs.get(entry.id); if (!cur || Buffer.compare(asBuf(cur), data) !== 0) { blobs.set(entry.id, new Uint8Array(data)); if (!seed) touched.add(norm) } }
    else { const t = texts.get(entry.id); if (t && applyDiff(t, data.toString('utf8')) && !seed) touched.add(norm) }
  }, 'disk')
}
function removeFromDoc(rel) {
  doc.transact(() => {
    const entry = files.get(rel); if (!entry) return
    touched.add(rel); files.delete(rel); texts.delete(entry.id); blobs.delete(entry.id)
  }, 'disk')
}
function writeToDisk(rawRel) {
  const entry = files.get(rawRel); if (!entry) return
  const rel = safeRel(rawRel); if (!rel || rel !== rawRel) return
  if (shouldIgnore(rel)) return
  const abs = path.join(workDir, rel)
  if (symlinkEscape(abs)) return
  let data
  if (entry.bin) { const b = blobs.get(entry.id); data = b ? asBuf(b) : Buffer.alloc(0) }
  else data = Buffer.from(texts.get(entry.id)?.toString() ?? '', 'utf8')
  if (data.length > MAX_FILE) return
  try {
    if (fs.existsSync(abs) && Buffer.compare(fs.readFileSync(abs), data) === 0) return
    mkdirp(path.dirname(abs)); atomicWrite(abs, data); lastWritten.set(rel, Date.now())
    try { const st = fs.statSync(abs); diskMeta.set(rel, st.mtimeMs + ':' + st.size) } catch {}
  } catch {}
}
function scheduleWrite(rel) { clearTimeout(pendingWrites.get(rel)); pendingWrites.set(rel, setTimeout(() => { pendingWrites.delete(rel); writeToDisk(rel) }, WRITE_DEBOUNCE_MS)) }
function flushWrites() { for (const [rel, t] of pendingWrites) { clearTimeout(t); writeToDisk(rel) } pendingWrites.clear() }
files.observe(ev => {
  for (const [key, change] of ev.keys) {
    if (change.action === 'delete') { const o = change.oldValue; if (o?.id && idToPath.get(o.id) === key) idToPath.delete(o.id) }
    else { const e = files.get(key); if (change.action === 'update' && change.oldValue?.id && change.oldValue.id !== e?.id) idToPath.delete(change.oldValue.id); if (e?.id) idToPath.set(e.id, key) }
  }
  if (!remote(ev.transaction)) return
  for (const [rawRel, change] of ev.keys) {
    const rel = safeRel(rawRel); if (!rel || rel !== rawRel) continue
    if (shouldIgnore(rel)) continue
    if (change.action === 'delete') { touched.add(rel); fs.rmSync(path.join(workDir, rel), { force: true }) }
    else { touched.add(rel); scheduleWrite(rawRel) }
  }
})
const onContent = evs => {
  if (!remote(evs[0].transaction)) return
  for (const ev of evs) {
    const ids = ev.target === texts || ev.target === blobs ? [...ev.keys.keys()] : [ev.path[0]]
    for (const id of ids) { const p = idToPath.get(id); if (p) { touched.add(p); scheduleWrite(p) } }
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

// ---------- backend ----------
function makeBackend(config) {
  if (config.backend === 'git') {
    return {
      kind: 'git', excluded: null,
      prepare() {
        gitOk('fetch')
        if (gitOk('rev-parse', '--abbrev-ref', 'HEAD') === 'HEAD')
          for (const b of ['main', 'master']) if (gitOk('rev-parse', '--verify', '--quiet', 'refs/heads/' + b)) { try { git('checkout', b); break } catch {} }
      },
      generation: () => gitOk('rev-parse', 'HEAD') ?? 'no-head',
      save(paths, meta) {
        const list = [...paths]
        for (let i = 0; i < list.length; i += 500) git('add', '-A', '--', ...list.slice(i, i + 500))
        if (gitOk('status', '--porcelain') === '') return { saved: false }
        const idc = gitOk('config', 'user.name') && gitOk('config', 'user.email') ? [] : ['-c', 'user.name=c3', '-c', 'user.email=c3@localhost']
        git(...idc, 'commit', '-m', meta.message)
        try { git('push'); return { saved: true, pushed: true } } catch {}
        try { gitOk('fetch'); git('merge', '-X', 'ours', '--no-edit', '@{u}') } catch {
          try { gitOk('merge', '--abort') } catch {}
          if (config.forcePush !== false) { try { git('push', '--force'); return { saved: true, pushed: true, forced: true } } catch {} }
          return { saved: true, pushed: false }
        }
        try { git('push'); return { saved: true, pushed: true } } catch { return { saved: true, pushed: false } }
      }
    }
  }
  return { kind: 'none', excluded: null, prepare() {}, generation: () => 'static', save: () => ({ saved: false }) }
}

// ---------- sync ----------
function sync(mesh, doc, onAddrs) {
  if (!mesh.punchKey) return
  const seen = new Set()
  const parts = new Map()
  const aes = crypto.createHash('sha256').update('c3msg').update(mesh.psk).digest ? mesh.psk : mesh.psk
  const sendVec = () => mesh.sendAll(T_VECTOR, Buffer.from(Y.encodeStateVector(doc)))
  const sendAddrs = () => mesh.sendAll(T_ADDRS, Buffer.from(JSON.stringify(mesh.addrs())))
  const sendUpd = u => {
    const data = Buffer.from(u)
    const id = crypto.createHash('sha1').update(data).digest().subarray(0, 8)
    const count = Math.max(1, Math.ceil(data.length / CHUNK))
    for (let i = 0; i < count; i++) {
      const h = Buffer.allocUnsafe(13); h[0] = T_UPDATE; id.copy(h, 1); h.writeUInt16BE(i, 9); h.writeUInt16BE(count, 11)
      mesh.sendAll(T_UPDATE, Buffer.concat([h, data.subarray(i * CHUNK, (i + 1) * CHUNK)]))
    }
  }
  mesh.on('message', ev => {
    const { conn, type, payload } = ev.detail || {}
    if (!type || !payload) return
    if (type === T_VECTOR) { const diff = Y.encodeStateAsUpdate(doc, payload); if (diff.length > 2) sendUpd(diff) }
    else if (type === T_UPDATE) {
      if (payload.length < 13) return
      const id = payload.subarray(1, 9).toString('hex')
      const i = payload.readUInt16BE(9), count = payload.readUInt16BE(11)
      if (count < 1 || count > 4096 || i >= count) return
      let e = parts.get(id); if (!e) { e = { count, got: 0, buf: [] }; parts.set(id, e) }
      if (e.count !== count || e.buf[i]) return
      e.buf[i] = Buffer.from(payload.subarray(13)); e.got++
      if (e.got === e.count) {
        parts.delete(id); const full = Buffer.concat(e.buf)
        const h = crypto.createHash('sha1').update(full).digest('hex')
        if (seen.has(h)) return; seen.add(h); if (seen.size > 2048) seen.clear()
        try { Y.applyUpdate(doc, full, 'remote') } catch {}
        for (const c of mesh.conns) if (c !== conn && c.ready) { try { c.sock.write(frame(T_UPDATE, seal(c.key, T_UPDATE, payload))) } catch {} }
      }
      if (parts.size > 256) parts.clear()
    } else if (type === T_ADDRS) {
      let a; try { a = JSON.parse(payload.toString('utf8')) } catch { return }
      if (Array.isArray(a)) onAddrs(a.filter(x => typeof x === 'string' && /\/p2p\//.test(x)).slice(0, 16))
    }
  })
  mesh.on('peer:connect', () => { sendVec(); sendAddrs() })
  doc.on('update', (u, origin) => { if (origin !== 'remote' && origin !== 'restore') sendUpd(u) })
  const t = setInterval(() => { sendVec(); sendAddrs() }, 8000); t.unref?.()
  sendVec(); sendAddrs()
}

// ---------- connect ----------
async function connect() {
  const cfg0 = readConfig() ?? {}
  mkdirp(SESSION_DIR)
  const ident = loadIdentity()
  const name = flag('name') ?? cfg0.name ?? die('No session name. Run `c3 config`.')
  const sdir = sdirOf(name)
  const sKey = flag('key') ?? process.env.C3_KEY ?? readKey(sdir)
  if (!sKey) die('No session key. Run `c3 config` or paste a share block.')
  if (flag('key')) writeKey(sdir, sKey)
  const wantPort = Number(flag('port') ?? cfg0.port ?? DEFAULT_PORT)
  const advertise = String(flag('advertise') ?? cfg0.advertise ?? '').trim()
  const wantRelay = has('relay') || cfg0.relay === true
  const psk = crypto.createHash('sha256').update('c3psk\0').update(name).update('\0').update(sKey).digest()
  const mesh = new Mesh(ident, { port: wantPort, psk, advertise, relay: wantRelay })
  mesh.punchKey = psk
  await mesh.start()
  const port = mesh.port
  const me = { name: gitOk('config', 'user.name') ?? (os.userInfo().username || 'peer') }
  const cfg = { ...cfg0, name, port }
  if (advertise) cfg.advertise = advertise
  if (wantRelay) cfg.relay = true
  if (!cfg.backend) cfg.backend = fs.existsSync(path.join(workDir, '.git')) ? 'git' : 'none'
  atomicWrite(CONFIG_FILE, JSON.stringify(cfg, null, 2)); chmod(CONFIG_FILE, 0o600)
  atomicWrite(path.join(sdir, 'name'), JSON.stringify({ name }))
  loadIgnores()
  backend = makeBackend(cfg)
  backend.prepare()
  const peers = new Set()
  for (const a of readPeers(sdir)) peers.add(a)
  if (flag('peer')) peers.add(flag('peer'))
  const askedPeers = flag('peer') !== undefined
  let leaving = false, started = false, watcher = null
  let peerTimer = null, snapTimer = null, scanTimer = null, tick = null, dialTimer = null, addrsTimer = null
  const addPeer = a => {
    if (typeof a !== 'string' || a.length > 500 || !/\/p2p\//.test(a)) return
    if (a.includes('/p2p/' + mesh.id)) return
    if (peers.has(a) || peers.size >= 64) return
    peers.add(a); writePeers(sdir, [...peers])
  }
  const dialPeers = () => {
    if (leaving) return
    for (const a of readPeers(sdir)) if (!peers.has(a)) peers.add(a)
    const live = new Set(mesh.getConnections().map(c => c.remotePeer.toString()))
    let n = 0
    for (const a of peers) {
      if (n >= 8) break
      const p = parseMa(a); if (!p || live.has(p.id)) continue
      mesh.dial(a).catch(() => {}); n++
    }
  }
  const waitFor = async (ms, cond) => { const until = Date.now() + ms; while (Date.now() < until) { if (cond()) return true; await sleep(200) } return cond() }
  // state
  const stateFile = path.join(sdir, 'state.bin')
  const genFile = path.join(sdir, 'state.gen')
  const logFile = path.join(sdir, 'oplog')
  const appendLog = u => { try { const h = Buffer.allocUnsafe(4); h.writeUInt32BE(u.length, 0); fs.appendFileSync(logFile, Buffer.concat([h, Buffer.from(u)])) } catch {} }
  const snapshotNow = () => { try { atomicWrite(stateFile, Y.encodeStateAsUpdate(doc)); atomicWrite(genFile, backend.generation()); fs.rmSync(logFile, { force: true }) } catch {} }
  const scheduleSnapshot = () => { clearTimeout(snapTimer); snapTimer = setTimeout(snapshotNow, 5000) }
  const removeState = () => { for (const f of [stateFile, genFile, logFile]) { try { fs.rmSync(f, { force: true }) } catch {} } }
  function restoreState() {
    if (!fs.existsSync(stateFile)) return false
    try {
      const g = fs.existsSync(genFile) ? fs.readFileSync(genFile, 'utf8').trim() : null
      if (g && g !== backend.generation()) { removeState(); return false }
      Y.applyUpdate(doc, fs.readFileSync(stateFile), 'restore')
      if (fs.existsSync(logFile)) {
        const b = fs.readFileSync(logFile); let off = 0
        while (off + 4 <= b.length) { const len = b.readUInt32BE(off); off += 4; if (len < 1 || len > MAX_FRAME || off + len > b.length) break; try { Y.applyUpdate(doc, b.subarray(off, off + len), 'restore') } catch {}; off += len }
      }
      for (const rel of files.keys()) touched.add(rel)
      ui.say('Restored unsaved state from last run.'); return true
    } catch { removeState(); return false }
  }
  const restored = restoreState()
  sync(mesh, doc, addrs => { for (const a of addrs) addPeer(a); dialPeers() })
  doc.on('update', (u, origin) => { if (origin === 'restore') return; appendLog(u); scheduleSnapshot() })
  // scan
  let lastGitignore = 0
  function scan() {
    try {
      let m = 0; try { m = fs.statSync(path.join(workDir, '.gitignore')).mtimeMs } catch {}
      if (m !== lastGitignore) { lastGitignore = m; ignoredCache.clear() }
      const list = walkTree(); const present = new Set(list); const now = Date.now()
      for (const rel of list) {
        if (pendingWrites.has(rel) || (lastWritten.get(rel) ?? 0) > now - 500) continue
        let st; try { st = fs.statSync(path.join(workDir, rel)) } catch { continue }
        const sig = st.mtimeMs + ':' + st.size; if (diskMeta.get(rel) === sig) continue
        diskMeta.set(rel, sig); syncFromDisk(rel)
      }
      for (const rel of [...files.keys()]) { if (present.has(rel) || pendingWrites.has(rel) || (lastWritten.get(rel) ?? 0) > now - 500) continue; removeFromDoc(rel) }
    } catch {}
  }
  function quick(rel) {
    if (!rel) return; const now = Date.now(); if (pendingWrites.has(rel) || (lastWritten.get(rel) ?? 0) > now - 300) return
    let st; try { st = fs.statSync(path.join(workDir, rel)) } catch { if (files.has(rel)) removeFromDoc(rel); return }
    if (!st.isFile()) return
    const sig = st.mtimeMs + ':' + st.size; if (diskMeta.get(rel) === sig) return
    diskMeta.set(rel, sig); syncFromDisk(rel)
  }
  function startScan() {
    if (started) return; started = true; scan()
    try {
      watcher = fs.watch(workDir, { recursive: true }, (_e, f) => {
        if (!f) return
        const rel = String(f).split(path.sep).join('/')
        if (!rel || rel === '.git' || rel.startsWith('.git/') || rel === '.c3' || rel.startsWith('.c3/')) return
        if (c3InsideWork && (rel === c3Rel || rel.startsWith(c3Rel + '/'))) return
        quick(rel)
      })
      watcher.on('error', () => {})
    } catch { ui.warn('instant watching unavailable -- polling only') }
    scanTimer = setInterval(scan, SCAN_MS)
  }
  function seedFromDisk() {
    const seed = walkTree(); let bytes = 0
    for (const rel of seed) { try { bytes += fs.statSync(path.join(workDir, rel)).size } catch {} }
    if (!cfg.forceSeed && (seed.length > SEED_FILES || bytes > SEED_BYTES)) die(`Refusing to seed ${seed.length} files / ${(bytes / 1e6).toFixed(0)} MB.`)
    ui.say(`Seeding ${seed.length} files.`)
    doc.transact(() => { for (const rel of seed) syncFromDisk(rel, true) }, 'disk')
    startScan()
  }
  async function confirmSave() {
    if (has('yes')) return true
    if (!process.stdin.isTTY) return false
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
    const a = (await rl.question(`Publish ${touched.size} changed path(s) to archive? [y/N] `)).trim().toLowerCase()
    rl.close(); return a === 'y' || a === 'yes'
  }
  async function leave() {
    if (leaving) return; leaving = true
    clearInterval(scanTimer); clearTimeout(snapTimer); clearTimeout(peerTimer); clearInterval(tick); clearInterval(dialTimer); clearInterval(addrsTimer)
    try { watcher?.close() } catch {}
    flushWrites(); snapshotNow(); ui.clear()
    try {
      const others = mesh.peerCount()
      if (others > 0) ui.say(`Others still in session (${others}) -- keeping local state.`)
      else if (touched.size === 0) { ui.say('Nothing changed.'); removeState() }
      else if (!(await confirmSave())) ui.say('Skipped publishing.')
      else {
        const r = backend.save(touched, { user: me.name, message: `Session snapshot ${new Date().toISOString()}` })
        if (r.saved === false) { ui.say('Nothing changed.'); removeState() }
        else if (r.pushed === false) ui.warn('Could not push -- commit kept locally.')
        else { removeState(); ui.say(r.forced ? 'Saved and pushed (force).' : 'Saved and pushed.') }
      }
    } catch (e) { console.error('Save failed:', e.message) }
    finally { try { await mesh.stop() } catch {}; process.exit(0) }
  }
  mesh.addEventListener('peer:connect', ev => { const pid = ev.detail?.toString?.() ?? 'peer'; ui.say(`peer ${pid.slice(0, 8)} connected`); dialPeers() })
  mesh.addEventListener('peer:disconnect', () => ui.set(`live - ${mesh.peerCount()} peer(s)`))
  const addrsFile = path.join(sdir, 'addrs.json')
  const writeAddrs = () => { try { atomicWrite(addrsFile, JSON.stringify({ id: mesh.id, addrs: mesh.addrs(), port })) } catch {} }
  addrsTimer = setInterval(writeAddrs, 5000); writeAddrs()
  dialPeers(); dialTimer = setInterval(dialPeers, 10000)
  ui.set('looking for peers...')
  await sleep(PEER_WAIT_MS)
  if (askedPeers && files.size === 0) await waitFor(STATE_WAIT_MS, () => files.size > 0)
  if (restored && files.size > 0) { ui.say('Ready from local state.'); reconcile(); startScan() }
  else if (files.size > 0) { ui.say(`Joined session with ${mesh.peerCount()} peer(s).`); reconcile(); startScan() }
  else if (askedPeers && !has('seed')) { ui.say('No state yet -- keeping directory as-is (pass --seed for a new session).'); startScan() }
  else seedFromDisk()
  tick = setInterval(() => {
    const p = mesh.peerCount()
    ui.set(`live - ${p} peer${p === 1 ? '' : 's'} - ${files.size} files - ${backend.kind}${wantRelay ? ' - relay' : ''}`)
  }, 2000)
  ui.say('Ready. Ctrl+C to leave.')
  process.on('SIGINT', leave); process.on('SIGTERM', leave)
}

// ---------- config ----------
async function configCmd() {
  const isGit = fs.existsSync(path.join(workDir, '.git'))
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  const ask = async (q, def) => {
    if (!process.stdin.isTTY) return def
    const a = (await rl.question(`${C.cyn}?${C.r} ${q}${def ? ` [${C.yel}${def}${C.r}]` : ''} `)).trim()
    return a || def
  }
  ui.clear(); console.log(`c3 config -- ${workDir}`)
  const choice = await ask('Backend  1) git  2) none  Pick 1/2', isGit ? '1' : '2')
  const kind = ({ '1': 'git', '2': 'none' })[choice] || choice
  if (kind === 'git' && !isGit) die('No .git here.')
  const name = flag('name') ?? await ask('Session name', path.basename(workDir))
  if (!name) die('Session name required.')
  const sdir = sdirOf(name)
  let key = flag('key')
  if (!key) {
    const c = (await ask(`Session key: new / paste${readKey(sdir) ? ' / keep' : ''}`, 'new')).toLowerCase()
    if (c === 'keep' && readKey(sdir)) key = readKey(sdir)
    else if (c === 'paste') key = (await rl.question('Paste key: ')).trim()
    else key = crypto.randomBytes(32).toString('base64url')
  }
  if (!key) die('No key.')
  writeKey(sdir, key)
  const port = Number(flag('port') ?? await ask('Listening TCP/UDP port', String(DEFAULT_PORT)))
  if (!Number.isInteger(port) || port < 1 || port > 65535) die('Bad port.')
  const advertise = String(flag('advertise') ?? await ask('Reachable host:port (blank = LAN only)', '')).trim()
  const cfg = { backend: kind, name, port }
  if (advertise) cfg.advertise = advertise
  atomicWrite(CONFIG_FILE, JSON.stringify(cfg, null, 2)); chmod(CONFIG_FILE, 0o600)
  atomicWrite(path.join(sdir, 'name'), JSON.stringify({ name }))
  if (kind === 'git') {
    const ex = path.join(workDir, '.git', 'info', 'exclude')
    mkdirp(path.dirname(ex))
    const cur = fs.existsSync(ex) ? fs.readFileSync(ex, 'utf8') : ''
    if (!cur.split('\n').includes(c3Name + '/')) fs.appendFileSync(ex, '\n' + c3Name + '/\n')
  }
  rl.close(); ui.clear()
  console.log(`Config written: ${CONFIG_FILE}`)
  console.log('Start:  node c3.js connect')
  console.log('Then:   node c3.js share   (paste the block to the other peer)')
}

// ---------- share / peer ----------
function shareCmd() {
  const cfg = readConfig() ?? die('No config.')
  const sdir = sdirOf(cfg.name)
  const key = readKey(sdir) ?? die('No key.')
  let addrs = []
  try { addrs = JSON.parse(fs.readFileSync(path.join(sdir, 'addrs.json'), 'utf8')).addrs ?? [] } catch {}
  if (!addrs.length) {
    const id = loadIdentity().id
    addrs = lanAddrs(id, Number(cfg.port ?? DEFAULT_PORT))
  }
  addrs = addrs.filter(a => /\/p2p\//.test(a) && !a.includes('/ip4/127.0.0.1/')).slice(0, 4)
  if (!addrs.length) die('No LAN address found. Start `connect` first.')
  ui.clear()
  console.log(`Share for "${cfg.name}" -- paste this block to the other peer:\n`)
  console.log(`  name: ${cfg.name}`)
  console.log(`  key:  ${key}`)
  addrs.forEach(a => console.log(`  peer: ${a}`))
  console.log('\nThey run:')
  console.log(`  node c3.js connect --name="${cfg.name}" --key="${key}" --peer="${addrs[0]}"`)
  console.log('\nThen they `share` and you paste their "peer:" line into:')
  console.log('  node c3.js peer "<their peer:>"')
  console.log('\nufw on = TCP drops; UDP punching takes over within a few seconds.')
}
function peerCmd() {
  const cfg = readConfig() ?? die('No config.')
  const sdir = sdirOf(cfg.name)
  const ma = String(argv[1] || '').trim()
  if (!/^\/(ip4|ip6|dns)\/.+\/p2p\/[0-9a-f]{16}$/.test(ma)) die('usage: node c3.js peer "/ip4/10.0.0.5/tcp/8443/p2p/<id>"')
  const list = readPeers(sdir)
  if (!list.includes(ma)) list.push(ma)
  writePeers(sdir, list)
  ui.say(`peer added: ${ma}`)
  ui.say('A running `connect` picks it up in ~10s.')
}

// ---------- dispatch ----------
const usage = `usage: node c3.js <command> [flags]
Commands:
  config    interactive setup
  connect   join/start session
  share     print name + key + addresses (paste once)
  peer <ma> add a cached peer address
Flags:
  --name <n>    session name
  --key <k>     session key
  --peer <ma>   peer multiaddr
  --port <n>    listening TCP/UDP port (default 8443)
  --advertise   reachable host:port
  --relay       forward frames for other peers (on by default in this build)
  --seed        publish this directory into an empty session
  --yes         auto-confirm publish
Same session name + key = same room.
`
loadIgnores()
if (cmd === 'config') await configCmd()
else if (cmd === 'connect') await connect()
else if (cmd === 'share') shareCmd()
else if (cmd === 'peer') peerCmd()
else die(usage)
