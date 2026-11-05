#!/usr/bin/env node
// c3 -- P2P live file session, single file. Node 22+, `yjs` is the only dependency.
// Layout this is built for:
//
//   repo/                 <- ROOT is ALWAYS the folder that contains c3/
//   ├── .git/             (the "trunk")
//   ├── src/...
//   └── c3/               <- this file, excluded from sync
//       └── .c3/          <- state
//
// Lifecycle:
//   peer 1  `node c3.js`               -> resets the tree to HEAD, seeds it, prints invite
//   peer 2  `node c3.js join c3://...` -> adopts peer 1's live state
//   ...they edit, changes flow both ways...
//   peer 1  Ctrl+C                     -> "others still in session", no commit
//   peer 2  Ctrl+C (last out)          -> commits + pushes the whole tree
//
// `node c3.js` alone RESUMES local state. Use `join` for a first contact.
//
// Networking: addresses are multiaddrs. IPv4 and global IPv6 are both advertised.
// A peer behind carrier NAT (phone hotspot) or on a NAT'd campus network cannot be
// dialled from another network -- c3 says so at startup instead of letting the other
// side hang for 45s. Start the session from the peer that has a global IPv6 or a
// public IPv4. `--lan-only` hides global addresses; `--all-ifaces` also advertises
// virtual adapters (VMware, docker, ...).
import * as Y from 'yjs'
import readline from 'node:readline/promises'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import net from 'node:net'
import dgram from 'node:dgram'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'

// ---------- cli ----------
const argv = process.argv.slice(2)
const cmd = argv[0]
const flag = n => {
  const i = argv.indexOf('--' + n)
  if (i >= 0 && argv[i + 1] !== undefined && !argv[i + 1].startsWith('--')) return argv[i + 1]
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
const mkdirp = (d, mode) => fs.mkdirSync(d, { recursive: true, ...(mode ? { mode } : {}) })
const atomicWrite = (f, d, mode = 0o600) => {
  const t = f + '.tmp-' + process.pid + '-' + crypto.randomBytes(4).toString('hex')
  fs.writeFileSync(t, d, { mode })
  fs.renameSync(t, f)
  try { fs.chmodSync(f, mode) } catch {}
}
const chmod = (f, m) => { try { fs.chmodSync(f, m) } catch {} }
const sigOf = st => st.mtimeMs + ':' + st.size
const env = { ...process.env, GIT_TERMINAL_PROMPT: '0' }
const GIT_TIMEOUT = 120000
const git = (...a) => execFileSync('git', a, { cwd: ROOT, encoding: 'utf8', maxBuffer: 1 << 28, timeout: GIT_TIMEOUT, env }).trim()
const gitOk = (...a) => { try { return git(...a) } catch { return null } }

// ---------- paths / root ----------
const c3Dir = path.dirname(fileURLToPath(import.meta.url))
const SESSION_DIR = path.join(c3Dir, '.c3')
const CONFIG_FILE = path.join(SESSION_DIR, 'config.json')
let ROOT = null, c3Rel = null, c3Inside = false
const readConfig = () => { try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) } catch { return null } }
const sidOf = n => crypto.createHash('sha256').update('c3sid\0' + n).digest()
const sdirOf = n => { const d = path.join(SESSION_DIR, 's', sidOf(n).toString('hex').slice(0, 32)); mkdirp(d, 0o700); chmod(d, 0o700); return d }
const readKey = s => { try { return fs.readFileSync(path.join(s, 'key'), 'utf8').trim() } catch { return null } }
const writeKey = (s, k) => { atomicWrite(path.join(s, 'key'), k, 0o600) }
const peersFile = s => path.join(s, 'peers.json')
const readPeers = s => { try { const a = JSON.parse(fs.readFileSync(peersFile(s), 'utf8')); return Array.isArray(a) ? a.filter(x => typeof x === 'string' && x.length < 500).slice(0, 64) : [] } catch { return [] } }
const writePeers = (s, a) => { atomicWrite(peersFile(s), JSON.stringify(a.slice(0, 64), null, 2), 0o600) }

// ROOT is always the directory above c3/. No .git check, no cwd fallback.
const defaultRoot = () => path.resolve(c3Dir, '..')
const chooseRoot = () => flag('dir') ?? defaultRoot()

function setRoot(dir) {
  let real
  try { real = fs.realpathSync(path.resolve(String(dir))) } catch { die('Directory not found: ' + dir) }
  if (!fs.statSync(real).isDirectory()) die('Not a directory: ' + real)
  if (real === path.parse(real).root) die('Refusing to use the filesystem root. Pass --dir <project>.')
  let home = os.homedir()
  try { home = fs.realpathSync(home) } catch {}
  if (real === home) die('Refusing to sync your home directory. Pass --dir <project>.')
  if (home.startsWith(real + path.sep)) die('Refusing to sync a directory that contains your home directory.')
  ROOT = real
  const r = path.relative(ROOT, c3Dir)
  c3Inside = !!r && !r.startsWith('..') && !path.isAbsolute(r)
  c3Rel = c3Inside ? r.split(path.sep).join('/') : null
  mkdirp(SESSION_DIR, 0o700)
}

// ---------- identity ----------
function loadIdentity() {
  mkdirp(SESSION_DIR, 0o700)
  const f = path.join(SESSION_DIR, 'identity.json')
  try {
    const j = JSON.parse(fs.readFileSync(f, 'utf8'))
    if (/^[0-9a-f]{16}$/.test(j.id)) return j
  } catch {}
  const j = { id: crypto.randomBytes(8).toString('hex') }
  atomicWrite(f, JSON.stringify(j), 0o600)
  return j
}

// ---------- addresses ----------
const bareAddr = h => String(h ?? '').trim().replace(/^\[/, '').replace(/\]$/, '').split('%')[0]

const isLocalOnly = h => {
  const a = bareAddr(h)
  if (net.isIPv4(a)) return /^(0\.|127\.|169\.254\.|22[4-9]\.|2[3-5]\d\.|255\.)/.test(a)
  if (net.isIPv6(a)) {
    const l = a.toLowerCase()
    if (l === '::' || l === '::1' || l === '0:0:0:0:0:0:0:1') return true
    if (/^fe[89ab]/.test(l)) return true          // fe80::/10 link-local
    if (/^ff/.test(l)) return true                // multicast
    if (/^::ffff:/.test(l)) return true           // v4-mapped
    return false
  }
  return false
}

// globally routable IPv6: not loopback, not link-local, not ULA
const isGlobal6 = h => {
  const a = bareAddr(h)
  if (!net.isIPv6(a) || isLocalOnly(a)) return false
  if (/^f[cd]/.test(a.toLowerCase())) return false   // fc00::/7
  return true
}

// 100.64.0.0/10 -- carrier-grade NAT. The laptop cannot see this; the phone can.
const isCgnat4 = h => {
  const a = bareAddr(h)
  if (!net.isIPv4(a)) return false
  const [x, y] = a.split('.').map(Number)
  return x === 100 && y >= 64 && y <= 127
}

// public IPv4 -- 100.64/10 is CGNAT and NOT reachable from outside
const isPublic4 = h => {
  const a = bareAddr(h)
  if (!net.isIPv4(a)) return false
  const [x, y] = a.split('.').map(Number)
  if (x === 0 || x === 10 || x === 127) return false
  if (x === 172 && y >= 16 && y <= 31) return false
  if (x === 192 && y === 168) return false
  if (x === 169 && y === 254) return false
  if (isCgnat4(a)) return false
  if (x >= 224) return false
  return true
}

// private IPv4 handed out by a phone hotspot (iPhone / Android / Windows)
const HOTSPOT4 = /^(172\.20\.1[01]\.|192\.168\.4[23]\.|192\.168\.137\.|10\.42\.0\.)/
const hotspotLike = h => HOTSPOT4.test(bareAddr(h))

// interface names that are almost always virtual adapters
const VIRTUAL_IFACE = /^(vethernet|vmware|virtualbox|vboxnet|docker|br-|veth|virbr|podman|cni|flannel|cali|kube|hyper-v|npcap|loopback|zt|tailscale|wg\d|tun\d|tap\d|utun|awdl|llw|anpi|bridge\d)/i
const isVirtualIface = n => VIRTUAL_IFACE.test(String(n || ''))

const isDialable = p => !!p && (isGlobal6(p.host) || isPublic4(p.host) || p.kind === 'dns')

// ---------- multiaddr ----------
const toMa = (host, port, id) => {
  const h = bareAddr(host)
  const k = net.isIPv6(h) ? 'ip6' : net.isIPv4(h) ? 'ip4' : 'dns'
  return `/${k}/${h}/tcp/${port}/p2p/${id}`
}
const parseMa = s => {
  const m = String(s || '').match(/^\/(ip4|ip6|dns)\/([^/]{1,255})\/tcp\/(\d{1,5})\/p2p\/([0-9a-f]{16})$/)
  if (!m) return null
  const kind = m[1]
  const host = bareAddr(m[2])
  const port = Number(m[3])
  if (!(port > 0 && port < 65536)) return null
  if (kind === 'ip4' && !net.isIPv4(host)) return null
  if (kind === 'ip6' && !net.isIPv6(host)) return null
  if (kind === 'dns' && !/^[a-z0-9]([a-z0-9.-]{0,252}[a-z0-9])?$/i.test(host)) return null
  return { kind, host, port, id: m[4] }
}

const addrRank = p => {
  if (!p) return 9
  if (p.kind === 'ip6') return isGlobal6(p.host) ? 0 : 3       // global v6 wins
  if (p.kind === 'dns') return 1
  if (p.kind === 'ip4') return isPublic4(p.host) ? 1 : p.host === '127.0.0.1' ? 8 : 2
  return 4
}

function lanAddrs(id, port, opts = {}) {
  const out = []
  if (!port) return out
  const all = !!opts.allIfaces
  for (const [name, list] of Object.entries(os.networkInterfaces())) {
    if (!all && isVirtualIface(name)) continue
    for (const i of list || []) {
      const a = bareAddr(i?.address || '')
      if (!a || i.internal || isLocalOnly(a)) continue
      const v4 = net.isIPv4(a), v6 = net.isIPv6(a)
      if (!v4 && !v6) continue
      if (v6 && !isGlobal6(a)) continue                    // drop ULA, mapped
      out.push(toMa(a, port, id))
    }
  }
  out.push(toMa('127.0.0.1', port, id))                    // last resort, filtered from invites
  const seen = new Set()
  return out
    .filter(m => { if (seen.has(m)) return false; seen.add(m); return true })
    .map((m, i) => ({ m, i, r: addrRank(parseMa(m)) }))
    .sort((a, b) => a.r - b.r || a.i - b.i)
    .map(x => x.m)
    .slice(0, 16)
}

// what may go into an invite / a peers list: no loopback, no link-local
const invitable = addrs => (addrs || []).filter(m => { const p = parseMa(m); return !!p && !isLocalOnly(p.host) })

// classify a set of local addresses so we can explain why hosting will fail
function classifyAddrs(addrs) {
  const ps = (addrs || []).map(parseMa).filter(Boolean)
  const v6 = ps.filter(p => p.kind === 'ip6' && isGlobal6(p.host))
  const pub4 = ps.filter(p => p.kind === 'ip4' && isPublic4(p.host))
  const dns = ps.filter(p => p.kind === 'dns')
  const cgnat4 = ps.filter(p => p.kind === 'ip4' && isCgnat4(p.host))
  const priv4 = ps.filter(p => p.kind === 'ip4' && net.isIPv4(p.host) && !isPublic4(p.host) && !isCgnat4(p.host) && p.host !== '127.0.0.1')
  return { v6, pub4, dns, cgnat4, priv4, dialable: v6.length + pub4.length + dns.length > 0 }
}

// ---------- invite ----------
let JOIN = null
const makeInvite = o => {
  const j = JSON.stringify({ v: 1, n: o.name, k: o.key, a: o.addrs, h: o.host, p: o.port, i: o.id })
  const sum = crypto.createHash('sha256').update(j).digest().subarray(0, 4).toString('base64url')
  return 'c3://' + Buffer.from(j).toString('base64url') + '.' + sum
}
const readInvite = tok => {
  const m = /^c3:\/\/([A-Za-z0-9_-]{16,16384})\.([A-Za-z0-9_-]{6})$/.exec(String(tok || '').trim())
  if (!m) return null
  let j, o
  try { j = Buffer.from(m[1], 'base64url').toString('utf8'); o = JSON.parse(j) } catch { return null }
  if (crypto.createHash('sha256').update(j).digest().subarray(0, 4).toString('base64url') !== m[2]) return null
  if (o?.v !== 1 || typeof o.n !== 'string' || !o.n || o.n.length > 64) return null
  if (typeof o.k !== 'string' || o.k.length < 8 || o.k.length > 512) return null
  if (typeof o.h !== 'string' || !o.h || o.h.length > 255) return null
  const port = Number(o.p)
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null
  if (!/^[0-9a-f]{16}$/.test(String(o.i || ''))) return null
  const ma = toMa(o.h, port, o.i)
  if (!parseMa(ma)) return null
  const addrs = []
  if (Array.isArray(o.a)) {
    for (const raw of o.a.slice(0, 16)) {
      const p = parseMa(raw)
      if (p && p.id === o.i) addrs.push(toMa(p.host, p.port, o.i))
    }
  }
  return { name: o.n, key: o.k, host: o.h, port, id: o.i, ma, addrs }
}
const pickHost = addrs => {
  const list = (addrs || []).map(parseMa).filter(Boolean)
  let best = null
  for (const p of list) if (!best || addrRank(p) < addrRank(best)) best = p
  return best
}

// ---------- wire ----------
const T_AUTH = 1, T_AUTH_OK = 2, T_HELLO = 3, T_VECTOR = 4, T_UPDATE = 5, T_ADDRS = 6, T_PING = 7
const MAX_FILE = 16 << 20
const MAX_UPDATE = 32 << 20
const MAX_FRAME = 2 << 20
const CHUNK = 32 << 10          // was 1200: ~27x fewer frames, seals, and syscalls
const UDP_MAX = 1200            // only small frames go over UDP (no IP fragmentation)
const MAX_CONNS = 64, MAX_CONNS_PER_IP = 8
const MAX_DIAL = 8
const HANDSHAKE_MS = 8000
const MAGIC = Buffer.from('C3PU')

const frame = (type, payload) => {
  const p = payload || Buffer.alloc(0)
  const h = Buffer.allocUnsafe(5)
  h.writeUInt32BE(p.length + 1, 0); h[4] = type
  return Buffer.concat([h, p])
}
const sealBody = (key, type, payload) => {
  const iv = crypto.randomBytes(12)
  const c = crypto.createCipheriv('aes-256-gcm', key, iv)
  c.setAAD(Buffer.from([type]))
  const ct = Buffer.concat([c.update(payload || Buffer.alloc(0)), c.final()])
  return Buffer.concat([iv, ct, c.getAuthTag()])
}
const unseal = (key, type, body) => {
  if (body.length < 28) throw new Error('short frame')
  const d = crypto.createDecipheriv('aes-256-gcm', key, body.subarray(0, 12))
  d.setAAD(Buffer.from([type]))
  d.setAuthTag(body.subarray(body.length - 16))
  return Buffer.concat([d.update(body.subarray(12, body.length - 16)), d.final()])
}

// ---------- mesh ----------
class Mesh {
  constructor(ident, { port, psk, advertise, lanOnly, allIfaces }) {
    this.id = ident.id
    this.peerId = { toString: () => this.id }
    this.wantPort = port
    this.port = 0
    this.psk = psk
    this.advertise = advertise
    this.lanOnly = !!lanOnly
    this.allIfaces = !!allIfaces
    this.conns = new Set()
    this.events = new Map()
    this.stopped = false
    this.punchCtr = crypto.randomBytes(4).readUInt32BE(0)
    this.targets = new Map()
    this.peerAddr = new Map()
    this.punchedAt = new Map()
    this.replied = new Map()
    this.tags = new Map()
    this.connIP = new Map()
    this.cid = 0
  }
  on(t, fn) {
    if (!this.events.has(t)) this.events.set(t, new Set())
    this.events.get(t).add(fn)
    return () => this.events.get(t)?.delete(fn)
  }
  addEventListener(t, fn) { this.on(t, fn) }
  removeEventListener(t, fn) { this.events.get(t)?.delete(fn) }
  emit(t, detail) { for (const fn of this.events.get(t) || []) try { fn({ detail }) } catch (e) { dbg('[mesh] handler', e?.message) } }
  peerIds() { const s = new Set(); for (const c of this.conns) if (c.ready && c.peerId) s.add(c.peerId); return s }
  peerCount() { return this.peerIds().size }
  getConnections() { return [...this.conns].filter(c => c.ready).map(c => ({ remotePeer: { toString: () => c.peerId } })) }
  // recomputed on every call: temporary IPv6 and network switches must not go stale
  addrs() {
    const out = []
    const adv = String(this.advertise || '').trim()
    if (adv) {
      const m = adv.match(/^(?:\[([^\]]+)\]|([^:/]+)):(\d+)$/)
      if (m && Number(m[3]) > 0) out.push(toMa(m[1] || m[2], Number(m[3]), this.id))
    }
    out.push(...lanAddrs(this.id, this.port, { allIfaces: this.allIfaces }))
    const seen = new Set()
    let list = out.filter(m => {
      if (!parseMa(m) || seen.has(m)) return false
      seen.add(m)
      return true
    })
    if (this.lanOnly) list = list.filter(m => !isDialable(parseMa(m)))
    return list
      .map((m, i) => ({ m, i, r: addrRank(parseMa(m)) }))
      .sort((a, b) => a.r - b.r || a.i - b.i)
      .map(x => x.m)
      .slice(0, 16)
  }

  async start() {
    this.server = net.createServer(s => this.accept(s))
    const listen = p => new Promise((res, rej) => {
      const onErr = e => { this.server.off('error', onErr); rej(e) }
      this.server.once('error', onErr)
      this.server.listen(p, () => { this.server.off('error', onErr); res() })
    })
    try { await listen(this.wantPort) } catch { dbg('[mesh] listen failed on', this.wantPort); await listen(0) }
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
      this.udpTimer = setInterval(() => this.tick(), 1000)
      this.udpTimer.unref?.()
    } catch { this.udp = null }
    dbg('[mesh] listening', this.port, 'udp', this.udp ? 'on' : 'off', 'id', this.id)
  }
  async stop() {
    this.stopped = true
    clearInterval(this.udpTimer)
    try { this.server?.close() } catch {}
    try { this.udp?.close() } catch {}
    for (const c of [...this.conns]) this.drop(c)
  }

  // --- connection plumbing ---
  accept(sock) {
    const ip = sock.remoteAddress || '?'
    if (this.conns.size >= MAX_CONNS || (this.connIP.get(ip) || 0) >= MAX_CONNS_PER_IP) {
      try { sock.destroy() } catch {}
      return
    }
    this.connIP.set(ip, (this.connIP.get(ip) || 0) + 1)
    const c = this.newConn(sock, null)
    c.dir = 'in'                      // responder: wait for the initiator's T_AUTH
    c.timer = setTimeout(() => this.kill(c), HANDSHAKE_MS)
    c.timer.unref?.()
  }
  newConn(sock, hp) {
    const c = {
      id: ++this.cid, sock, hp, dir: 'out', state: 'auth', rx: null, tx: null, tag: null,
      ecdh: null, nonce: null, peerId: null, ready: false, udp: null, udpTs: 0, cands: [],
      rbuf: null, off: 0, timer: null, ip: sock ? sock.remoteAddress : null, t: 0
    }
    if (sock) {
      sock.setNoDelay?.(true); sock.setKeepAlive?.(true, 10000)
      sock.on('data', d => this.feed(c, d))
      sock.on('close', () => this.drop(c))
      sock.on('error', () => {})
    }
    this.conns.add(c)
    return c
  }
  kill(c) { try { c.sock?.destroy() } catch {} this.drop(c) }
  drop(c) {
    const was = c.ready, pid = c.peerId
    c.ready = false
    clearTimeout(c.timer); c.timer = null
    if (c.tag) this.tags.delete(c.tag.toString('hex'))
    if (c.ip) { const n = (this.connIP.get(c.ip) || 1) - 1; n > 0 ? this.connIP.set(c.ip, n) : this.connIP.delete(c.ip) }
    this.conns.delete(c)
    try { c.sock?.destroy() } catch {}
    if (was && pid && ![...this.conns].some(o => o.ready && o.peerId === pid)) this.emit('peer:disconnect', pid)
  }
  // offset cursor instead of Buffer.concat per data event: no O(n^2) on big frames
  feed(c, d) {
    const prev = c.rbuf
    if (!prev || c.off >= prev.length) { c.rbuf = d; c.off = 0 }
    else { c.rbuf = Buffer.concat([prev.subarray(c.off), d]); c.off = 0 }
    const b = c.rbuf
    while (b.length - c.off >= 4) {
      const len = b.readUInt32BE(c.off)
      if (len < 1 || len > MAX_FRAME) return this.kill(c)
      if (b.length - c.off < 4 + len) break
      const type = b[c.off + 4]
      try { this.onFrame(c, type, b.subarray(c.off + 5, c.off + 4 + len)) }
      catch (e) { dbg('[mesh] frame', e?.message); return this.kill(c) }
      c.off += 4 + len
    }
    if (c.off >= b.length) { c.rbuf = null; c.off = 0 }
  }

  // --- handshake (ECDH over psk, per-direction keys) ---
  proof(mode, pub, nonce) {
    const mac = crypto.createHmac('sha256', this.psk)
      .update(Buffer.concat([Buffer.from('c3auth\0'), Buffer.from([mode]), pub, nonce])).digest()
    return Buffer.concat([Buffer.from([mode]), pub, nonce, mac])
  }
  derive(c, peerPub, peerNonce, saltParts) {
    const shared = c.ecdh.computeSecret(peerPub)
    const salt = crypto.createHash('sha256').update(Buffer.concat(saltParts)).digest()
    const a = Buffer.from(crypto.hkdfSync('sha256', shared, salt, Buffer.from('c3conn-a'), 32))
    const b = Buffer.from(crypto.hkdfSync('sha256', shared, salt, Buffer.from('c3conn-b'), 32))
    c.tx = c.dir === 'out' ? a : b
    c.rx = c.dir === 'out' ? b : a
    c.tag = crypto.createHash('sha256').update(Buffer.concat([Buffer.from('c3udp\0'), a, b])).digest().subarray(0, 8)
    this.tags.set(c.tag.toString('hex'), c)
  }
  startDial(c) {
    c.ecdh = crypto.createECDH('prime256v1')
    c.ecdh.generateKeys()
    c.nonce = crypto.randomBytes(16)
    try { c.sock.write(frame(T_AUTH, this.proof(1, c.ecdh.getPublicKey(), c.nonce))) } catch { this.kill(c) }
  }
  onAuth(c, p) {
    if (c.state !== 'auth' || c.dir !== 'in' || p.length !== 114 || p[0] !== 1) throw new Error('auth')
    const pub = p.subarray(1, 66), nonce = p.subarray(66, 82), mac = p.subarray(82, 114)
    const exp = crypto.createHmac('sha256', this.psk)
      .update(Buffer.concat([Buffer.from('c3auth\0'), Buffer.from([1]), pub, nonce])).digest()
    if (!crypto.timingSafeEqual(mac, exp)) throw new Error('bad proof')
    c.ecdh = crypto.createECDH('prime256v1'); c.ecdh.generateKeys()
    c.nonce = crypto.randomBytes(16)
    this.derive(c, pub, nonce, [pub, c.ecdh.getPublicKey(), nonce, c.nonce])
    const ok = crypto.createHmac('sha256', this.psk)
      .update(Buffer.concat([Buffer.from('c3ok\0'), c.ecdh.getPublicKey(), c.nonce])).digest()
    c.state = 'hello'
    c.sock.write(frame(T_AUTH_OK, Buffer.concat([c.ecdh.getPublicKey(), c.nonce, ok])))
    if (c.timer) { clearTimeout(c.timer); c.timer = setTimeout(() => this.kill(c), HANDSHAKE_MS); c.timer.unref?.() }
    this.sendHello(c)
  }
  onAuthOk(c, p) {
    if (c.state !== 'auth' || c.dir !== 'out' || p.length !== 113) throw new Error('auth ok')
    const pub = p.subarray(0, 65), nonce = p.subarray(65, 81), mac = p.subarray(81, 113)
    const exp = crypto.createHmac('sha256', this.psk)
      .update(Buffer.concat([Buffer.from('c3ok\0'), pub, nonce])).digest()
    if (!crypto.timingSafeEqual(mac, exp)) throw new Error('bad ok')
    this.derive(c, pub, nonce, [c.ecdh.getPublicKey(), pub, c.nonce, nonce])
    c.state = 'hello'
    this.sendHello(c)
  }
  sendHello(c) {
    const h = JSON.stringify({ id: this.id, addrs: this.addrs() })
    try { c.sock.write(frame(T_HELLO, sealBody(c.tx, T_HELLO, Buffer.from(h)))) } catch { this.kill(c) }
  }
  onFrame(c, type, body) {
    if (type === T_AUTH) return this.onAuth(c, body)
    if (type === T_AUTH_OK) return this.onAuthOk(c, body)
    if (!c.rx) throw new Error('unauth')
    const plain = unseal(c.rx, type, body)
    if (c.state === 'hello') {
      if (type !== T_HELLO) throw new Error('expected hello')
      let h
      try { h = JSON.parse(plain.toString('utf8')) } catch { throw new Error('bad hello') }
      if (!h || typeof h.id !== 'string' || !/^[0-9a-f]{16}$/.test(h.id) || h.id === this.id) throw new Error('bad id')
      if (c.hp?.id && h.id !== c.hp.id) throw new Error('peer id mismatch')

      // two peers dialling each other at once: keep one live connection
      const dup = [...this.conns].find(o => o !== c && o.ready && o.peerId === h.id)
      if (dup) {
        const [keep, dropit] = dup.id < c.id ? [dup, c] : [c, dup]
        if (dropit === c) return this.kill(c)
        this.drop(dropit)
      }

      c.peerId = h.id
      c.state = 'ready'
      c.ready = true
      clearTimeout(c.timer); c.timer = null
      if (Array.isArray(h.addrs)) {
        this.learnAddrs(h.id, h.addrs)
        c.cands = h.addrs.slice(0, 8).map(parseMa)
          .filter(a => a && a.id === h.id && !isLocalOnly(a.host) && a.kind === 'ip4')
          .map(a => ({ host: a.host, port: a.port }))
      }
      this.emit('peer:connect', h.id)
      return
    }
    if (!c.ready) throw new Error('not ready')
    if (type === T_PING) return
    if (type === T_VECTOR || type === T_UPDATE || type === T_ADDRS) return this.emit('message', { conn: c, type, payload: plain })
    throw new Error('bad type')
  }
  learnAddrs(id, list) {
    let n = 0
    for (const raw of list.slice(0, 16)) {
      const a = parseMa(raw)
      if (!a || a.id !== id || a.id === this.id) continue
      if (isLocalOnly(a.host)) continue
      const k = a.host + ':' + a.port
      this.peerAddr.set(k, id)
      if (a.kind === 'ip4') this.targets.set(k, { host: a.host, port: a.port })   // punching is v4 only
      if (++n >= 8) break
    }
    while (this.targets.size > 32) this.targets.delete(this.targets.keys().next().value)
  }
  async dial(ma) {
    const a = parseMa(ma)
    if (!a || a.id === this.id || this.stopped) return false
    for (const c of this.conns) if (c.hp && c.hp.host === a.host && c.hp.port === a.port) return true
    this.peerAddr.set(a.host + ':' + a.port, a.id)
    if (a.kind === 'ip4') this.targets.set(a.host + ':' + a.port, { host: a.host, port: a.port })
    return new Promise(res => {
      let done = false
      const sock = net.connect({ host: a.host, port: a.port })
      const finish = ok => { if (!done) { done = true; res(ok) } }
      sock.setTimeout(6000, () => { try { sock.destroy() } catch {}; finish(false) })
      sock.once('connect', () => {
        sock.setTimeout(0)
        const c = this.newConn(sock, a)
        c.timer = setTimeout(() => this.kill(c), HANDSHAKE_MS); c.timer.unref?.()
        this.startDial(c)
        finish(true)
      })
      sock.once('error', () => { try { sock.destroy() } catch {}; finish(false) })
    })
  }

  // --- udp fast path (only after TCP auth, ipv4 only) ---
  punch(host, port) {
    if (!this.udp || this.stopped || !net.isIPv4(host)) return
    const b = Buffer.allocUnsafe(24)
    MAGIC.copy(b, 0)
    b.writeUInt32BE(this.punchCtr = (this.punchCtr + 1) >>> 0, 4)
    crypto.createHmac('sha256', this.psk).update(b.subarray(0, 8)).digest().subarray(0, 16).copy(b, 8)
    try { this.udp.send(b, port, host, () => {}) } catch {}
  }
  validPunch(d) {
    if (d.length !== 24 || d.toString('ascii', 0, 4) !== 'C3PU') return false
    const mac = crypto.createHmac('sha256', this.psk).update(d.subarray(0, 8)).digest().subarray(0, 16)
    return crypto.timingSafeEqual(mac, d.subarray(8, 24))
  }
  onUdp(d, r) {
    const now = Date.now()
    if (this.validPunch(d)) {
      const k = r.address + ':' + r.port
      this.punchedAt.set(k, now)
      if (!this.replied.has(k) || now - this.replied.get(k) > 500) {
        this.replied.set(k, now)
        this.punch(r.address, r.port)      // reply only to a proven session member
      }
      if (this.replied.size > 512) this.replied.clear()
      return
    }
    if (d.length < 6) return
    const len = d.readUInt32BE(0)
    if (len !== d.length - 4 || len < 1 + 8 + 28) return
    const type = d[4]
    if (type < T_HELLO || type > T_PING) return
    const c = this.tags.get(d.subarray(5, 13).toString('hex'))
    if (!c || !c.ready) return                  // no tag, no state, no reply
    let plain
    try { plain = unseal(c.rx, type, d.subarray(13)) } catch { return }
    const k = r.address + ':' + r.port
    if (c.udp && (c.udp.host !== r.address || c.udp.port !== r.port)) return
    if (!c.udp) { c.udp = { host: r.address, port: r.port }; dbg('[mesh] udp path', k) }
    c.udpTs = now
    if (type === T_PING) return
    if (type === T_VECTOR || type === T_UPDATE || type === T_ADDRS) this.emit('message', { conn: c, type, payload: plain })
  }
  tick() {
    if (this.stopped) return
    const now = Date.now()
    for (const t of this.targets.values()) this.punch(t.host, t.port)
    for (const [k, ts] of this.punchedAt) if (now - ts > 60000) this.punchedAt.delete(k)
    for (const c of this.conns) {
      if (!c.ready) continue
      if (c.udp && now - c.udpTs > 15000) c.udp = null
      if (c.udp || !this.udp || now - c.t < 2000) continue
      c.t = now
      const body = sealBody(c.tx, T_PING, Buffer.alloc(0))
      const f = frame(T_PING, Buffer.concat([c.tag, body]))
      for (const t of c.cands) { try { this.udp.send(f, t.port, t.host, () => {}) } catch {} }
    }
  }

  sendAll(type, payload, skip) {
    for (const c of this.conns) {
      if (!c.ready || c === skip) continue
      let body
      try { body = sealBody(c.tx, type, payload) } catch { continue }
      const f = frame(type, body)
      if (c.sock && !c.sock.destroyed) { try { c.sock.write(f) } catch {} }
      if (c.udp && this.udp && f.length <= UDP_MAX) {
        try { this.udp.send(frame(type, Buffer.concat([c.tag, body])), c.udp.port, c.udp.host, () => {}) } catch {}
      }
    }
  }
  // one seal per chunk, one socket.write for the whole update
  sendChunks(payloads, skip) {
    const single = payloads.length === 1
    for (const c of this.conns) {
      if (!c.ready || c === skip) continue
      const frames = []
      let total = 0
      for (const p of payloads) {
        let body
        try { body = sealBody(c.tx, T_UPDATE, p) } catch { continue }
        const f = frame(T_UPDATE, body)
        frames.push(f); total += f.length
        if (single && c.udp && this.udp && f.length <= UDP_MAX) {
          try { this.udp.send(frame(T_UPDATE, Buffer.concat([c.tag, body])), c.udp.port, c.udp.host, () => {}) } catch {}
        }
      }
      if (!total || !c.sock || c.sock.destroyed) continue
      try { c.sock.write(frames.length === 1 ? frames[0] : Buffer.concat(frames, total)) } catch {}
    }
  }
}

// ---------- document + mirror ----------
const doc = new Y.Doc()
const files = doc.getMap('files')
const texts = doc.getMap('texts')
const blobs = doc.getMap('blobs')
const touched = new Set()
const idToPath = new Map()
const lastWritten = new Map()
const diskMeta = new Map()
const pendingWrites = new Map()
const missing = new Map()
const remote = tx => tx.origin !== 'disk' && tx.origin !== 'restore'
const asBuf = u => Buffer.from(u.buffer, u.byteOffset, u.byteLength)
let backend = null

const DEFAULT_IGNORE = ['.git', '.c3', 'node_modules', 'dist', 'build', 'out', '.env*', '*.pem', 'id_rsa*', '*.log', '.DS_Store', 'Thumbs.db', 'desktop.ini', '*.tmp', '*.tmp-*']
let customRules = []
function loadIgnores() {
  let lines = []
  try { lines = fs.readFileSync(path.join(SESSION_DIR, 'ignore'), 'utf8').split(/\r?\n/) } catch {}
  customRules = [...DEFAULT_IGNORE, ...lines.map(l => l.trim()).filter(l => l && !l.startsWith('#'))]
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
}
function shouldIgnore(rel) {
  if (!rel) return false
  rel = rel.split(path.sep).join('/')
  if (rel === '.git' || rel.startsWith('.git/')) return true
  if (rel === '.c3' || rel.startsWith('.c3/')) return true
  if (c3Inside && (rel === c3Rel || rel.startsWith(c3Rel + '/'))) return true
  if (backend?.excluded && (rel === backend.excluded || rel.startsWith(backend.excluded + '/'))) return true
  return customRules.some(re => re.test(rel))
}

// path safety: every mutation, including deletes, goes through this
function inside(abs) { return abs === ROOT || abs.startsWith(ROOT + path.sep) }
function symlinkEscape(abs) {
  let cur = ROOT
  for (const part of path.relative(ROOT, abs).split(path.sep)) {
    cur = path.join(cur, part)
    let st
    try { st = fs.lstatSync(cur) } catch { return false }
    if (st.isSymbolicLink()) return true
  }
  return false
}
function safeAbs(rel) {
  if (typeof rel !== 'string' || !rel || rel.length > 512 || rel.includes('\0')) return null
  const abs = path.resolve(ROOT, rel)
  if (!inside(abs) || abs === ROOT) return null
  const norm = path.relative(ROOT, abs).split(path.sep).join('/')
  if (norm !== rel.split(path.sep).join('/')) return null
  return { abs, norm }
}
function dropFile(rel) {
  const s = safeAbs(rel)
  if (!s || symlinkEscape(s.abs)) return
  try { fs.unlinkSync(s.abs) } catch {}
}

// tree listing: one git process per scan, never one per file
function walkFs() {
  const out = []
  const walk = (abs, rel) => {
    let ents
    try { ents = fs.readdirSync(abs, { withFileTypes: true }) } catch { return }
    for (const e of ents) {
      if (out.length > 50000) return
      const r = rel ? rel + '/' + e.name : e.name
      if (shouldIgnore(r)) continue
      if (e.isDirectory()) walk(path.join(abs, e.name), r)
      else if (e.isFile()) out.push(r)
    }
  }
  walk(ROOT, '')
  return out
}
function walkTree() {
  if (backend?.kind === 'git') {
    let out
    try { out = execFileSync('git', ['ls-files', '-z', '-co', '--exclude-standard'], { cwd: ROOT, encoding: 'buffer', maxBuffer: 1 << 28, timeout: GIT_TIMEOUT, env }) } catch { return walkFs() }
    return out.toString('utf8').split('\0').filter(Boolean).filter(rel => !shouldIgnore(rel)).slice(0, 50000)
  }
  return walkFs()
}

const isHi = c => c >= 0xd800 && c <= 0xdbff
function applyDiff(t, next) {
  const cur = t.toString()
  if (cur === next) return false
  let s = 0
  while (s < cur.length && s < next.length && cur.charCodeAt(s) === next.charCodeAt(s)) s++
  if (s > 0 && isHi(cur.charCodeAt(s - 1))) s--
  let e = 0
  while (e < cur.length - s && e < next.length - s &&
    cur.charCodeAt(cur.length - 1 - e) === next.charCodeAt(next.length - 1 - e)) e++
  if (e > 0 && isHi(cur.charCodeAt(cur.length - e - 1))) e--
  if (cur.length - s - e > 0) t.delete(s, cur.length - s - e)
  if (next.length - s - e > 0) t.insert(s, next.slice(s, next.length - e))
  return true
}
function syncFromDisk(rel, seed = false) {
  const norm = safeAbs(rel)?.norm
  if (!norm || shouldIgnore(norm)) return
  let data
  try { data = fs.readFileSync(path.join(ROOT, norm)) } catch { return }
  if (data.length > MAX_FILE) return
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
      if (!cur || Buffer.compare(asBuf(cur), data) !== 0) { blobs.set(entry.id, new Uint8Array(data)); if (!seed) touched.add(norm) }
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
    files.delete(rel); texts.delete(entry.id); blobs.delete(entry.id)
  }, 'disk')
}
function writeToDisk(rawRel) {
  const s = safeAbs(rawRel)
  if (!s || shouldIgnore(s.norm) || symlinkEscape(s.abs)) return
  const entry = files.get(s.norm)
  if (!entry) return
  let data
  if (entry.bin) {
    const b = blobs.get(entry.id)
    if (!b) return
    data = asBuf(b)
  } else data = Buffer.from(texts.get(entry.id)?.toString() ?? '', 'utf8')
  if (data.length > MAX_FILE) return
  const abs = s.abs
  try {
    const cur = fs.readFileSync(abs)
    if (Buffer.compare(cur, data) === 0) return
  } catch {}
  let mode = 0o644
  try { mode = fs.statSync(abs).mode & 0o777 } catch {}
  try {
    fs.mkdirSync(path.dirname(abs), { recursive: true })
    atomicWrite(abs, data, mode)
    lastWritten.set(s.norm, Date.now())
    try { diskMeta.set(s.norm, sigOf(fs.statSync(abs))) } catch {}
  } catch {}
}
function scheduleWrite(rel) {
  clearTimeout(pendingWrites.get(rel))
  pendingWrites.set(rel, setTimeout(() => { pendingWrites.delete(rel); writeToDisk(rel) }, 40))
}
function flushWrites() {
  for (const [, t] of pendingWrites) clearTimeout(t)
  pendingWrites.clear()
  for (const rel of [...files.keys()]) writeToDisk(rel)
}

files.observe(ev => {
  for (const [key, change] of ev.keys) {
    const o = change.oldValue
    if (o?.id && idToPath.get(o.id) === key) idToPath.delete(o.id)
    const e = files.get(key)
    if (change.action !== 'delete' && e?.id) idToPath.set(e.id, key)
  }
  if (!remote(ev.transaction)) return
  for (const [rawRel, change] of ev.keys) {
    const s = safeAbs(rawRel)
    if (!s || shouldIgnore(s.norm)) continue
    touched.add(s.norm)
    if (change.action === 'delete') dropFile(s.norm)
    else scheduleWrite(s.norm)
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

// The session is the truth on join: delete local files it doesn't have,
// then reconcile() writes everything it does have.
function wipeLocal() {
  const keep = new Set(files.keys())
  for (const rel of walkTree()) {
    if (keep.has(rel) || shouldIgnore(rel)) continue
    dropFile(rel)
  }
}
function reconcile(prune) {
  for (const rel of [...files.keys()]) writeToDisk(rel)
  if (!prune) return
  const keep = new Set(files.keys())
  for (const rel of walkTree()) if (!keep.has(rel) && !shouldIgnore(rel)) dropFile(rel)
}
function adoptTree() {
  for (const rel of walkTree()) { try { diskMeta.set(rel, sigOf(fs.statSync(path.join(ROOT, rel)))) } catch {} }
}

// Reset the working tree to HEAD: tracked files back to their committed
// content, untracked non-ignored files removed. Ignored paths (node_modules,
// c3/, .c3/) are untouched.
function resetToHead() {
  try { git('checkout', '--', '.') } catch (e) { ui.warn('checkout failed: ' + e.message); return }
  if (gitOk('status', '--porcelain')) { try { git('clean', '-fd') } catch (e) { ui.warn('clean failed: ' + e.message) } }
}

// ---------- backend ----------
function makeBackend(config) {
  if (config.backend !== 'git') return { kind: 'none', excluded: null, prepare() {}, generation: () => 'static', save: () => ({ saved: false, reason: 'no-git' }) }
  return {
    kind: 'git', excluded: null,
    prepare() {
      gitOk('fetch')
      if (gitOk('rev-parse', '--abbrev-ref', 'HEAD') === 'HEAD')
        for (const b of ['main', 'master'])
          if (gitOk('rev-parse', '--verify', '--quiet', 'refs/heads/' + b)) { try { git('checkout', b); break } catch {} }
    },
    generation: () => gitOk('rev-parse', 'HEAD') ?? 'no-head',
    save(paths, meta) {
      const list = [...paths]
      for (let i = 0; i < list.length; i += 500) {
        try { git('add', '-A', '--', ...list.slice(i, i + 500)) } catch (e) { return { saved: false, reason: 'add-failed: ' + e.message } }
      }
      if (gitOk('status', '--porcelain') === '') return { saved: false, reason: 'clean' }
      const idc = gitOk('config', 'user.name') && gitOk('config', 'user.email') ? [] : ['-c', 'user.name=c3', '-c', 'user.email=c3@localhost']
      try { git(...idc, 'commit', '-m', meta.message) } catch (e) { return { saved: false, reason: 'commit-failed: ' + e.message } }
      try { git('push'); return { saved: true, pushed: true } } catch {}
      try {
        gitOk('fetch'); git('merge', '-X', 'ours', '--no-edit', '@{u}')
      } catch {
        try { gitOk('merge', '--abort') } catch {}
        if (config.forcePush === true && has('force-push')) {
          try { git('push', '--force'); return { saved: true, pushed: true, forced: true } } catch {}
        }
        return { saved: true, pushed: false }
      }
      try { git('push'); return { saved: true, pushed: true } } catch { return { saved: true, pushed: false } }
    }
  }
}

// ---------- sync ----------
function sync(mesh, doc, onAddrs) {
  const parts = new Map()
  const seen = new Set()
  let liveBytes = 0
  const sendVec = () => mesh.sendAll(T_VECTOR, Buffer.from(Y.encodeStateVector(doc)))
  const sendAddrs = () => {
    const peers = []
    for (const c of mesh.conns) {
      if (!c.ready || !c.peerId) continue
      const a = (c.cands || []).map(t => toMa(t.host, t.port, c.peerId)).slice(0, 4)
      if (a.length) peers.push(a)
      if (peers.length >= 8) break
    }
    mesh.sendAll(T_ADDRS, Buffer.from(JSON.stringify({ self: mesh.addrs(), peers })))
  }
  const sendUpd = u => {
    const data = Buffer.from(u)
    if (!data.length || data.length > MAX_UPDATE) return
    const id = crypto.createHash('sha1').update(data).digest().subarray(0, 8)
    const n = Math.max(1, Math.ceil(data.length / CHUNK))
    if (n > 65535) return
    const out = []
    for (let i = 0; i < n; i++) {
      const h = Buffer.allocUnsafe(13)
      h[0] = T_UPDATE; id.copy(h, 1); h.writeUInt16BE(i, 9); h.writeUInt16BE(n, 11)
      out.push(Buffer.concat([h, data.subarray(i * CHUNK, (i + 1) * CHUNK)]))
    }
    mesh.sendChunks(out)
  }
  const dropStale = () => {
    const now = Date.now()
    for (const [id, p] of parts) if (now - p.ts > 60000) { liveBytes -= p.bytes; parts.delete(id) }
  }
  mesh.on('message', ev => {
    const { type, payload } = ev.detail || {}
    if (!payload) return
    if (type === T_VECTOR) {
      const d = Y.encodeStateAsUpdate(doc, payload)
      if (d.length > 2) sendUpd(d)
      return
    }
    if (type === T_ADDRS) {
      let a
      try { a = JSON.parse(payload.toString('utf8')) } catch { return }
      const out = []
      if (Array.isArray(a)) out.push(...a)
      else if (a && typeof a === 'object') {
        if (Array.isArray(a.self)) out.push(...a.self)
        if (Array.isArray(a.peers)) for (const g of a.peers) if (Array.isArray(g)) out.push(...g)
      }
      onAddrs(out.slice(0, 32))
      return
    }
    if (type !== T_UPDATE || payload.length < 15) return
    const id = payload.subarray(1, 9).toString('hex')
    const i = payload.readUInt16BE(9), n = payload.readUInt16BE(11)
    if (n < 1 || i >= n || n > 65535) return
    dropStale()
    let p = parts.get(id)
    if (!p) {
      if (parts.size >= 64) return
      p = { n, got: 0, ch: new Array(n), ts: 0, bytes: 0 }
      parts.set(id, p)
    }
    if (p.n !== n || p.ch[i]) return
    const c = Buffer.from(payload.subarray(13))
    p.ch[i] = c; p.got++; p.bytes += c.length; p.ts = Date.now()
    liveBytes += c.length
    if (liveBytes > 64 << 20) { parts.clear(); liveBytes = 0; return }
    if (p.got !== p.n) return
    parts.delete(id); liveBytes -= p.bytes
    const full = Buffer.concat(p.ch)
    if (full.length < 2 || full.length > MAX_UPDATE) return
    const digest = crypto.createHash('sha1').update(full).digest().subarray(0, 8).toString('hex')
    if (digest !== id) return                              // integrity, as designed
    if (seen.has(digest)) return
    seen.add(digest); if (seen.size > 4096) seen.clear()
    try { Y.applyUpdate(doc, full, 'remote') } catch {}
  })
  mesh.on('peer:connect', () => { sendVec(); sendAddrs() })
  mesh.on('peer:disconnect', () => { parts.clear(); liveBytes = 0 })
  doc.on('update', (u, origin) => { if (origin !== 'remote' && origin !== 'restore') sendUpd(u) })
  const t = setInterval(() => { sendVec(); sendAddrs() }, 8000)
  t.unref?.()
  sendVec(); sendAddrs()
}

// ---------- connect ----------
async function connect() {
  const cfg0 = readConfig() ?? {}
  const dir = chooseRoot()
  setRoot(dir)
  const ident = loadIdentity()
  const name = JOIN?.name ?? flag('name') ?? cfg0.name ?? path.basename(ROOT)
  const sdir = sdirOf(name)
  if (flag('key')) die('Use the invite line or C3_KEY (argv is visible in ps).')
  let sKey = JOIN?.key ?? process.env.C3_KEY ?? readKey(sdir)
  const fresh = !sKey
  if (!sKey) sKey = crypto.randomBytes(32).toString('base64url')
  if (fresh || JOIN) writeKey(sdir, sKey)
  const wantPort = Number(flag('port') ?? cfg0.port ?? 8443)
  if (!Number.isInteger(wantPort) || wantPort < 0 || wantPort > 65535) die('Bad port.')
  const advertise = String(flag('advertise') ?? cfg0.advertise ?? '').trim()
  const psk = crypto.createHash('sha256').update('c3psk\0').update(name).update('\0').update(sKey).digest()
  const mesh = new Mesh(ident, {
    port: wantPort, psk, advertise,
    lanOnly: has('lan-only'),
    allIfaces: has('all-ifaces') || cfg0.allIfaces === true
  })

  // --- host-side reachability check, before anything is dialled ---
  const claimed = !!advertise
  const selfAddrs = mesh.addrs()
  const cls = classifyAddrs(selfAddrs)
  if (!JOIN && !cls.dialable && !claimed) {
    ui.warn('this machine cannot host a cross-network session')
    for (const p of cls.cgnat4) console.error(`    /ip4/${p.host}   carrier-grade NAT (outbound only)`)
    for (const p of cls.priv4) {
      const why = hotspotLike(p.host) ? 'phone hotspot subnet (private)' : 'private address (same LAN only)'
      console.error(`    /ip4/${p.host}   ${why}`)
    }
    if (!cls.cgnat4.length && !cls.priv4.length) console.error('    (no non-loopback addresses at all)')
    console.error('  a peer on another network cannot dial any of these: it will hang and')
    console.error('  then fail after 45s. start the session from the peer that has a global')
    console.error('  IPv6 or a public IPv4 address, or keep both peers on the same network.')
    console.error('  (this is fine if both peers really are on the same LAN.)')
  } else if (!JOIN && claimed && !cls.dialable) {
    ui.say(`advertising ${advertise} -- assuming it is reachable from outside`)
  }

  // --- joiner-side: is this invite even worth dialling? ---
  if (JOIN) {
    const hostAddrs = JOIN.addrs.length ? JOIN.addrs : [JOIN.ma]
    if (!classifyAddrs(hostAddrs).dialable) {
      ui.warn('this invite carries no globally routable address')
      console.error('  the host looks like it is on a LAN, a phone hotspot, or behind NAT,')
      console.error('  so it is only reachable from the same network. if you are on another')
      console.error('  network, the host must start from a machine with global IPv6 or a')
      console.error('  public IPv4. killing this after 45s of retries either way.')
    }
  }

  await mesh.start()
  const port = mesh.port
  const kind = cfg0.backend === 'git' || cfg0.backend === 'none'
    ? cfg0.backend
    : (fs.existsSync(path.join(ROOT, '.git')) ? 'git' : 'none')
  const cfg = { ...cfg0, name, port, backend: kind }      // dir is per-run, never stored
  delete cfg.dir
  if (advertise) cfg.advertise = advertise
  else delete cfg.advertise
  atomicWrite(CONFIG_FILE, JSON.stringify(cfg, null, 2), 0o600)
  loadIgnores()
  backend = makeBackend(cfg)
  backend.prepare()
  const me = { name: gitOk('config', 'user.name') ?? (os.userInfo().username || 'peer') }
  const prune = has('prune')

  // A joiner starts from the peer's state, never from its own leftovers.
  if (JOIN) {
    for (const f of ['state.bin', 'state.gen', 'oplog']) { try { fs.rmSync(path.join(sdir, f), { force: true }) } catch {} }
  }

  // Starter: the repo is the trunk. Reset the working tree to HEAD before
  // seeding, so first-run state is always "whatever is committed".
  if (!JOIN && kind === 'git') {
    ui.set('resetting to repo...')
    resetToHead()
  }

  // --- peer bookkeeping: ranked, deduped, capped ---
  const peers = new Set()
  const savePeers = () => {
    const arr = [...peers].map((a, i) => ({ a, i, p: parseMa(a) })).filter(x => x.p)
    arr.sort((x, y) => addrRank(x.p) - addrRank(y.p) || x.i - y.i)
    const out = []
    const seen = new Set()
    for (const x of arr) {
      const k = x.p.host + ':' + x.p.port
      if (seen.has(k)) continue
      seen.add(k)
      out.push(x.a)
      if (out.length >= 64) break
    }
    peers.clear()
    for (const a of out) peers.add(a)
    writePeers(sdir, out)
  }
  const addPeer = a => {
    if (typeof a !== 'string' || a.length > 500) return false
    const p = parseMa(a)
    if (!p || p.id === mesh.id || isLocalOnly(p.host)) return false
    if (peers.has(a)) return false
    peers.add(a)
    savePeers()
    return true
  }
  for (const a of readPeers(sdir)) addPeer(a)
  if (JOIN?.ma) { peers.add(JOIN.ma); savePeers() }   // primary target may be loopback (two repos, one machine)
  if (JOIN) for (const m of JOIN.addrs) addPeer(m)    // siblings: loopback / link-local dropped
  if (flag('peer')) addPeer(flag('peer'))

  let leaving = false
  const dialPeers = () => {
    if (leaving) return
    for (const a of readPeers(sdir)) addPeer(a)
    const live = mesh.peerIds()
    const list = []
    let i = 0
    for (const a of peers) {
      const p = parseMa(a)
      if (!p || p.id === mesh.id || live.has(p.id)) continue
      list.push({ a, i: i++, r: addrRank(p) })
    }
    // best 8 by rank, not the 8 oldest: virtual/private candidates must not crowd
    // out the global IPv6 one after a few sessions have piled up in peers.json
    list.sort((x, y) => x.r - y.r || x.i - y.i)
    for (const x of list.slice(0, MAX_DIAL)) mesh.dial(x.a).catch(() => {})
  }
  const waitFor = async (ms, cond) => {
    const until = Date.now() + ms
    while (Date.now() < until) { if (cond()) return true; await sleep(200) }
    return cond()
  }

  // state
  const stateFile = path.join(sdir, 'state.bin')
  const genFile = path.join(sdir, 'state.gen')
  const logFile = path.join(sdir, 'oplog')
  const appendLog = u => { try { const h = Buffer.allocUnsafe(4); h.writeUInt32BE(u.length, 0); fs.appendFileSync(logFile, Buffer.concat([h, Buffer.from(u)])) } catch {} }
  const snapshotNow = () => { try { atomicWrite(stateFile, Y.encodeStateAsUpdate(doc), 0o600); atomicWrite(genFile, backend.generation(), 0o600); fs.rmSync(logFile, { force: true }) } catch {} }
  const scheduleSnapshot = () => { clearTimeout(snapTimer); snapTimer = setTimeout(snapshotNow, 5000) }
  const removeState = () => { for (const f of [stateFile, genFile, logFile]) { try { fs.rmSync(f, { force: true }) } catch {} } }
  function restoreState() {
    if (!fs.existsSync(stateFile)) return false
    try {
      const g = fs.existsSync(genFile) ? fs.readFileSync(genFile, 'utf8').trim() : null
      if (g && g !== backend.generation()) { removeState(); return false }
      Y.applyUpdate(doc, fs.readFileSync(stateFile), 'restore')
      if (fs.existsSync(logFile)) {
        const b = fs.readFileSync(logFile)
        let off = 0
        while (off + 4 <= b.length) {
          const len = b.readUInt32BE(off); off += 4
          if (len < 1 || len > MAX_FRAME || off + len > b.length) break
          try { Y.applyUpdate(doc, b.subarray(off, off + len), 'restore') } catch {}
          off += len
        }
      }
      return true
    } catch { removeState(); return false }
  }
  const restored = restoreState()
  if (restored && kind === 'git' && !JOIN) {
    // resumed state older than HEAD: this machine has been reset underneath,
    // so what is on disk is not what the session thinks it is.
    const g = fs.existsSync(genFile) ? fs.readFileSync(genFile, 'utf8').trim() : null
    if (g && g !== backend.generation()) {
      ui.warn('local state is older than HEAD -- run `node c3.js join <invite>` to resync,')
      ui.warn('or delete c3/.c3 and start over')
    }
  }
  sync(mesh, doc, addrs => { for (const a of addrs) addPeer(a); dialPeers() })
  doc.on('update', (u, origin) => { if (origin === 'restore') return; appendLog(u); scheduleSnapshot() })

  // scan
  function scan() {
    try {
      const list = walkTree()
      const present = new Set(list)
      const now = Date.now()
      for (const rel of list) {
        if (pendingWrites.has(rel) || (lastWritten.get(rel) ?? 0) > now - 1500) continue
        let st
        try { st = fs.statSync(path.join(ROOT, rel)) } catch { continue }
        if (!st.isFile()) continue
        const sig = sigOf(st)
        if (diskMeta.get(rel) === sig) continue
        diskMeta.set(rel, sig)
        syncFromDisk(rel)
      }
      for (const rel of [...files.keys()]) {
        if (present.has(rel)) { missing.delete(rel); continue }
        if (shouldIgnore(rel) || pendingWrites.has(rel)) continue
        if ((lastWritten.get(rel) ?? 0) > now - 3000) continue
        const n = (missing.get(rel) || 0) + 1
        if (n < 2) { missing.set(rel, n); continue }        // two strikes: ~16s
        missing.delete(rel)
        removeFromDoc(rel)
      }
    } catch {}
  }
  function quick(rel) {
    if (!rel) return
    const s = safeAbs(rel)
    if (!s || shouldIgnore(s.norm)) return
    const now = Date.now()
    if (pendingWrites.has(s.norm) || (lastWritten.get(s.norm) ?? 0) > now - 500) return
    let st
    try { st = fs.statSync(s.abs) } catch { return }        // transient; scan decides deletions
    if (!st.isFile()) return
    const sig = sigOf(st)
    if (diskMeta.get(s.norm) === sig) return
    diskMeta.set(s.norm, sig)
    syncFromDisk(s.norm)
  }
  let started = false, watcher = null
  function startScan() {
    if (started) return
    started = true
    scan()
    try {
      watcher = fs.watch(ROOT, { recursive: true }, (_e, f) => { if (f) quick(String(f).split(path.sep).join('/')) })
      watcher.on('error', () => {})
    } catch { ui.warn('instant watching unavailable -- polling only') }
    scanTimer = setInterval(scan, 8000)
  }
  function seedFromDisk() {
    const seed = walkTree()
    let bytes = 0
    for (const rel of seed) { try { bytes += fs.statSync(path.join(ROOT, rel)).size } catch {} }
    if (seed.length > 10000 || bytes > 200 << 20) die(`Refusing to seed ${seed.length} files / ${(bytes / 1e6).toFixed(0)} MB. Use --dir on a smaller tree.`)
    doc.transact(() => { for (const rel of seed) syncFromDisk(rel, true) }, 'disk')
    startScan()
  }

  async function confirmSave(n) {
    if (has('yes')) return true
    if (!process.stdin.isTTY) return false
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
    const a = (await rl.question(`Publish ${n} changed path(s) to archive? [y/N] `)).trim().toLowerCase()
    rl.close(); return a === 'y' || a === 'yes'
  }
  let snapTimer = null, scanTimer = null, tick = null, dialTimer = null, addrsTimer = null
  async function leave() {
    if (leaving) return
    leaving = true
    for (const t of [scanTimer, snapTimer, tick, dialTimer, addrsTimer]) { clearInterval(t); clearTimeout(t) }
    try { watcher?.close() } catch {}
    flushWrites(); snapshotNow(); ui.clear()
    try {
      if (mesh.peerCount() > 0) {
        ui.say('others still in session -- keeping local state, not publishing')
      } else {
        const all = new Set(walkTree())
        for (const rel of touched) all.add(rel)
        const staged = backend.kind === 'git'
          ? gitOk('status', '--porcelain') ?? ''
          : ''
        const n = Math.max(all.size, staged ? staged.split('\n').length : 0)
        if (!(await confirmSave(n))) ui.say('skipped publishing')
        else {
          const r = backend.save(all, { user: me.name, message: `Session snapshot ${new Date().toISOString()}` })
          if (r.saved === false) {
            if (r.reason === 'no-git') ui.say(`nothing to publish: no git repo in ${ROOT}`)
            else if (r.reason === 'clean') ui.say('nothing changed (already committed)')
            else ui.warn('publish failed: ' + (r.reason || 'unknown'))
            removeState()
          } else if (r.pushed === false) ui.warn('could not push -- commit kept locally')
          else { removeState(); ui.say(r.forced ? 'saved and pushed (force)' : 'saved and pushed') }
        }
      }
    } catch (e) { console.error('Save failed:', e.message) }
    finally { try { await mesh.stop() } catch {}; process.exit(0) }
  }

  mesh.addEventListener('peer:connect', ev => {
    ui.say(`peer ${String(ev.detail ?? '').slice(0, 8)} connected`)
    dialPeers()
  })
  mesh.addEventListener('peer:disconnect', () => ui.set(`live -- ${mesh.peerCount()} peer(s)`))

  // --- live address set: re-read on a timer so a rotated IPv6 is not stale ---
  const addrsFile = path.join(sdir, 'addrs.json')
  let myAddrs = mesh.addrs()
  const writeAddrs = () => {
    try { atomicWrite(addrsFile, JSON.stringify({ id: mesh.id, addrs: myAddrs, port }), 0o600) } catch {}
  }
  const refreshAddrs = () => {
    const next = mesh.addrs()
    if (next.join('|') === myAddrs.join('|')) return false
    const was = invitable(myAddrs).join('|')
    myAddrs = next
    writeAddrs()
    if (invitable(next).join('|') !== was) {
      ui.warn('network address changed -- any invite already printed is stale')
      ui.say('run `node c3.js share` in another terminal for a fresh invite')
    }
    return true
  }

  ui.say(`root ${ROOT}${flag('dir') ? ' (--dir)' : ''} -- ${kind}`)
  dialPeers(); dialTimer = setInterval(dialPeers, 10000)
  ui.set(JOIN ? 'connecting...' : 'starting...')
  if (JOIN) await waitFor(45000, () => files.size > 0)
  else await sleep(2500)

  const had = files.size
  if (had > 0) {
    if (JOIN) wipeLocal()          // joining: the session wins
    adoptTree()
    reconcile(prune)
  } else if (JOIN) {
    ui.warn('joined but received no state from the peer in 45s')
    ui.warn('the peer must stay running until your file count matches theirs')
    ui.say('leaving without touching local files')
    try { await mesh.stop() } catch {}
    process.exit(1)
  } else seedFromDisk()
  if (!started) startScan()

  writeAddrs()
  addrsTimer = setInterval(refreshAddrs, 5000)
  if (had > 0) ui.say(`${restored ? 'resumed' : 'joined'} "${name}" -- ${files.size} files -- ${mesh.peerCount()} peer(s) -- ${kind}`)
  else ui.say(`started "${name}" -- ${files.size} files -- ${kind}`)

  const host = pickHost(invitable(myAddrs))
  if (host) {
    console.log('')
    console.log('  invite -- paste this into the other terminal:')
    console.log('')
    console.log('  node c3.js join ' + makeInvite({ name, key: sKey, addrs: invitable(myAddrs), host: host.host, port: host.port, id: mesh.id }))
    console.log('')
  } else if (!JOIN) {
    ui.warn('no address to put in an invite -- see the reachability warning above')
  }

  tick = setInterval(() => {
    const p = mesh.peerCount()
    ui.set(`live -- ${p} peer${p === 1 ? '' : 's'} -- ${files.size} files -- ${kind}`)
  }, 2000)
  process.on('SIGINT', leave); process.on('SIGTERM', leave)
}

// ---------- join / share / peer ----------
async function joinCmd() {
  const inv = readInvite(argv[1] ?? flag('invite'))
  if (!inv) die('Bad invite. Paste the whole line: node c3.js join c3://...')
  JOIN = inv
  await connect()
}
function shareCmd() {
  const cfg = readConfig() ?? die('No session yet -- run `node c3.js` first.')
  const sdir = sdirOf(cfg.name)
  const key = readKey(sdir) ?? die('No key -- run `node c3.js` first.')
  const me = loadIdentity().id
  let addrs = []
  try { addrs = JSON.parse(fs.readFileSync(path.join(sdir, 'addrs.json'), 'utf8')).addrs ?? [] } catch {}
  addrs = addrs.map(parseMa).filter(p => p && p.id === me).map(p => toMa(p.host, p.port, me))
  if (!addrs.length) addrs = lanAddrs(me, Number(cfg.port || 8443), { allIfaces: has('all-ifaces') })
  const usable = invitable(addrs)
  const host = pickHost(usable)
  if (!host) die('No reachable address. Run with --advertise <host:port>.')
  const cls = classifyAddrs(usable)
  if (!cls.dialable) ui.warn('this invite is LAN-only -- cross-network peers cannot dial it')
  ui.clear()
  console.log('\n  node c3.js join ' + makeInvite({ name: cfg.name, key, addrs: usable, host: host.host, port: host.port, id: me }) + '\n')
}
function peerCmd() {
  const cfg = readConfig() ?? die('No config.')
  const ma = String(argv[1] || '').trim()
  if (!parseMa(ma)) die('usage: node c3.js peer "/ip4/10.0.0.5/tcp/8443/p2p/<16 hex>"')
  const sdir = sdirOf(cfg.name)
  const list = readPeers(sdir)
  if (!list.includes(ma)) list.push(ma)
  writePeers(sdir, list)
  ui.say('peer added')
}

// ---------- config ----------
async function configCmd() {
  const dir = chooseRoot()
  setRoot(dir)
  const isGit = fs.existsSync(path.join(ROOT, '.git'))
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  const ask = async (q, def) => {
    if (!process.stdin.isTTY) return def
    const a = (await rl.question(`? ${q}${def ? ` [${def}]` : ''} `)).trim()
    return a || def
  }
  ui.clear(); console.log(`c3 config -- ${ROOT}`)
  const picked = await ask('Backend  1) git  2) none  Pick 1/2', isGit ? '1' : '2')
  const kind = picked === '1' && isGit ? 'git' : 'none'
  const port = Number(flag('port') ?? await ask('Listening TCP/UDP port', '8443'))
  if (!Number.isInteger(port) || port < 1 || port > 65535) die('Bad port.')
  const advertise = String(flag('advertise') ?? await ask('Reachable host:port (blank = LAN only)', '')).trim()
  const cfg = { ...(readConfig() ?? {}), backend: kind, port }
  delete cfg.dir
  if (advertise) cfg.advertise = advertise
  else delete cfg.advertise
  atomicWrite(CONFIG_FILE, JSON.stringify(cfg, null, 2), 0o600)
  if (kind === 'git') {
    const ex = path.join(ROOT, '.git', 'info', 'exclude')
    mkdirp(path.dirname(ex))
    const cur = fs.existsSync(ex) ? fs.readFileSync(ex, 'utf8') : ''
    if (!cur.split('\n').includes('.c3/')) fs.appendFileSync(ex, '\n.c3/\n')
  }
  rl.close(); ui.clear()
  console.log(`Config written: ${CONFIG_FILE}`)
}

// ---------- dispatch ----------
const usage = `usage: node c3.js [command]
  (no command)      resume this directory's session, or start one
  join <c3://...>   adopt a session (use this for first contact)
  share             print the invite line again
  config            change port / backend / advertise
  peer <ma>         add a peer address manually
Flags: --dir <p>  --port <n>  --advertise <host:port>  --lan-only  --all-ifaces
       --prune  --yes  --force-push
`
if (cmd === 'join') await joinCmd()
else if (cmd === 'share') shareCmd()
else if (cmd === 'config') await configCmd()
else if (cmd === 'peer') peerCmd()
else if (cmd === undefined || cmd === 'connect') await connect()
else die(usage)
