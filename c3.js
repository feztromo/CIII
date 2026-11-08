#!/usr/bin/env node
// c3 -- P2P live file session, single file. Node 22+, `yjs` is the only dependency.
// Layout: repo/ (ROOT), repo/c3/ (this file), repo/c3/.c3/ (state).
//
// Transport: raw TCP for LAN/IPv6, plus WebSocket so an HTTP tunnel can carry the
// same frames. One port: the listener sniffs "GET " and upgrades, else raw c3.
// Hosting: if no local address is dialable, c3 offers LAN / Cloudflare / public.
// Only the host needs cloudflared.
import * as Y from 'yjs'
import readline from 'node:readline/promises'
import { execFile, execFileSync, spawn } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import net from 'node:net'
import tls from 'node:tls'
import dgram from 'node:dgram'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'

// ---------- cli ----------
const argv = process.argv.slice(2), cmd = argv[0]
const flag = n => {
  const i = argv.indexOf('--' + n)
  if (i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--')) return argv[i + 1]
  const e = argv.find(a => a.startsWith('--' + n + '='))
  return e ? e.slice(n.length + 3) : undefined
}
const has = n => argv.includes('--' + n)
const IS_WIN = process.platform === 'win32'
const COLOR = !!process.stdout.isTTY && !process.env.NO_COLOR
const cl = (s, code) => COLOR ? `\x1b[${code}m${s}\x1b[0m` : String(s)
const cyan = s => cl(s, '96')
const dcyan = s => cl(s, '38;5;30')
const yellow = s => cl(s, '93')
const red = s => cl(s, '91')
const dim = s => cl(s, '2')
const cap = s => String(s).replace(/^(\s*)([a-z])/, (_, w, c) => w + c.toUpperCase())
const ui = {
  msg: '', active: false, live: false, frame: 0, timer: null, dots: false, hold: false, done: false, wake: 0, curFace: null, specialHold: -1, tty: !!process.stdout.isTTY,
  render() {
    if (!this.tty || this.hold || this.done) return
    const sleepF = ['(-.-) z  ', '(-.-) Zz ', '(-.-) zZz', '(-.-)  zZ', '(-.-)   z', '(-.-)    ', '(-,-)    ', '(-,-)    ']
    const happy = '(^.' + '^)'
    // awake face picker: 90% standard every 1s, 10% special holds 2s.
    const stdPool = ['(o.o)', '(o.o)', '(O.o)', '(o.O)', '(O.O)']
    const rndPool = [
      '(-.-)', '(OwO)', '(^-^)', '(>.<)', '(oWo)',
      '(o_0)', '(^_^)', '(^o^)', '(-_-)', '(^.^)',
      '(@_@)', '(UwU)', '(~_~)', '(Uwu)', '(T_T)',
      '(*.*)', '(Q_Q)', '(Q.Q)', '(0_o)', '(x_x)',
      '(X.X)', '(>.>)', '(<.<)', '(+.+)', '(>w<)',
      '(^w^)', '(o3o)', '(-w-)', '(=.=)', '(;w;)',
    ]
    const pickWake = () => {
      const pool = Math.random() < 0.85 ? stdPool : rndPool
      return pool[Math.floor(Math.random() * pool.length)]
    }
    const face = this.active
      ? (Date.now() < this.wake ? happy
        : this.frame < this.specialHold ? this.curFace
        : (this.curFace = pickWake(),
           this.specialHold = rndPool.includes(this.curFace) ? this.frame + 3 : this.frame + 2,
           this.curFace))
      : this.live ? sleepF[this.frame % sleepF.length]
      : ''
    const tail = this.dots ? '.'.repeat((this.frame % 3) + 1) : ''
    const parts = [cyan('* c3')]
    if (face) parts.push(face)
    if (this.msg || tail) parts.push(this.msg + tail)
    process.stdout.write('\r\x1b[K' + parts.join(' '))
  },
  set(m, o = {}) { this.msg = cap(m); this.dots = !!o.dots; if (!this.done) this.render() },
  setActive(v) {
    const was = this.active
    this.active = !!v
    if (!was && this.active) { this.curFace = null; this.specialHold = -1 }
    this.render()
  },
  idle() { this.msg = ''; this.dots = false },
  start() { if (!this.timer) this.timer = setInterval(() => { if (COLOR) { this.frame++; this.render() } }, 500) },
  stop() { clearInterval(this.timer); this.timer = null },
  clear() { if (this.tty) process.stdout.write('\r\x1b[K') },
  say(...a) { this.idle(); this.clear(); if (typeof a[0] === 'string') a[0] = cap(a[0]); console.log(cyan('* c3'), ...a); if (!this.done) this.render() },
  warn(...a) { this.idle(); this.clear(); if (typeof a[0] === 'string') a[0] = cap(a[0]); console.error(yellow('! warning'), ...a); if (!this.done) this.render() },
  err(...a) { this.idle(); this.clear(); if (typeof a[0] === 'string') a[0] = cap(a[0]); console.error(red('! error'), ...a); if (!this.done) this.render() }
}
const dbg = (...a) => { if (process.env.C3_DEBUG) console.error(...a) }
const die = m => { console.error(red('! error'), cap(m)); process.exit(1) }
const sleep = ms => new Promise(r => setTimeout(r, ms))
const mkdirp = (d, m) => { try { fs.mkdirSync(d, { recursive: true, mode: m }) } catch { } }
const atomicWrite = (f, d, mode = 0o600) => {
  const t = f + '.tmp-' + process.pid + '-' + crypto.randomBytes(4).toString('hex')
  try { fs.writeFileSync(t, d, { mode }); fs.renameSync(t, f) }
  catch (e) { try { fs.rmSync(t, { force: true }) } catch { }; throw e }
  try { fs.chmodSync(f, mode) } catch { }
}
const sigOf = st => st.mtimeMs + ':' + st.size
const env = { ...process.env, GIT_TERMINAL_PROMPT: '0' }
const GIT_TIMEOUT = 120000
// Autosave interval: retries dirty file writes and delays the full state snapshot.
// Incremental updates are appended to the oplog immediately, so 0 is still crash-safe.
const AUTOSAVE_MS = (() => {
  const v = flag('autosave')
  if (v === undefined) return 1000
  const s = Number(v)
  if (!Number.isFinite(s) || s < 0 || s > 3600) die('Bad --autosave: use seconds (0 disables).')
  return s === 0 ? 0 : Math.max(100, Math.round(s * 1000))
})()
const git = (...a) => execFileSync('git', a, { cwd: ROOT, encoding: 'utf8', maxBuffer: 1 << 28, timeout: GIT_TIMEOUT, env, stdio: 'pipe' }).trim()
const gitOk = (...a) => { try { return git(...a) } catch { return null } }

// ---------- paths ----------
const c3Dir = path.dirname(fileURLToPath(import.meta.url))
const SESSION_DIR = path.join(c3Dir, '.c3')
const CONFIG_FILE = path.join(SESSION_DIR, 'config.json')
let ROOT = null, c3Rel = null, c3Inside = false
const readConfig = () => { try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) } catch { return null } }
const sdirOf = n => {
  const d = path.join(SESSION_DIR, 's', crypto.createHash('sha256').update('c3sid\0' + n).digest().toString('hex').slice(0, 32))
  mkdirp(d, 0o700); try { fs.chmodSync(d, 0o700) } catch { }; return d
}
const readKey = s => { try { return fs.readFileSync(path.join(s, 'key'), 'utf8').trim() } catch { return null } }
const writeKey = (s, k) => atomicWrite(path.join(s, 'key'), k, 0o600)
const peersFile = s => path.join(s, 'peers.json')
const readPeers = s => {
  try {
    const a = JSON.parse(fs.readFileSync(peersFile(s), 'utf8'))
    return Array.isArray(a) ? a.filter(x => typeof x === 'string' && x.length < 500).slice(0, 64) : []
  } catch { return [] }
}
const writePeers = (s, a) => atomicWrite(peersFile(s), JSON.stringify(a.slice(0, 64), null, 2), 0o600)
const chooseRoot = () => flag('dir') ?? path.resolve(c3Dir, '..')

function setRoot(dir) {
  let real
  try { real = fs.realpathSync(path.resolve(String(dir))) } catch { die('Directory not found: ' + dir) }
  if (!fs.statSync(real).isDirectory()) die('Not a directory: ' + real)
  if (real === path.parse(real).root) die('Refusing to use the filesystem root. Pass --dir <project>.')
  let home = os.homedir(); try { home = fs.realpathSync(home) } catch { }
  if (real === home) die('Refusing to sync your home directory.')
  if (home.startsWith(real + path.sep)) die('Refusing to sync a directory that contains your home directory.')
  ROOT = real
  const r = path.relative(ROOT, c3Dir)
  c3Inside = !!r && !r.startsWith('..') && !path.isAbsolute(r)
  c3Rel = c3Inside ? r.split(path.sep).join('/') : null
  mkdirp(SESSION_DIR, 0o700)
}
function loadIdentity() {
  mkdirp(SESSION_DIR, 0o700)
  const f = path.join(SESSION_DIR, 'identity.json')
  try { const j = JSON.parse(fs.readFileSync(f, 'utf8')); if (/^[0-9a-f]{16}$/.test(j.id)) return j } catch { }
  const j = { id: crypto.randomBytes(8).toString('hex') }
  atomicWrite(f, JSON.stringify(j), 0o600); return j
}

// ---------- addresses ----------
const bare = h => String(h ?? '').trim().replace(/^\[/, '').replace(/\]$/, '')
const zap = h => bare(h).split('%')[0]
const isLoop = h => { const a = zap(h); return a === '::1' || a === '::' || a === '0.0.0.0' || /^127\./.test(a) || /^::ffff:127\./.test(a.toLowerCase()) }
const isLocal = h => {
  const a = zap(h), l = a.toLowerCase()
  if (net.isIPv4(a)) return /^(0\.|127\.|169\.254\.|22[4-9]\.|2[3-5]\d\.|255\.)/.test(a)
  if (!net.isIPv6(a)) return false
  return l === '::' || l === '::1' || l === '0:0:0:0:0:0:0:1' || /^fe[89ab]/.test(l) || /^ff/.test(l) || /^::ffff:/.test(l)
}
const isGlobal6 = h => { const a = zap(h); return net.isIPv6(a) && !isLocal(a) && !/^f[cd]/.test(a.toLowerCase()) }
const isCgnat = h => { const a = zap(h); if (!net.isIPv4(a)) return false; const [x, y] = a.split('.').map(Number); return x === 100 && y >= 64 && y <= 127 }
const isPublic4 = h => {
  const a = zap(h), [x, y] = a.split('.').map(Number)
  return net.isIPv4(a) && x !== 0 && x !== 10 && x !== 127 && !(x === 172 && y >= 16 && y <= 31) &&
    !(x === 192 && y === 168) && !(x === 169 && y === 254) && !isCgnat(a) && x < 224
}
const hotspotLike = h => /^(172\.20\.1[01]\.|192\.168\.4[23]\.|192\.168\.137\.|10\.42\.0\.)/.test(bare(h))
const isVirt = n => /^(vethernet|vmware|virtualbox|vboxnet|docker|br-|veth|virbr|podman|cni|flannel|cali|kube|hyper-v|npcap|loopback|zt|tailscale|wg\d|tun\d|tap\d|utun|awdl|llw|anpi|bridge\d)/i.test(String(n || ''))

const toMa = (h, p, id) => {
  const a = bare(h), v = zap(h), k = net.isIPv6(v) ? 'ip6' : net.isIPv4(v) ? 'ip4' : 'dns'
  return `/${k}/${a}/tcp/${p}/p2p/${id}`
}
const wssMa = (h, id) => `/wss/${h}/tcp/443/p2p/${id}`
const maStr = p => `/${p.kind}/${p.host}/tcp/${p.port}/p2p/${p.id}`
const parseMa = s => {
  const m = String(s || '').match(/^\/(ip4|ip6|dns|wss)\/([^/]{1,255})\/tcp\/(\d{1,5})\/p2p\/([0-9a-f]{16})$/)
  if (!m) return null
  const kind = m[1], host = bare(m[2]), port = +m[3]
  if (port < 1 || port > 65535) return null
  if (kind === 'ip4' && !net.isIPv4(zap(host))) return null
  if (kind === 'ip6' && !net.isIPv6(zap(host))) return null
  if ((kind === 'dns' || kind === 'wss') && !/^[a-z0-9]([a-z0-9.-]{0,252}[a-z0-9])?$/i.test(host)) return null
  return { kind, host, port, id: m[4] }
}
const rank = p => !p ? 9
  : p.kind === 'ip6' ? (isGlobal6(p.host) ? 0 : 3)
    : p.kind === 'wss' || p.kind === 'dns' ? 1
      : p.kind === 'ip4' ? (isPublic4(p.host) ? 1 : p.host === '127.0.0.1' ? 8 : 2) : 4
const dialable = p => !!p && (isGlobal6(p.host) || isPublic4(p.host) || p.kind === 'dns' || p.kind === 'wss')

function lanAddrs(id, port, all) {
  const out = []
  if (!port) return out
  for (const [name, list] of Object.entries(os.networkInterfaces())) {
    if (!all && isVirt(name)) continue
    for (const i of list || []) {
      const a = bare(i?.address || '')
      if (!a || i.internal || isLocal(a)) continue
      if (net.isIPv6(a) && !isGlobal6(a)) continue
      if (!net.isIPv4(a) && !net.isIPv6(a)) continue
      out.push(toMa(a, port, id))
    }
  }
  out.push(toMa('127.0.0.1', port, id))
  return [...new Set(out)]
}
const inviteOk = a => a.filter(m => { const p = parseMa(m); return p && !isLocal(p.host) })
function classify(a) {
  const p = a.map(parseMa).filter(Boolean)
  return {
    cgnat4: p.filter(x => x.kind === 'ip4' && isCgnat(x.host)),
    priv4: p.filter(x => x.kind === 'ip4' && net.isIPv4(x.host) && !isPublic4(x.host) && !isCgnat(x.host) && x.host !== '127.0.0.1'),
    ok: p.some(dialable)
  }
}

// ---------- invite ----------
let JOIN = null
const makeInv = o => {
  const j = JSON.stringify({ v: 1, n: o.name, k: o.key, a: o.addrs, h: o.host, p: o.port, i: o.id })
  return 'c3://' + Buffer.from(j).toString('base64url') + '.' + crypto.createHash('sha256').update(j).digest().subarray(0, 4).toString('base64url')
}
const readInv = tok => {
  const m = /^c3:\/\/([A-Za-z0-9_-]{16,16384})\.([A-Za-z0-9_-]{6})$/.exec(String(tok || '').trim())
  if (!m) return null
  let j, o
  try { j = Buffer.from(m[1], 'base64url').toString('utf8'); o = JSON.parse(j) } catch { return null }
  if (crypto.createHash('sha256').update(j).digest().subarray(0, 4).toString('base64url') !== m[2]) return null
  if (o?.v !== 1 || !o.n || o.n.length > 64 || !o.k || o.k.length < 8 || o.k.length > 512 || !o.h || o.h.length > 255) return null
  const port = +o.p
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null
  if (!/^[0-9a-f]{16}$/.test(String(o.i || ''))) return null
  const addrs = []
  if (Array.isArray(o.a)) for (const r of o.a.slice(0, 16)) { const p = parseMa(r); if (p && p.id === o.i) addrs.push(maStr({ ...p, id: o.i })) }
  const ma = addrs[0] ?? toMa(o.h, port, o.i)
  if (!parseMa(ma)) return null
  return { name: o.n, key: o.k, host: o.h, port, id: o.i, ma, addrs }
}
const bestHost = a => a.map(parseMa).filter(Boolean).reduce((b, p) => !b || rank(p) < rank(b) ? p : b, null)

// ---------- wire ----------
const AUTH = 1, AUTH_OK = 2, HELLO = 3, VEC = 4, UPDATE = 5, ADDRS = 6, PING = 7
const DISC_MAGIC = Buffer.from('C3DI')
const DISC_PORT = (() => { const n = +(process.env.C3_DISC_PORT || 8444); return Number.isInteger(n) && n > 0 && n < 65536 ? n : 8444 })()
const DISC_GROUP4 = '224.0.0.251'
const DISC_GROUP6 = 'ff02::c3'
const DISC_GROUP6_ALL = 'ff02::1'
const MAX_FILE = 16 << 20, MAX_UPD = 32 << 20, MAX_FRM = 2 << 20, CHUNK = 32 << 10, UDP_MAX = 1200
const MAX_CONNS = 64, MAX_PER_IP = 8, MAX_DIAL = 8, HANDSHAKE = 8000
const MAGIC = Buffer.from('C3PU')
const frame = (t, p) => {
  const x = p || Buffer.alloc(0), h = Buffer.allocUnsafe(5)
  h.writeUInt32BE(x.length + 1, 0); h[4] = t
  return Buffer.concat([h, x])
}
const seal = (k, t, p) => {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', k, iv)
  c.setAAD(Buffer.from([t]))
  return Buffer.concat([iv, c.update(p || Buffer.alloc(0)), c.final(), c.getAuthTag()])
}
const open = (k, t, b) => {
  const d = crypto.createDecipheriv('aes-256-gcm', k, b.subarray(0, 12))
  d.setAAD(Buffer.from([t])); d.setAuthTag(b.subarray(b.length - 16))
  return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()])
}

// ---------- websocket ----------
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
function wsEncode(b, client, op = 0x2) {
  const n = b.length, base = n < 126 ? 2 : n < 65536 ? 4 : 10
  const h = Buffer.allocUnsafe(base + (client ? 4 : 0))
  h[0] = 0x80 | op
  if (n < 126) h[1] = n
  else if (n < 65536) { h[1] = 126; h.writeUInt16BE(n, 2) }
  else { h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2) }
  if (!client) return Buffer.concat([h, b])
  h[1] |= 0x80
  const mk = crypto.randomBytes(4); mk.copy(h, base)
  const out = Buffer.allocUnsafe(n)
  for (let i = 0; i < n; i++) out[i] = b[i] ^ mk[i & 3]
  return Buffer.concat([h, out])
}
function wsDecode(st, d, onMsg, onClose, sock, client) {
  st.buf = st.buf.length ? Buffer.concat([st.buf, d]) : d
  for (; ;) {
    const b = st.buf
    if (b.length < 2) return
    const fin = b[0] & 0x80, op = b[0] & 0xf, masked = b[1] & 0x80
    let len = b[1] & 0x7f, off = 2
    if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4 }
    else if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); off = 10 }
    const mo = off
    if (masked) off += 4
    if (len > MAX_FRM) { onClose(); return }
    if (b.length < off + len) return
    let p = Buffer.from(b.subarray(off, off + len))
    if (masked) { const mk = b.subarray(mo, mo + 4); for (let i = 0; i < p.length; i++) p[i] ^= mk[i & 3] }
    st.buf = b.subarray(off + len)
    if (op === 0x8) { onClose(); return }
    if (op === 0x9) { try { sock.write(wsEncode(p, client, 0xa)) } catch { } continue }
    if (op === 0xa) continue
    if (op === 0x0) { st.frag.push(p); if (fin) { const f = Buffer.concat(st.frag); st.frag = []; onMsg(f) } continue }
    if (op === 0x1 || op === 0x2) { if (fin) onMsg(p); else st.frag = [p] }
  }
}
function wsWrap(sock, client, head) {
  const h = { data: [], close: [], error: [] }
  const st = { buf: Buffer.alloc(0), frag: [] }
  const fire = (t, a) => { for (const fn of h[t].slice()) try { fn(a) } catch { } }
  const w = {
    remoteAddress: client ? 'wss' : (sock.remoteAddress || 'wss'),
    destroyed: false,
    setNoDelay() { }, setKeepAlive() { }, setTimeout() { }, ref() { }, unref() { },
    write(b) {
      if (w.destroyed || !b?.length) return false
      try { for (let i = 0; i < b.length; i += 1 << 20) sock.write(wsEncode(b.subarray(i, i + (1 << 20)), client)) } catch { return false }
      return true
    },
    destroy() { if (w.destroyed) return; w.destroyed = true; try { sock.destroy() } catch { }; fire('close') },
    on(t, fn) { (h[t] ??= []).push(fn); return w },
    once(t, fn) { const f = a => { w.removeListener(t, f); fn(a) }; return w.on(t, f) },
    removeListener(t, fn) { const a = h[t]; if (a) { const i = a.indexOf(fn); if (i > -1) a.splice(i, 1) } return w },
    off(t, fn) { return w.removeListener(t, fn) }
  }
  sock.on('data', d => wsDecode(st, d, m => fire('data', m), () => w.destroy(), sock, client))
  sock.on('close', () => { if (!w.destroyed) { w.destroyed = true; fire('close') } })
  sock.on('error', e => { fire('error', e); w.destroy() })
  if (head?.length) wsDecode(st, head, m => fire('data', m), () => w.destroy(), sock, client)
  return w
}
function wsConnect(host, port) {
  return new Promise((resolve, reject) => {
    let done = false, buf = Buffer.alloc(0)
    const fail = e => { if (done) return; done = true; try { s.destroy() } catch { }; reject(e) }
    const s = tls.connect({ host, port, servername: host })
    s.setTimeout(15000, () => fail(new Error('tls timeout')))
    s.once('error', fail)
    s.once('secureConnect', () => {
      s.setTimeout(0)
      s.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}\r\nSec-WebSocket-Version: 13\r\n\r\n`)
    })
    const onD = d => {
      if (done) return
      buf = Buffer.concat([buf, d])
      const i = buf.indexOf('\r\n\r\n')
      if (i < 0) { if (buf.length > 16384) fail(new Error('bad handshake')); return }
      const head = buf.subarray(0, i).toString('latin1')
      if (!/^HTTP\/1\.[01] 101/i.test(head) || !/sec-websocket-accept/i.test(head)) return fail(new Error('upgrade rejected'))
      s.off('data', onD); done = true
      resolve(wsWrap(s, true, buf.subarray(i + 4)))
    }
    s.on('data', onD)
  })
}

// ---------- tunnel ----------
function haveBin(c) { try { execFileSync(c, ['--version'], { stdio: 'ignore', timeout: 5000 }); return true } catch { return false } }
function findCloudflared() {
  const c = ['cloudflared']
  if (IS_WIN) {
    c.push(path.join(process.env.LOCALAPPDATA || '', 'Microsoft', 'WinGet', 'Links', 'cloudflared.exe'))
    c.push(path.join(process.env.ProgramFiles || 'C:\\Program Files', 'cloudflared', 'cloudflared.exe'))
    c.push(path.join(process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)', 'cloudflared', 'cloudflared.exe'))
    c.push(path.join(os.homedir(), 'cloudflared.exe'))
  } else c.push('/usr/local/bin/cloudflared', '/opt/homebrew/bin/cloudflared', '/usr/bin/cloudflared', path.join(os.homedir(), '.local/bin/cloudflared'))
  return c.find(x => x && haveBin(x)) || null
}
function tunnelHelp() {
  console.error('  Install cloudflared once, then re-run c3:')
  if (IS_WIN) console.error('    winget install --id Cloudflare.cloudflared')
  else if (process.platform === 'darwin') console.error('    brew install cloudflared')
  else console.error('    curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o ~/.local/bin/cloudflared && chmod +x ~/.local/bin/cloudflared')
}
function startTunnel(port, opts = {}) {
  const bin = findCloudflared()
  if (!bin) { ui.warn('Cloudflared not found'); tunnelHelp(); return Promise.resolve(null) }
  if (opts.kind === 'named') {
    const host = String(opts.host || '').trim()
    if (!host) { ui.warn('Named tunnel requires a hostname (--tunnel-host or config tunnelHost)'); return Promise.resolve(null) }
    ui.set('Starting stable Cloudflare tunnel', { dots: true })
    const args = opts.token ? ['tunnel', 'run', '--token', opts.token] : ['tunnel', 'run', opts.name || 'c3']
    const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] })
    child.stdout.on('data', () => { }); child.stderr.on('data', () => { })
    return new Promise(res => {
      let done = false
      const finish = v => { if (done) return; done = true; if (!v) try { child.kill() } catch { }; res(v) }
      child.on('error', () => finish(null)); child.on('exit', () => finish(null))
      setTimeout(() => finish({ host, child }), 3000).unref?.()
    })
  }
  ui.set('Starting Cloudflare quick tunnel', { dots: true })
  return new Promise(res => {
    let done = false, log = ''
    const child = spawn(bin, ['tunnel', '--url', `http://127.0.0.1:${port}`, '--no-autoupdate'], { stdio: ['ignore', 'pipe', 'pipe'] })
    const finish = v => { if (done) return; done = true; if (!v) try { child.kill() } catch { }; res(v) }
    const scan = d => {
      log += String(d)
      const m = /https:\/\/([a-z0-9-]+\.trycloudflare\.com)/i.exec(log)
      if (m) finish({ host: m[1], child })
      if (log.length > 65536) log = log.slice(-8192)
    }
    child.stdout.on('data', scan); child.stderr.on('data', scan)
    child.on('error', () => finish(null)); child.on('exit', () => finish(null))
    setTimeout(() => finish(null), 45000).unref?.()
  })
}

// ---------- mesh ----------
class Mesh {
  constructor(ident, o) {
    this.id = ident.id
    this.wantPort = o.port
    this.psk = o.psk
    this.ad = o.advertise
    this.tunnel = null
    this.lo = !!o.lanOnly
    this.all = !!o.allIfaces
    this.conns = new Set(); this.evt = {}; this.stop = false
    this.punchCtr = crypto.randomBytes(4).readUInt32BE(0)
    this.tgt = new Map(); this.pAt = new Map(); this.rep = new Map(); this.tags = new Map()
    this.cip = {}; this.cid = 0
    this.discTag = crypto.createHmac('sha256', this.psk).update('c3disc').digest().subarray(0, 8)
    this.disc = null; this.disc6 = null
  }
  on(t, fn) {
    (this.evt[t] ??= []).push(fn)
    return () => { const a = this.evt[t]; if (a) { const i = a.indexOf(fn); if (i > -1) a.splice(i, 1) } }
  }
  emit(t, d) { for (const fn of this.evt[t] || []) try { fn({ detail: d }) } catch { } }
  peerIds() { const s = new Set(); for (const c of this.conns) if (c.ready && c.peerId) s.add(c.peerId); return s }
  peerCount() { return this.peerIds().size }

  addrs() {
    const out = []
    if (this.tunnel) out.push(wssMa(this.tunnel, this.id))
    else {
      const a = String(this.ad || '').trim()
      if (a) { const m = a.match(/^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/); if (m) out.push(toMa(m[1] || m[2], +m[3], this.id)) }
    }
    // this.port, not wantPort: the listener may have fallen back to a random port
    out.push(...lanAddrs(this.id, this.port, this.all))
    let list = [...new Set(out)]
    if (this.lo && !this.tunnel) list = list.filter(m => !dialable(parseMa(m)))
    return list.map((m, i) => ({ m, i, r: rank(parseMa(m)) }))
      .sort((x, y) => x.r - y.r || x.i - y.i).map(x => x.m).slice(0, 16)
  }
  async start() {
    this.srv = net.createServer(s => this.accept(s))
    const listen = p => new Promise((res, rej) => { this.srv.once('error', rej); this.srv.listen(p, () => { this.srv.off('error', rej); res() }) })
    try { await listen(this.wantPort) } catch { try { await listen(0) } catch (e) { die('cannot listen: ' + e.message) } }
    this.port = this.srv.address().port
    if (this.port !== this.wantPort) ui.warn(`port ${this.wantPort} busy -- using ${this.port}`)
    this.srv.on('error', () => { })
    try {
      this.udp = dgram.createSocket({ type: 'udp4', reuseAddr: true })
      this.udp.on('message', (d, r) => this.onUdp(d, r)); this.udp.on('error', () => { })
      await new Promise((res, rej) => { this.udp.once('error', rej); this.udp.bind(this.port, () => { this.udp.off('error', rej); res() }) })
      try { this.udp.setBroadcast(true); this.udp.addMembership(DISC_GROUP4) } catch {}
      const bindDisc = async (type, group) => {
        const o = { type, reuseAddr: true }
        if (type === 'udp6') o.ipv6Only = true
        const s = dgram.createSocket(o)
        s.on('message', (d, r) => this.onDisc(d, r)); s.on('error', () => { })
        await new Promise((res, rej) => { s.once('error', rej); s.bind(DISC_PORT, () => { s.off('error', rej); res() }) })
        try { s.setBroadcast(true) } catch {}
        try { s.addMembership(group) } catch {
          if (type === 'udp6') for (const [, list] of Object.entries(os.networkInterfaces())) for (const i of list || []) if (i.family === 'IPv6') try { s.addMembership(group, i.address) } catch {}
        }
        return s
      }
      try { this.disc = await bindDisc('udp4', DISC_GROUP4) } catch { this.disc = null }
      try { this.disc6 = await bindDisc('udp6', DISC_GROUP6) } catch { this.disc6 = null }
      this.udpT = setInterval(() => this.tick(), 1000); this.udpT.unref?.()
    } catch { this.udp = null }
  }
  async stop() {
    this.stop = true; clearInterval(this.udpT)
    try { this.srv.close() } catch { }
    try { this.udp.close() } catch { }
    try { this.disc?.close() } catch { }
    try { this.disc6?.close() } catch { }
    for (const c of [...this.conns]) this.drop(c)
  }

  accept(sock) {
    const ip = sock.remoteAddress || '?'
    if (this.conns.size >= MAX_CONNS) { try { sock.destroy() } catch { }; return }
    const loop = ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1'
    if (!loop && (this.cip[ip] || 0) >= MAX_PER_IP) { try { sock.destroy() } catch { }; return }
    this.cip[ip] = (this.cip[ip] || 0) + 1
    let buf = Buffer.alloc(0)
    const onData = d => {
      buf = Buffer.concat([buf, d])
      if (buf.length >= 4 && !(buf[0] === 0x47 && buf[1] === 0x45 && buf[2] === 0x54 && buf[3] === 0x20)) {
        sock.off('data', onData)
        this.feed(this.openConn(sock), buf)
        return
      }
      if (buf.indexOf('\r\n\r\n') < 0) { if (buf.length > 16384) { try { sock.destroy() } catch { } } return }
      sock.off('data', onData); this.upgrade(sock, buf)
    }
    sock.on('data', onData); sock.once('error', () => { })
    sock.setTimeout(10000, () => { try { sock.destroy() } catch { } })
  }
  upgrade(sock, buf) {
    const i = buf.indexOf('\r\n\r\n'), head = buf.subarray(0, i).toString('latin1')
    const key = /\r\nsec-websocket-key:\s*([A-Za-z0-9+/=]+)/i.exec(head)?.[1]
    if (!key || !/upgrade:\s*websocket/i.test(head)) {
      try { sock.write('HTTP/1.1 426 Upgrade Required\r\nConnection: close\r\nContent-Length: 0\r\n\r\n') } catch { }
      try { sock.destroy() } catch { }; return
    }
    sock.setTimeout(0)
    const acc = crypto.createHash('sha1').update(key + WS_GUID).digest('base64')
    sock.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acc}\r\n\r\n`)
    this.openConn(wsWrap(sock, false, buf.subarray(i + 4))).ws = true
  }
  openConn(sock) {
    // clear the accept-side reaper: an idle 8s heartbeat must outlive it
    sock.setTimeout?.(0)
    const c = this.mkConn(sock, null)
    c.dir = 'in'
    c.t = setTimeout(() => this.kill(c), HANDSHAKE); c.t.unref?.()
    return c
  }
  mkConn(s, hp) {
    const c = {
      id: ++this.cid, sock: s, hp, dir: 'out', state: 'auth', rx: null, tx: null, tag: null,
      ecdh: null, nonce: null, peerId: null, ready: false, udp: null, udpTs: 0, cands: [],
      rb: null, off: 0, t: null, ip: s?.remoteAddress || null, time: 0, ws: false
    }
    if (s) { s.setNoDelay?.(true); s.setKeepAlive?.(true, 10000); s.on('data', d => this.feed(c, d)); s.on('close', () => this.drop(c)); s.on('error', () => { }) }
    this.conns.add(c); return c
  }
  kill(c) { try { c.sock.destroy() } catch { } this.drop(c) }
  drop(c) {
    const was = c.ready, pid = c.peerId
    c.ready = false; clearTimeout(c.t); c.t = null
    if (c.tag) delete this.tags[c.tag.toString('hex')]
    if (c.ip) { const n = (this.cip[c.ip] || 1) - 1; n > 0 ? this.cip[c.ip] = n : delete this.cip[c.ip] }
    this.conns.delete(c); try { c.sock.destroy() } catch { }
    if (was && pid && ![...this.conns].some(o => o.ready && o.peerId === pid)) this.emit('peer:disconnect', pid)
  }
  feed(c, d) {
    const prev = c.rb
    if (!prev || c.off >= prev.length) { c.rb = d; c.off = 0 }
    else { c.rb = Buffer.concat([prev.subarray(c.off), d]); c.off = 0 }
    const b = c.rb
    while (b.length - c.off >= 4) {
      const len = b.readUInt32BE(c.off)
      if (len < 1 || len > MAX_FRM) return this.kill(c)
      if (b.length - c.off < 4 + len) break
      try { this.onFrm(c, b[c.off + 4], b.subarray(c.off + 5, c.off + 4 + len)) } catch { this.kill(c); return }
      c.off += 4 + len
    }
    if (c.off >= b.length) { c.rb = null; c.off = 0 }
  }

  proof(m, pub, nonce) {
    return Buffer.concat([Buffer.from([m]), pub, nonce,
      crypto.createHmac('sha256', this.psk).update(Buffer.concat([Buffer.from('c3auth\0'), Buffer.from([m]), pub, nonce])).digest()])
  }
  derive(c, peerPub, peerNonce, sp) {
    const shared = c.ecdh.computeSecret(peerPub)
    const salt = crypto.createHash('sha256').update(Buffer.concat(sp)).digest()
    const A = Buffer.from(crypto.hkdfSync('sha256', shared, salt, Buffer.from('c3conn-a'), 32))
    const B = Buffer.from(crypto.hkdfSync('sha256', shared, salt, Buffer.from('c3conn-b'), 32))
    c.tx = c.dir === 'out' ? A : B; c.rx = c.dir === 'out' ? B : A
    c.tag = crypto.createHash('sha256').update(Buffer.concat([Buffer.from('c3udp\0'), A, B])).digest().subarray(0, 8)
    this.tags[c.tag.toString('hex')] = c
  }
  startDial(c) {
    c.ecdh = crypto.createECDH('prime256v1'); c.ecdh.generateKeys(); c.nonce = crypto.randomBytes(16)
    try { c.sock.write(frame(AUTH, this.proof(1, c.ecdh.getPublicKey(), c.nonce))) } catch { this.kill(c) }
  }
  onAuth(c, p) {
    if (c.state !== 'auth' || c.dir !== 'in' || p.length !== 114 || p[0] !== 1) throw 0
    const pub = p.subarray(1, 66), nonce = p.subarray(66, 82), mac = p.subarray(82, 114)
    if (!crypto.timingSafeEqual(mac, crypto.createHmac('sha256', this.psk).update(Buffer.concat([Buffer.from('c3auth\0'), Buffer.from([1]), pub, nonce])).digest())) throw 0
    c.ecdh = crypto.createECDH('prime256v1'); c.ecdh.generateKeys(); c.nonce = crypto.randomBytes(16)
    this.derive(c, pub, nonce, [pub, c.ecdh.getPublicKey(), nonce, c.nonce])
    c.state = 'hello'
    c.sock.write(frame(AUTH_OK, Buffer.concat([c.ecdh.getPublicKey(), c.nonce,
      crypto.createHmac('sha256', this.psk).update(Buffer.concat([Buffer.from('c3ok\0'), c.ecdh.getPublicKey(), c.nonce])).digest()])))
    clearTimeout(c.t); c.t = setTimeout(() => this.kill(c), HANDSHAKE); c.t.unref?.()
    this.sendHello(c)
  }
  onAuthOk(c, p) {
    if (c.state !== 'auth' || c.dir !== 'out' || p.length !== 113) throw 0
    const pub = p.subarray(0, 65), nonce = p.subarray(65, 81), mac = p.subarray(81, 113)
    if (!crypto.timingSafeEqual(mac, crypto.createHmac('sha256', this.psk).update(Buffer.concat([Buffer.from('c3ok\0'), pub, nonce])).digest())) throw 0
    this.derive(c, pub, nonce, [c.ecdh.getPublicKey(), pub, c.nonce, nonce])
    c.state = 'hello'; this.sendHello(c)
  }
  sendHello(c) { c.sock.write(frame(HELLO, seal(c.tx, HELLO, Buffer.from(JSON.stringify({ id: this.id, addrs: this.addrs() }))))) }
  onFrm(c, t, b) {
    if (t === AUTH) return this.onAuth(c, b)
    if (t === AUTH_OK) return this.onAuthOk(c, b)
    if (!c.rx) throw 0
    const plain = open(c.rx, t, b)
    if (c.state === 'hello') {
      if (t !== HELLO) throw 0
      let h; try { h = JSON.parse(plain.toString()) } catch { throw 0 }
      if (!h?.id || !/^[0-9a-f]{16}$/.test(h.id) || h.id === this.id) throw 0
      if (c.hp?.id && h.id !== c.hp.id) throw 0
      const dup = [...this.conns].find(o => o !== c && o.ready && o.peerId === h.id)
      if (dup) { const drop = dup.id < c.id ? c : dup; if (drop === c) return this.kill(c); this.drop(drop) }
      c.peerId = h.id; c.state = 'ready'; c.ready = true; clearTimeout(c.t); c.t = null
      if (Array.isArray(h.addrs)) {
        this.learnAddrs(h.id, h.addrs)
        c.cands = h.addrs.slice(0, 8).map(parseMa)
          .filter(a => a && a.id === h.id && !isLocal(a.host) && a.kind === 'ip4')
          .map(a => ({ host: a.host, port: a.port }))
      }
      this.emit('peer:connect', h.id); return
    }
    if (!c.ready) throw 0
    if (t === PING) return
    if (t >= VEC && t <= ADDRS) this.emit('message', { conn: c, type: t, payload: plain })
    else throw 0
  }
  learnAddrs(id, list) {
    let n = 0
    for (const raw of list.slice(0, 16)) {
      const a = parseMa(raw)
      if (!a || a.id !== id || a.id === this.id || isLocal(a.host)) continue
      if (a.kind === 'ip4') this.tgt.set(a.host + ':' + a.port, { host: a.host, port: a.port })
      if (++n >= 8) break
    }
    while (this.tgt.size > 32) this.tgt.delete(this.tgt.keys().next().value)
  }
  async dial(ma) {
    const a = parseMa(ma)
    if (!a || a.id === this.id || this.stop) return false
    if ([...this.conns].some(c => c.hp?.host === a.host && c.hp?.port === a.port)) return true
    if (a.kind === 'ip4') this.tgt.set(a.host + ':' + a.port, { host: a.host, port: a.port })
    if (a.kind === 'wss') {
      try {
        const w = await wsConnect(a.host, a.port)
        if (this.stop) { w.destroy(); return false }
        const c = this.mkConn(w, a)
        c.ws = true; c.t = setTimeout(() => this.kill(c), HANDSHAKE); c.t.unref?.()
        this.startDial(c); return true
      } catch (e) { dbg('ws dial failed', e.message); return false }
    }
    return new Promise(res => {
      let done
      const s = net.connect({ host: a.host, port: a.port })
      const fin = ok => { if (!done) { done = 1; res(ok) } }
      s.setTimeout(6000, () => { s.destroy(); fin(false) })
      s.once('connect', () => { s.setTimeout(0); const c = this.mkConn(s, a); c.t = setTimeout(() => this.kill(c), HANDSHAKE); c.t.unref?.(); this.startDial(c); fin(true) })
      s.once('error', () => { s.destroy(); fin(false) })
    })
  }
  punch(host, port) {
    if (!this.udp || this.stop || !net.isIPv4(host)) return
    const b = Buffer.allocUnsafe(24); MAGIC.copy(b, 0); b.writeUInt32BE(this.punchCtr = (this.punchCtr + 1) >>> 0, 4)
    crypto.createHmac('sha256', this.psk).update(b.subarray(0, 8)).digest().subarray(0, 16).copy(b, 8)
    try { this.udp.send(b, port, host, () => { }) } catch { }
  }
  validPunch(d) {
    if (d.length !== 24 || d.toString('ascii', 0, 4) !== 'C3PU') return false
    return crypto.timingSafeEqual(crypto.createHmac('sha256', this.psk).update(d.subarray(0, 8)).digest().subarray(0, 16), d.subarray(8, 24))
  }
  discFrame() {
    const d = Buffer.allocUnsafe(22)
    DISC_MAGIC.copy(d, 0)
    this.discTag.copy(d, 4)
    d.writeUInt16BE(this.port, 12)
    Buffer.from(this.id, 'hex').copy(d, 14)
    return d
  }
  onDisc(d, r) {
    if (d.length !== 22 || d.toString('ascii', 0, 4) !== 'C3DI') return
    if (!crypto.timingSafeEqual(d.subarray(4, 12), this.discTag)) return
    const port = d.readUInt16BE(12)
    const peerId = d.subarray(14, 22).toString('hex')
    if (peerId === this.id) return
    const host = r.address
    const ma = toMa(host, port, peerId)
    this.tgt.set(host + ':' + port, { host, port })
    this.emit('peer:discover', { ma, host, port, peerId })
    const sock = r.family === 'IPv6' ? this.disc6 : (this.disc || this.udp)
    try { sock?.send(this.discFrame(), r.port, host, () => { }) } catch { }
  }
  discover() {
    if (this.stop) return
    const d = this.discFrame()
    const v4 = (sock, port) => {
      if (!sock) return
      try { sock.setBroadcast(true) } catch { }
      try { sock.send(d, port, '255.255.255.255', () => { }) } catch { }
      try { sock.send(d, port, DISC_GROUP4, () => { }) } catch { }
    }
    if (this.disc) v4(this.disc, DISC_PORT)
    else if (this.udp) v4(this.udp, this.port)
    if (this.disc6) {
      try { this.disc6.send(d, DISC_PORT, DISC_GROUP6, () => { }) } catch { }
      try { this.disc6.send(d, DISC_PORT, DISC_GROUP6_ALL, () => { }) } catch { }
    }
  }
  onUdp(d, r) {
    const now = Date.now()
    if (d.length === 22 && d.toString('ascii', 0, 4) === 'C3DI') return this.onDisc(d, r)
    if (this.validPunch(d)) {
      const k = r.address + ':' + r.port; this.pAt.set(k, now)
      if (!this.rep.has(k) || now - this.rep.get(k) > 500) { this.rep.set(k, now); this.punch(r.address, r.port) }
      if (this.rep.size > 512) this.rep.clear(); return
    }
    if (d.length < 6) return
    const len = d.readUInt32BE(0)
    if (len !== d.length - 4 || len < 1 + 8 + 28) return
    const t = d[4]
    if (t < HELLO || t > PING) return
    const c = this.tags[d.subarray(5, 13).toString('hex')]
    if (!c || !c.ready || c.ws) return
    let plain; try { plain = open(c.rx, t, d.subarray(13)) } catch { return }
    if (c.udp && (c.udp.host !== r.address || c.udp.port !== r.port)) return
    if (!c.udp) { c.udp = { host: r.address, port: r.port }; dbg('udp path', r.address) }
    c.udpTs = now
    if (t === PING) return
    if (t >= VEC && t <= ADDRS) this.emit('message', { conn: c, type: t, payload: plain })
  }
  tick() {
    if (this.stop) return
    const now = Date.now()
    if (this.peerCount() === 0 && now % 3000 < 1100) this.discover()
    for (const t of this.tgt.values()) this.punch(t.host, t.port)
    for (const [k, ts] of this.pAt) if (now - ts > 60000) this.pAt.delete(k)
    for (const c of this.conns) {
      if (!c.ready || c.ws) continue
      if (c.udp && now - c.udpTs > 15000) c.udp = null
      if (c.udp || !this.udp || now - c.time < 2000) continue
      c.time = now
      const f = frame(PING, Buffer.concat([c.tag, seal(c.tx, PING, Buffer.alloc(0))]))
      for (const t of c.cands) try { this.udp.send(f, t.port, t.host, () => { }) } catch { }
    }
  }
  sendAll(type, payload, skip) {
    for (const c of this.conns) {
      if (!c.ready || c === skip) continue
      let body; try { body = seal(c.tx, type, payload) } catch { continue }
      const f = frame(type, body)
      if (c.sock && !c.sock.destroyed) try { c.sock.write(f) } catch { }
      if (c.udp && this.udp && !c.ws && f.length <= UDP_MAX)
        try { this.udp.send(frame(type, Buffer.concat([c.tag, body])), c.udp.port, c.udp.host, () => { }) } catch { }
    }
  }
  sendChunks(payloads, skip) {
    const single = payloads.length === 1
    for (const c of this.conns) {
      if (!c.ready || c === skip) continue
      const frames = []; let total = 0
      for (const p of payloads) {
        let body; try { body = seal(c.tx, UPDATE, p) } catch { continue }
        const f = frame(UPDATE, body); frames.push(f); total += f.length
        if (!c.ws && single && c.udp && this.udp && f.length <= UDP_MAX)
          try { this.udp.send(frame(UPDATE, Buffer.concat([c.tag, body])), c.udp.port, c.udp.host, () => { }) } catch { }
      }
      if (!total || !c.sock || c.sock.destroyed) continue
      try { c.sock.write(frames.length === 1 ? frames[0] : Buffer.concat(frames, total)) } catch { }
    }
  }
}

// ---------- document + mirror ----------
const doc = new Y.Doc()
const files = doc.getMap('files'), texts = doc.getMap('texts'), blobs = doc.getMap('blobs')
const touched = new Set(), idToPath = new Map(), lastWritten = new Map()
const diskMeta = new Map(), pendingWrites = new Map(), goneChecks = new Map()
const dirtyDocs = new Set()
const remote = tx => tx.origin !== 'disk' && tx.origin !== 'restore'
const asBuf = u => Buffer.from(u.buffer, u.byteOffset, u.byteLength)
let backend = null
const DEF_IGNORE = ['.git', '.c3', 'node_modules', 'dist', 'build', 'out', '.env*', '*.pem', 'id_rsa*', '*.log', '.DS_Store', 'Thumbs.db', 'desktop.ini', '*.tmp', '*.tmp-*']
let customRules = []
function loadIgnores() {
  let lines = []
  try { lines = fs.readFileSync(path.join(SESSION_DIR, 'ignore'), 'utf8').split(/\r?\n/) } catch { }
  customRules = [...DEF_IGNORE, ...lines.map(l => l.trim()).filter(l => l && !l.startsWith('#'))].map(p => {
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
const inside = abs => abs === ROOT || abs.startsWith(ROOT + path.sep)
function symlinkEscape(abs) {
  let cur = ROOT
  for (const part of path.relative(ROOT, abs).split(path.sep)) {
    cur = path.join(cur, part)
    let st; try { st = fs.lstatSync(cur) } catch { return false }
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
  dirtyDocs.delete(s.norm)
  try { fs.unlinkSync(s.abs) } catch { }
}
function walkFs() {
  const out = []
  const walk = (abs, rel) => {
    let ents; try { ents = fs.readdirSync(abs, { withFileTypes: true }) } catch { return }
    for (const e of ents) {
      if (out.length > 50000) return
      const r = rel ? rel + '/' + e.name : e.name
      if (shouldIgnore(r)) continue
      if (e.isDirectory()) walk(path.join(abs, e.name), r)
      else if (e.isFile()) out.push(r)
    }
  }
  walk(ROOT, ''); return out
}
function walkTree() {
  if (backend?.kind === 'git') {
    let out
    try { out = execFileSync('git', ['ls-files', '-z', '-co', '--exclude-standard'], { cwd: ROOT, encoding: 'buffer', maxBuffer: 1 << 28, timeout: GIT_TIMEOUT, env }) } catch { return walkFs() }
    return out.toString('utf8').split('\0').filter(Boolean).filter(rel => !shouldIgnore(rel)).slice(0, 50000)
  }
  return walkFs()
}
// Async variant for the background scan: keeps the event loop (and sync) responsive in large repos.
function walkTreeAsync() {
  if (backend?.kind !== 'git') return Promise.resolve(walkFs())
  return new Promise(res => {
    execFile('git', ['ls-files', '-z', '-co', '--exclude-standard'], { cwd: ROOT, encoding: 'buffer', maxBuffer: 1 << 28, timeout: GIT_TIMEOUT, env }, (err, out) => {
      if (err || !out) return res(walkFs())
      try { res(out.toString('utf8').split('\0').filter(Boolean).filter(rel => !shouldIgnore(rel)).slice(0, 50000)) } catch { res(walkFs()) }
    })
  })
}
const isHi = c => c >= 0xd800 && c <= 0xdbff
function applyDiff(t, next) {
  const cur = t.toString()
  if (cur === next) return false
  let s = 0
  while (s < cur.length && s < next.length && cur.charCodeAt(s) === next.charCodeAt(s)) s++
  if (s > 0 && isHi(cur.charCodeAt(s - 1))) s--
  let e = 0
  while (e < cur.length - s && e < next.length - s && cur.charCodeAt(cur.length - 1 - e) === next.charCodeAt(next.length - 1 - e)) e++
  if (e > 0 && isHi(cur.charCodeAt(cur.length - e - 1))) e--
  if (cur.length - s - e > 0) t.delete(s, cur.length - s - e)
  if (next.length - s - e > 0) t.insert(s, next.slice(s, next.length - e))
  return true
}
function syncFromDisk(rel, seed = false) {
  const norm = safeAbs(rel)?.norm
  if (!norm || shouldIgnore(norm)) return
  let data; try { data = fs.readFileSync(path.join(ROOT, norm)) } catch { return }
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
  dirtyDocs.delete(rel)
  doc.transact(() => {
    const entry = files.get(rel)
    if (!entry) return
    touched.add(rel); files.delete(rel); texts.delete(entry.id); blobs.delete(entry.id)
  }, 'disk')
}
// A missing path may just be an editor's atomic save (delete + rename), so confirm
// briefly before broadcasting a delete.
function noteGone(rel) {
  if (!files.has(rel) || goneChecks.has(rel)) return
  const t = setTimeout(() => {
    goneChecks.delete(rel)
    if (!files.has(rel)) return
    const s = safeAbs(rel)
    if (!s || shouldIgnore(s.norm)) return
    let st; try { st = fs.statSync(s.abs) } catch { st = null }
    if (st?.isFile()) {
      if (pendingWrites.has(s.norm)) return
      const sig = sigOf(st)
      if (diskMeta.get(s.norm) !== sig) { diskMeta.set(s.norm, sig); syncFromDisk(s.norm) }
      return
    }
    if (pendingWrites.has(s.norm)) return
    diskMeta.delete(s.norm); lastWritten.delete(s.norm)
    removeFromDoc(s.norm)
  }, 100)
  t.unref?.()
  goneChecks.set(rel, t)
}
function writeToDisk(rawRel) {
  const s = safeAbs(rawRel)
  if (!s || shouldIgnore(s.norm) || symlinkEscape(s.abs)) { dirtyDocs.delete(rawRel); return }
  const done = () => dirtyDocs.delete(s.norm)
  const entry = files.get(s.norm)
  if (!entry) { done(); return }
  let data
  if (entry.bin) {
    const b = blobs.get(entry.id)
    if (!b) { done(); return }
    data = asBuf(b)
  } else data = Buffer.from(texts.get(entry.id)?.toString() ?? '', 'utf8')
  if (data.length > MAX_FILE) { done(); return }
  const abs = s.abs
  try { const cur = fs.readFileSync(abs); if (Buffer.compare(cur, data) === 0) { done(); return } } catch { }
  let mode = 0o644; try { mode = fs.statSync(abs).mode & 0o777 } catch { }
  try {
    fs.mkdirSync(path.dirname(abs), { recursive: true })
    atomicWrite(abs, data, mode)
    lastWritten.set(s.norm, Date.now())
    try { diskMeta.set(s.norm, sigOf(fs.statSync(abs))) } catch { }
    done()
  } catch { }
}
function scheduleWrite(rel) {
  dirtyDocs.add(rel)
  clearTimeout(pendingWrites.get(rel))
  pendingWrites.set(rel, setTimeout(() => { pendingWrites.delete(rel); writeToDisk(rel) }, 40))
}
function flushWrites() {
  for (const [, t] of pendingWrites) clearTimeout(t)
  pendingWrites.clear()
  for (const rel of [...files.keys()]) writeToDisk(rel)
  dirtyDocs.clear()
}
files.observe(ev => {
  for (const [k, change] of ev.keys) {
    const o = change.oldValue
    if (o?.id && idToPath.get(o.id) === k) idToPath.delete(o.id)
    const e = files.get(k)
    if (change.action !== 'delete' && e?.id) idToPath.set(e.id, k)
  }
  if (!remote(ev.transaction)) return
  for (const [rawRel, change] of ev.keys) {
    const s = safeAbs(rawRel)
    if (!s || shouldIgnore(s.norm)) continue
    touched.add(s.norm)
    change.action === 'delete' ? dropFile(s.norm) : scheduleWrite(s.norm)
  }
})
const onContent = evs => {
  if (!remote(evs[0].transaction)) return
  for (const ev of evs) {
    const ids = (ev.target === texts || ev.target === blobs) ? [...ev.keys.keys()] : [ev.path[0]]
    for (const id of ids) { const p = idToPath.get(id); if (p) { touched.add(p); scheduleWrite(p) } }
  }
}
texts.observeDeep(onContent)
blobs.observeDeep(onContent)
function wipeLocal() {
  const keep = new Set(files.keys())
  for (const rel of walkTree()) { if (keep.has(rel) || shouldIgnore(rel)) continue; dropFile(rel) }
}
function reconcile(prune) {
  for (const rel of [...files.keys()]) writeToDisk(rel)
  if (!prune) return
  const keep = new Set(files.keys())
  for (const rel of walkTree()) if (!keep.has(rel) && !shouldIgnore(rel)) dropFile(rel)
}
function adoptTree() {
  for (const rel of walkTree()) try { diskMeta.set(rel, sigOf(fs.statSync(path.join(ROOT, rel)))) } catch { }
}
function resetToHead() {
  try { git('checkout', '--', '.') } catch (e) { ui.warn('checkout failed: ' + e.message); return }
  if (gitOk('status', '--porcelain')) try { git('clean', '-fd') } catch (e) { ui.warn('clean failed: ' + e.message) }
}

// ---------- backend ----------
function makeBackend(cfg) {
  if (cfg.backend !== 'git') return { kind: 'none', excluded: null, prepare() { }, generation: () => 'static', save: () => ({ saved: false, reason: 'no-git' }) }
  return {
    kind: 'git', excluded: null,
    prepare() {
      gitOk('fetch')
      if (gitOk('rev-parse', '--abbrev-ref', 'HEAD') === 'HEAD')
        for (const b of ['main', 'master'])
          if (gitOk('rev-parse', '--verify', '--quiet', 'refs/heads/' + b)) try { git('checkout', b); break } catch { }
    },
    generation: () => gitOk('rev-parse', 'HEAD') ?? 'no-head',
    save(paths, meta) {
      const list = [...paths]
      for (let i = 0; i < list.length; i += 500) try { git('add', '-A', '--', ...list.slice(i, i + 500)) } catch (e) { return { saved: false, reason: 'add-failed: ' + e.message } }
      if (gitOk('status', '--porcelain') === '') return { saved: false, reason: 'clean' }
      const idc = gitOk('config', 'user.name') && gitOk('config', 'user.email') ? [] : ['-c', 'user.name=c3', '-c', 'user.email=c3@localhost']
      try { git(...idc, 'commit', '-m', meta.message) } catch (e) { return { saved: false, reason: 'commit-failed: ' + e.message } }
      try { git('push'); return { saved: true, pushed: true } } catch { }
      try { gitOk('fetch'); git('merge', '-X', 'ours', '--no-edit', '@{u}') } catch {
        try { gitOk('merge', '--abort') } catch { }
        if (cfg.forcePush === true && has('force-push')) try { git('push', '--force'); return { saved: true, pushed: true, forced: true } } catch { }
        return { saved: true, pushed: false }
      }
      try { git('push'); return { saved: true, pushed: true } } catch { return { saved: true, pushed: false } }
    }
  }
}

// ---------- sync ----------
function sync(mesh, doc, onAddrs) {
  const parts = new Map(), seen = new Set()
  let liveBytes = 0
  const sendVec = () => mesh.sendAll(VEC, Buffer.from(Y.encodeStateVector(doc)))
  const sendAddrs = () => {
    const peers = []
    for (const c of mesh.conns) {
      if (!c.ready || !c.peerId) continue
      const a = (c.cands || []).map(t => toMa(t.host, t.port, c.peerId)).slice(0, 4)
      if (a.length) peers.push(a)
      if (peers.length >= 8) break
    }
    mesh.sendAll(ADDRS, Buffer.from(JSON.stringify({ self: mesh.addrs(), peers })))
  }
  const sendUpd = u => {
    const data = Buffer.from(u)
    if (!data.length || data.length > MAX_UPD) return
    const id = crypto.createHash('sha1').update(data).digest().subarray(0, 8)
    const n = Math.max(1, Math.ceil(data.length / CHUNK))
    if (n > 65535) return
    const out = []
    for (let i = 0; i < n; i++) {
      const h = Buffer.allocUnsafe(13)
      h[0] = UPDATE; id.copy(h, 1); h.writeUInt16BE(i, 9); h.writeUInt16BE(n, 11)
      out.push(Buffer.concat([h, data.subarray(i * CHUNK, (i + 1) * CHUNK)]))
    }
    mesh.sendChunks(out)
  }
  mesh.on('message', ev => {
    const { type, payload } = ev.detail || {}
    if (!payload) return
    if (type === VEC) {
      const d = Y.encodeStateAsUpdate(doc, payload)
      if (d.length > 2) sendUpd(d)
      return
    }
    if (type === ADDRS) {
      let a; try { a = JSON.parse(payload.toString('utf8')) } catch { return }
      const out = []
      if (Array.isArray(a)) out.push(...a)
      else if (a && typeof a === 'object') {
        if (Array.isArray(a.self)) out.push(...a.self)
        if (Array.isArray(a.peers)) for (const g of a.peers) if (Array.isArray(g)) out.push(...g)
      }
      onAddrs(out.slice(0, 32)); return
    }
    if (type !== UPDATE || payload.length < 15) return
    const id = payload.subarray(1, 9).toString('hex')
    const i = payload.readUInt16BE(9), n = payload.readUInt16BE(11)
    if (n < 1 || i >= n || n > 65535) return
    const now = Date.now()
    for (const [k, p] of parts) if (now - p.ts > 60000) { liveBytes -= p.bytes; parts.delete(k) }
    let p = parts.get(id)
    if (!p) { if (parts.size >= 64) return; p = { n, got: 0, ch: new Array(n), ts: 0, bytes: 0 }; parts.set(id, p) }
    if (p.n !== n || p.ch[i]) return
    const c = Buffer.from(payload.subarray(13))
    p.ch[i] = c; p.got++; p.bytes += c.length; p.ts = now
    liveBytes += c.length
    if (liveBytes > 64 << 20) { parts.clear(); liveBytes = 0; return }
    if (p.got !== n) return
    parts.delete(id); liveBytes -= p.bytes
    const full = Buffer.concat(p.ch)
    if (full.length < 2 || full.length > MAX_UPD) return
    if (crypto.createHash('sha1').update(full).digest().subarray(0, 8).toString('hex') !== id) return
    if (seen.has(id)) return
    seen.add(id); if (seen.size > 4096) seen.clear()
    try { Y.applyUpdate(doc, full, 'remote') } catch { }
  })
  mesh.on('peer:connect', () => { sendVec(); sendAddrs() })
  mesh.on('peer:disconnect', () => { parts.clear(); liveBytes = 0 })
  doc.on('update', (u, origin) => { if (origin !== 'remote' && origin !== 'restore') sendUpd(u) })
  const t = setInterval(() => { sendVec(); sendAddrs() }, 2000)
  t.unref?.()
  sendVec(); sendAddrs()
}

// ---------- hosting menu ----------
async function chooseHosting() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  const ask = q => rl.question(q).then(v => v.trim())
  ui.hold = true
  try {
    ui.clear()
  console.log('')
  console.log('  This machine has no address other networks can dial.')
  console.log('  How should peers reach it?')
  console.log('')
  console.log(`    ${cyan('1)')} Same network only         Peers must be on this LAN`)
  console.log(`    ${cyan('2)')} Cloudflare quick tunnel   Third-party option that works across networks`)
  console.log(`    ${cyan('3)')} Public address            When you already have a port forward or VPS`)
  console.log(`    ${cyan('4)')} Stable tunnel             Named Cloudflare tunnel with a fixed hostname`)
  console.log(`    ${cyan('5)')} Quit`)
  console.log('')
    for (; ;) {
      const a = (await ask('  Choose 1-5 [1]: ')).toLowerCase()
      if (a === '' || a === '1') { rl.close(); return { mode: 'lan' } }
      if (a === '2') { rl.close(); return { mode: 'cloudflare' } }
      if (a === '5' || a === 'q') { rl.close(); return { mode: 'quit' } }
      if (a === '4') {
        const v = (await rl.question('  Stable hostname (e.g. c3.example.com): ')).trim()
        rl.close()
        if (!/^[a-z0-9]([a-z0-9.-]{0,252}[a-z0-9])?$/i.test(v)) { ui.warn('Bad hostname'); return { mode: 'quit' } }
        return { mode: 'named', value: v }
      }
      if (a === '3') {
        const v = (await rl.question('  Host:port (IPv6 needs brackets): ')).trim()
        rl.close()
        if (!/^(?:\[[^\]]+\]|[^:/\s]+):\d{1,5}$/.test(v)) { ui.warn('Bad address'); return { mode: 'quit' } }
        return { mode: 'advertise', value: v }
      }
      console.log('  Enter 1, 2, 3, 4 or 5')
    }
  } finally { ui.hold = false }
}

// ---------- connect ----------
async function connect() {
  const cfg0 = readConfig() ?? {}
  setRoot(chooseRoot())
  const ident = loadIdentity()
  const name = JOIN?.name ?? flag('name') ?? cfg0.name ?? path.basename(ROOT)
  const sdir = sdirOf(name)
  if (flag('key')) die('Use the invite line or C3_KEY (argv is visible in ps).')
  let sKey = JOIN?.key ?? process.env.C3_KEY ?? readKey(sdir)
  const fresh = !sKey
  if (!sKey) sKey = crypto.randomBytes(32).toString('base64url')
  if (fresh || JOIN) writeKey(sdir, sKey)
  const wantPort = +(flag('port') ?? cfg0.port ?? 8443)
  if (!Number.isInteger(wantPort) || wantPort < 0 || wantPort > 65535) die('Bad port.')
  let advertise = String(flag('advertise') ?? cfg0.advertise ?? '').trim()
  const psk = crypto.createHash('sha256').update('c3psk\0').update(name).update('\0').update(sKey).digest()
  const mesh = new Mesh(ident, { port: wantPort, psk, advertise, lanOnly: has('lan-only'), allIfaces: has('all-ifaces') || cfg0.allIfaces === true })
  await mesh.start()
  const port = mesh.port
  ui.start()

  // ---- hosting decision ----
  let tunnelChild = null
  const tunFlag = flag('tunnel')
  let tunnelKind = tunFlag ?? cfg0.tunnel ?? null
  let tunnelHost = String(flag('tunnel-host') ?? cfg0.tunnelHost ?? '').trim()
  const tunnelToken = process.env.C3_TUNNEL_TOKEN ?? cfg0.tunnelToken ?? ''
  let tunnelMode = tunnelKind === 'cloudflare' || tunnelKind === 'named'
  if (!JOIN && !advertise && !has('lan-only')) {
    const cl = classify(mesh.addrs())
    let pick = (tunnelMode && tunFlag) ? { mode: tunnelKind } : null
    if (!cl.ok || tunnelMode) {
      if (!pick && process.stdin.isTTY) pick = await chooseHosting()
      if (pick?.mode === 'quit') { try { await mesh.stop() } catch { }; process.exit(0) }
      if (pick?.mode === 'advertise') { advertise = pick.value; mesh.ad = advertise }
      if (pick?.mode === 'cloudflare' || pick?.mode === 'named') {
        tunnelKind = pick.mode
        if (pick.mode === 'named' && pick.value) tunnelHost = pick.value
        const t = await startTunnel(port, { kind: tunnelKind, host: tunnelHost, token: tunnelToken })
        if (t) { mesh.tunnel = t.host; tunnelChild = t.child; tunnelMode = true; ui.say('Tunnel ' + t.host) }
        else {
          ui.warn('Cloudflare tunnel failed to start'); tunnelHelp()
          if (process.stdin.isTTY) {
            const retry = await chooseHosting()
            if (retry?.mode === 'quit') { try { await mesh.stop() } catch { }; process.exit(0) }
            if (retry?.mode === 'cloudflare' || retry?.mode === 'named') {
              const t2 = await startTunnel(port, { kind: retry.mode, host: retry.value || tunnelHost, token: tunnelToken })
              if (t2) { mesh.tunnel = t2.host; tunnelChild = t2.child; tunnelMode = true; ui.say('Tunnel ' + t2.host) }
            } else if (retry?.mode === 'advertise') { advertise = retry.value; mesh.ad = advertise }
          }
        }
      }
    }
    if (!cl.ok && !pick && !process.stdin.isTTY) {
      ui.warn('This machine cannot host a cross-network session')
      ui.clear()
      for (const p of cl.cgnat4) console.error('    ' + dcyan(`/ip4/${p.host}`) + '   Carrier-grade NAT (outbound only)')
      for (const p of cl.priv4) console.error('    ' + dcyan(`/ip4/${p.host}`) + `   ${hotspotLike(p.host) ? 'Phone hotspot subnet (private)' : 'Private address (same LAN only)'}`)
      if (!cl.cgnat4.length && !cl.priv4.length) console.error('    (No non-loopback addresses at all)')
      console.error('  Run interactively to choose a tunnel, or pass --tunnel cloudflare')
      console.error('  For a stable hostname: --tunnel named --tunnel-host c3.example.com')
    }
  }

  if (JOIN) {
    const hostAddrs = JOIN.addrs.length ? JOIN.addrs : [JOIN.ma].filter(Boolean)
    if (!classify(hostAddrs).ok) {
      ui.warn('This invite carries no globally routable address')
      ui.clear()
      console.error('  The host is on a LAN, a phone hotspot, or behind NAT, so it is only')
      console.error('  reachable from the same network. If you are on another network, the')
      console.error('  host should start with a tunnel or a public address.')
    }
  }

  const kind = cfg0.backend === 'git' || cfg0.backend === 'none' ? cfg0.backend : (fs.existsSync(path.join(ROOT, '.git')) ? 'git' : 'none')
  const cfg = { ...cfg0, name, port, backend: kind }
  delete cfg.dir
  if (advertise) cfg.advertise = advertise
  else delete cfg.advertise
  if (tunnelMode) { cfg.tunnel = tunnelKind; if (tunnelHost) cfg.tunnelHost = tunnelHost; else delete cfg.tunnelHost }
  else { delete cfg.tunnel; delete cfg.tunnelHost }
  atomicWrite(CONFIG_FILE, JSON.stringify(cfg, null, 2), 0o600)
  loadIgnores()
  backend = makeBackend(cfg)
  backend.prepare()
  const me = { name: gitOk('config', 'user.name') ?? (os.userInfo().username || 'peer') }
  const prune = has('prune')

  if (JOIN) for (const f of ['state.bin', 'state.gen', 'oplog']) try { fs.rmSync(path.join(sdir, f), { force: true }) } catch { }
  if (!JOIN && kind === 'git') { ui.set('resetting to repo...'); resetToHead() }

  const peers = new Set()
  const savePeers = () => {
    const arr = [...peers].map((a, i) => ({ a, i, p: parseMa(a) })).filter(x => x.p).sort((x, y) => rank(x.p) - rank(y.p) || x.i - y.i)
    const out = [], seen = new Set()
    for (const x of arr) {
      const k = x.p.host + ':' + x.p.port
      if (seen.has(k)) continue
      seen.add(k); out.push(x.a)
      if (out.length >= 64) break
    }
    peers.clear(); for (const a of out) peers.add(a)
    writePeers(sdir, out)
  }
  const addPeer = (a, allowLocal = false) => {
    if (typeof a !== 'string' || a.length > 500) return false
    const p = parseMa(a)
    if (!p || p.id === mesh.id || isLoop(p.host)) return false
    if (!allowLocal && isLocal(p.host)) return false
    if (peers.has(a)) return false
    peers.add(a); savePeers(); return true
  }
  for (const a of readPeers(sdir)) addPeer(a, true)
  if (JOIN?.ma) { peers.add(JOIN.ma); savePeers() }
  if (JOIN) for (const m of JOIN.addrs) addPeer(m)
  if (flag('peer')) addPeer(flag('peer'), true)

  let leaving = false
  const retry = new Map()
  const dialPeers = () => {
    if (leaving) return
    for (const a of readPeers(sdir)) addPeer(a, true)
    const live = mesh.peerIds(), list = []
    const now = Date.now()
    let i = 0
    for (const a of peers) {
      const p = parseMa(a)
      if (!p || p.id === mesh.id || live.has(p.id)) continue
      const r = retry.get(a)
      if (r && r.next > now) continue
      list.push({ a, i: i++, r: rank(p) })
    }
    list.sort((x, y) => x.r - y.r || x.i - y.i)
    for (const x of list.slice(0, MAX_DIAL)) {
      mesh.dial(x.a).then(ok => {
        if (ok) { retry.delete(x.a); return }
        const r = retry.get(x.a) || { n: 0, next: 0 }
        r.n++
        r.next = Date.now() + Math.min(300000, 10000 * (2 ** (r.n - 1)))
        retry.set(x.a, r)
      }).catch(() => { })
    }
  }
  const waitFor = async (ms, cond) => {
    const until = Date.now() + ms
    while (Date.now() < until) { if (cond()) return true; await sleep(200) }
    return cond()
  }

  let snapTimer = null, scanTimer = null, tick = null, dialTimer = null, addrsTimer = null, autosaveTimer = null
  const stateFile = path.join(sdir, 'state.bin'), genFile = path.join(sdir, 'state.gen'), logFile = path.join(sdir, 'oplog')
  const appendLog = u => { try { const h = Buffer.allocUnsafe(4); h.writeUInt32BE(u.length, 0); fs.appendFileSync(logFile, Buffer.concat([h, Buffer.from(u)])) } catch { } }
  const snapshotNow = () => { try { atomicWrite(stateFile, Y.encodeStateAsUpdate(doc), 0o600); atomicWrite(genFile, backend.generation(), 0o600); fs.rmSync(logFile, { force: true }) } catch { } }
  const scheduleSnapshot = () => {
    if (!AUTOSAVE_MS) return
    clearTimeout(snapTimer)
    snapTimer = setTimeout(snapshotNow, AUTOSAVE_MS)
    snapTimer.unref?.()
  }
  const removeState = () => { for (const f of [stateFile, genFile, logFile]) try { fs.rmSync(f, { force: true }) } catch { } }
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
          if (len < 1 || len > MAX_FRM || off + len > b.length) break
          try { Y.applyUpdate(doc, b.subarray(off, off + len), 'restore') } catch { }
          off += len
        }
      }
      return true
    } catch { removeState(); return false }
  }
  const restored = restoreState()
  if (restored && kind === 'git' && !JOIN) {
    const g = fs.existsSync(genFile) ? fs.readFileSync(genFile, 'utf8').trim() : null
    if (g && g !== backend.generation()) {
      ui.warn('local state is older than HEAD -- run `node c3.js join <invite>` to resync,')
      ui.warn('or delete c3/.c3 and start over')
    }
  }
  sync(mesh, doc, addrs => { for (const a of addrs) addPeer(a); dialPeers() })
  doc.on('update', (u, origin) => { if (origin === 'restore') return; appendLog(u); scheduleSnapshot() })
  // Ctrl+S-style autosave: writes usually land within 40 ms, this retries anything
  // still dirty (locked file, transient permissions, missed event) on an interval.
  if (AUTOSAVE_MS) {
    autosaveTimer = setInterval(() => {
      if (leaving || !dirtyDocs.size) return
      for (const rel of [...dirtyDocs]) writeToDisk(rel)
    }, AUTOSAVE_MS)
    autosaveTimer.unref?.()
  }

  let scanning = false
  async function scan() {
    if (scanning || leaving) return
    scanning = true
    try {
      const list = await walkTreeAsync(), present = new Set(list), now = Date.now()
      if (leaving) return
      for (const rel of list) {
        if (pendingWrites.has(rel) || (lastWritten.get(rel) ?? 0) > now - 200) continue
        let st; try { st = fs.statSync(path.join(ROOT, rel)) } catch { continue }
        if (!st.isFile()) continue
        const sig = sigOf(st)
        if (diskMeta.get(rel) === sig) continue
        diskMeta.set(rel, sig); syncFromDisk(rel)
      }
      for (const rel of [...files.keys()]) {
        if (present.has(rel)) continue
        if (shouldIgnore(rel) || pendingWrites.has(rel)) continue
        noteGone(rel)
      }
    } catch { } finally { scanning = false }
  }
  function quick(rel) {
    if (!rel) return
    const s = safeAbs(rel)
    if (!s || shouldIgnore(s.norm)) return
    let st; try { st = fs.statSync(s.abs) } catch { st = null }
    if (!st || !st.isFile()) { noteGone(s.norm); return }
    const now = Date.now()
    if (pendingWrites.has(s.norm) || (lastWritten.get(s.norm) ?? 0) > now - 200) return
    const sig = sigOf(st)
    if (diskMeta.get(s.norm) === sig) return
    diskMeta.set(s.norm, sig); syncFromDisk(s.norm)
  }
  let started = false, watcher = null
  function startScan() {
    if (started) return
    started = true; scan()
    const arm = ms => { clearInterval(scanTimer); scanTimer = setInterval(scan, ms); scanTimer.unref?.() }
    let watching = false
    try {
      watcher = fs.watch(ROOT, { recursive: true }, (_e, f) => { if (f) quick(String(f).split(path.sep).join('/')) })
      watcher.on('error', () => { try { watcher.close() } catch { }; watcher = null; if (!leaving) arm(1000) })
      watching = true
    } catch { ui.warn('instant watching unavailable -- polling every second') }
    arm(watching ? 2000 : 1000)
  }
  function seedFromDisk() {
    const seed = walkTree()
    let bytes = 0
    for (const rel of seed) try { bytes += fs.statSync(path.join(ROOT, rel)).size } catch { }
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
  async function leave() {
    if (leaving) return
    leaving = true
    ui.stop(); ui.setActive(false); ui.done = true
    for (const t of [scanTimer, snapTimer, tick, dialTimer, addrsTimer, autosaveTimer]) { clearInterval(t); clearTimeout(t) }
    try { watcher?.close() } catch { }
    try { tunnelChild?.kill() } catch { }
    flushWrites(); snapshotNow(); ui.clear()
    try {
      if (mesh.peerCount() > 0) {
        ui.say('others still in session -- keeping local state, not publishing')
      } else {
        const all = new Set(walkTree())
        for (const rel of touched) all.add(rel)
        const st = backend.kind === 'git' ? gitOk('status', '--porcelain') : null
        const clean = backend.kind === 'git' && st === ''
        const changed = st ? st.split('\n').filter(Boolean).length : 0
        if (backend.kind !== 'git') { ui.say(`nothing to publish: no git repo in ${ROOT}`); removeState() }
        else if (clean) { ui.say('nothing changed (already committed)'); removeState() }
        else if (!(await confirmSave(changed))) ui.say('skipped publishing')
        else {
          const r = backend.save(all, { user: me.name, message: `Session snapshot ${new Date().toISOString()}` })
          if (r.saved === false) {
            if (r.reason === 'clean') ui.say('nothing changed (already committed)')
            else ui.warn('publish failed: ' + (r.reason || 'unknown'))
            removeState()
          } else if (r.pushed === false) ui.warn('could not push -- commit kept locally')
          else { removeState(); ui.say(r.forced ? 'saved and pushed (force)' : 'saved and pushed') }
        }
      }
    } catch (e) { console.error('Save failed:', e.message) }
    finally { try { await mesh.stop() } catch { }; process.exit(0) }
  }

  const liveMsg = () => { const p = mesh.peerCount(); return `live -- ${p} peer${p === 1 ? '' : 's'} -- ${files.size} files -- ${kind}` }
  mesh.on('peer:connect', ev => {
    const pid = ev.detail
    for (const [a] of retry) { const p = parseMa(a); if (p?.id === pid) retry.delete(a) }
    ui.wake = Date.now() + 2000
    ui.setActive(mesh.peerCount() > 0)
    ui.set(liveMsg())
    dialPeers()
  })
  mesh.on('peer:disconnect', () => {
    ui.setActive(mesh.peerCount() > 0)
    ui.set(liveMsg())
  })
  mesh.on('peer:discover', ev => {
    const { ma } = ev.detail || {}
    if (!ma) return
    retry.delete(ma)
    if (addPeer(ma, true)) dialPeers()
  })

  const addrsFile = path.join(sdir, 'addrs.json')
  let myAddrs = mesh.addrs()
  const writeAddrs = () => { try { atomicWrite(addrsFile, JSON.stringify({ id: mesh.id, addrs: myAddrs, port }), 0o600) } catch { } }
  const refreshAddrs = () => {
    const next = mesh.addrs()
    if (next.join('|') === myAddrs.join('|')) return false
    const was = inviteOk(myAddrs).join('|')
    myAddrs = next; writeAddrs()
    if (inviteOk(next).join('|') !== was) {
      ui.warn('network address changed -- any invite already printed is stale')
      ui.say('run `node c3.js share` in another terminal for a fresh invite')
    }
    return true
  }

  ui.say('Root ' + dcyan(`${ROOT}${flag('dir') ? ' (--dir)' : ''}`) + ' -- ' + dcyan(kind))
  dialPeers(); dialTimer = setInterval(dialPeers, 10000)
  ui.set(JOIN ? 'Connecting' : 'Starting', { dots: true })
  if (JOIN) await waitFor(45000, () => files.size > 0)
  else await sleep(2500)

  const had = files.size
  if (had > 0) {
    if (JOIN) wipeLocal()
    adoptTree(); reconcile(prune)
  } else if (JOIN) {
    ui.warn('joined but received no state from the peer in 45s')
    ui.warn('the peer must stay running until your file count matches theirs')
    ui.say('leaving without touching local files')
    try { await mesh.stop() } catch { }
    try { tunnelChild?.kill() } catch { }
    process.exit(1)
  } else seedFromDisk()
  if (!started) startScan()

  writeAddrs()
  addrsTimer = setInterval(refreshAddrs, 5000)

  // If we joined a LAN-only session, offer to add a dialable endpoint so the
  // session can be reached from other networks even after the LAN host leaves.
  if (JOIN && process.stdin.isTTY) {
    const hostAddrs = JOIN.addrs.length ? JOIN.addrs : [JOIN.ma].filter(Boolean)
    if (!classify(hostAddrs).ok && !inviteOk(mesh.addrs()).length && !mesh.tunnel) {
      ui.clear()
      console.log('')
      console.log('  This session is LAN-only.')
      console.log('  You can make it reachable from other networks by adding a tunnel or public address.')
      console.log('')
      const pick = await chooseHosting()
      if (pick?.mode === 'quit') { try { await mesh.stop() } catch { }; process.exit(0) }
      if (pick?.mode === 'advertise') { mesh.ad = pick.value; refreshAddrs() }
      if (pick?.mode === 'cloudflare' || pick?.mode === 'named') {
        const t = await startTunnel(port, { kind: pick.mode, host: pick.value || tunnelHost, token: tunnelToken })
        if (t) { mesh.tunnel = t.host; tunnelChild = t.child; refreshAddrs(); ui.say('Tunnel ' + t.host) }
        else ui.warn('Cloudflare tunnel failed to start')
      }
    }
  }

  if (had > 0) ui.say(`${restored ? 'resumed' : 'joined'} "${name}" -- ${files.size} files -- ${kind}`)
  else ui.say(`started "${name}" -- ${files.size} files -- ${kind}`)

  const usable = inviteOk(myAddrs), host = bestHost(usable)
  if (host) {
    ui.clear()
    console.log('')
    console.log('  ' + cyan('Invite') + ' -- paste this into the other terminal:')
    console.log('')
    console.log('' + dcyan('node c3.js join ' + makeInv({ name, key: sKey, addrs: usable, host: host.host, port: host.port, id: mesh.id })))
    console.log('')
  } else if (!JOIN) ui.warn('No address to put in an invite -- see the reachability warning above')

  ui.live = true
  ui.setActive(mesh.peerCount() > 0)
  ui.set(liveMsg())
  tick = setInterval(() => {
    ui.setActive(mesh.peerCount() > 0)
    ui.set(liveMsg())
  }, 1000)
  process.on('SIGINT', leave); process.on('SIGTERM', leave)
}

// ---------- commands ----------
async function joinCmd() {
  const raw = argv[1] && !argv[1].startsWith('--') ? argv[1] : flag('invite')
  const inv = readInv(raw)
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
  try { addrs = JSON.parse(fs.readFileSync(path.join(sdir, 'addrs.json'), 'utf8')).addrs ?? [] } catch { }
  addrs = addrs.map(parseMa).filter(p => p && p.id === me).map(p => maStr({ ...p, id: me }))
  if (!addrs.length) addrs = lanAddrs(me, +(cfg.port || 8443), has('all-ifaces'))
  // Include dialable addresses from known peers so the session stays reachable
  // even if the original host leaves
  const peerAddrs = readPeers(sdir)
    .map(parseMa)
    .filter(p => p && dialable(p))
    .map(p => maStr(p))
  const allAddrs = [...addrs, ...peerAddrs]
  const usable = inviteOk(allAddrs)
  const host = bestHost(usable)
  if (!host) die('No reachable address. Run with --tunnel cloudflare or --tunnel named --tunnel-host <host>.')
  if (!classify(usable).ok) ui.warn('This invite is LAN-only -- cross-network peers cannot dial it')
  ui.clear()
  console.log('')
  console.log('  ' + dcyan('node c3.js join ' + makeInv({ name: cfg.name, key, addrs: usable, host: host.host, port: host.port, id: host.id })))
  console.log('')
}
function peerCmd() {
  const cfg = readConfig() ?? die('No config.')
  const ma = String(argv[1] || '').trim()
  if (!parseMa(ma)) die('usage: node c3.js peer "/ip4/10.0.0.5/tcp/8443/p2p/<16 hex>"')
  const sdir = sdirOf(cfg.name), list = readPeers(sdir)
  if (!list.includes(ma)) list.push(ma)
  writePeers(sdir, list)
  ui.say('peer added')
}
async function configCmd() {
  setRoot(chooseRoot())
  const isGit = fs.existsSync(path.join(ROOT, '.git'))
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  const ask = async (q, def) => { if (!process.stdin.isTTY) return def; const a = (await rl.question(`? ${q}${def ? ` [${def}]` : ''} `)).trim(); return a || def }
  ui.clear(); console.log(`C3 config -- ${ROOT}`)
  const cur = readConfig() ?? {}
  const picked = await ask('Backend  1) git  2) none  Pick 1/2', isGit ? '1' : '2')
  const kind = picked === '1' && isGit ? 'git' : 'none'
  const port = +(flag('port') ?? await ask('Listening TCP/UDP port', '8443'))
  if (!Number.isInteger(port) || port < 1 || port > 65535) die('Bad port.')
  const advertise = String(flag('advertise') ?? await ask('Reachable host:port (blank = ask at startup)', '')).trim()
  const tunDef = cur.tunnel === 'named' ? '2' : cur.tunnel === 'cloudflare' ? '1' : '0'
  const tun = String(await ask('Tunnel  0) none  1) quick cloudflare  2) named cloudflare  Pick 0/1/2', tunDef)).toLowerCase()
  const tunKind = tun === '2' ? 'named' : tun === '1' ? 'cloudflare' : null
  const tunHost = tunKind === 'named' ? String(await ask('Stable tunnel hostname', cur.tunnelHost || '')).trim() : ''
  const cfg = { ...cur, backend: kind, port }
  delete cfg.dir
  if (advertise) cfg.advertise = advertise
  else delete cfg.advertise
  if (tunKind) { cfg.tunnel = tunKind; if (tunHost) cfg.tunnelHost = tunHost; else delete cfg.tunnelHost }
  else { delete cfg.tunnel; delete cfg.tunnelHost }
  if (process.env.C3_TUNNEL_TOKEN) cfg.tunnelToken = process.env.C3_TUNNEL_TOKEN
  atomicWrite(CONFIG_FILE, JSON.stringify(cfg, null, 2), 0o600)
  if (kind === 'git') {
    const ex = path.join(ROOT, '.git', 'info', 'exclude')
    mkdirp(path.dirname(ex))
    const cur = fs.existsSync(ex) ? fs.readFileSync(ex, 'utf8') : ''
    if (!cur.split('\n').includes('.c3/')) fs.appendFileSync(ex, '\n.c3/\n')
  }
  rl.close(); ui.clear()
  console.log('Config written: ' + dcyan(CONFIG_FILE))
}

// ---------- dispatch ----------
const usage = `Usage: node c3.js [command]
  (no command)      Resume this directory's session, or start one
  join <c3://...>   Adopt a session (use this for first contact)
  share             Print the invite line again
  config            Change port / backend / advertise / tunnel
  peer <ma>         Add a peer address manually
Flags: --dir <p>  --port <n>  --advertise <host:port>  --tunnel cloudflare|named
       --tunnel-host <host>  --lan-only  --all-ifaces  --prune  --yes  --force-push
       --autosave <seconds>  (autosave interval, default 1; 0 disables)
`
if (cmd === 'help' || has('help')) { console.log(usage); process.exit(0) }
else if (cmd === 'join') await joinCmd()
else if (cmd === 'share') shareCmd()
else if (cmd === 'config') await configCmd()
else if (cmd === 'peer') peerCmd()
else if (cmd === undefined || cmd === 'connect' || cmd?.startsWith('--')) await connect()
else die(usage)