// net.js -- TCP + optional WebSocket + UDP hole-punched transport for c3.
// No DHT, no relays, no third-party discovery.
// Frame: [u32 length][u8 type][payload]. JOIN/JOINOK carry a P-256
// handshake; everything else is AES-256-GCM with the session key.
// Peers punch UDP on the same port number as TCP, so a pair that already
// knows each other's address connects even when both firewalls deny inbound.
import crypto from 'node:crypto'
import net from 'node:net'
import dgram from 'node:dgram'
import os from 'node:os'
import fs from 'node:fs'
import * as Y from 'yjs'

const T_JOIN = 1
const T_JOINOK = 2
const T_HELLO = 3
const T_VECTOR = 4
const T_UPDATE = 5
const T_ADDRS = 6
const MAX_FRAME = 64 << 20
const CHUNK = 32 * 1024
const MAX_ADDR = 12
const UDP_TTL = 25000
const NO_UDP = !!process.env.C3_NO_UDP
const dbg = (...a) => { if (process.env.C3_DEBUG) console.error(...a) }
const sha = b => crypto.createHash('sha256').update(b).digest()

export const tokenTopic = tok => 'c3tok/' + sha(String(tok)).toString('hex')
export const tokenKey = tok => sha('c3tokkey\0' + String(tok))

// ---------- optional ws dependency ----------
let wsMod = null
let wsTried = false
async function getWs() {
  if (wsTried) return wsMod
  wsTried = true
  try { wsMod = await import('ws') } catch { wsMod = null }
  if (!wsMod) dbg('[net] ws package not installed -- WebSocket transport disabled')
  return wsMod
}

// ---------- identity ----------
export async function loadKey(file) {
  try {
    const j = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (j && typeof j.id === 'string' && /^[0-9a-f]{16}$/.test(j.id)) return j
  } catch {}
  const ident = { id: crypto.randomBytes(8).toString('hex') }
  try { fs.writeFileSync(file, JSON.stringify(ident), { mode: 0o600 }) } catch {}
  return ident
}

// ---------- addressing ----------
export function toMa(hp, id, ws = false) {
  const s = String(hp || '').trim()
  const m = s.match(/^\[([^\]]+)\]:(\d+)$/) || s.match(/^([^:]+)(?::(\d+))?$/)
  if (!m) return null
  const port = Number(m[2] || 8443)
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null
  const host = m[1]
  const base = host.includes(':') ? `/ip6/${host}`
    : (/^\d+\.\d+\.\d+\.\d+$/.test(host) ? `/ip4/${host}` : `/dns/${host}`)
  return `${base}/tcp/${port}${ws ? '/ws' : ''}/p2p/${id}`
}

const hpOf = ma => {
  const s = String(ma || '')
  const ws = s.includes('/ws')
  let m = s.match(/^\/ip4\/([^/]+)\/tcp\/(\d+)/) || s.match(/^\/dns\/([^/]+)\/tcp\/(\d+)/)
  if (!m) m = s.match(/^\/ip6\/([^/]+)\/tcp\/(\d+)/)
  if (!m) return null
  return { host: m[1], port: Number(m[2]), ws }
}

const usableV4 = a => !a.startsWith('169.254.') && !a.startsWith('0.')

export function addrsOf(n, advertise) { return n.addrsList(advertise) }

// ---------- framing ----------
const frame = (type, payload) => {
  const p = payload && payload.length ? Buffer.from(payload) : Buffer.alloc(0)
  const h = Buffer.allocUnsafe(5)
  h.writeUInt32BE(p.length + 1, 0)
  h[4] = type
  return Buffer.concat([h, p])
}

const seal = (key, type, payload) => {
  const iv = crypto.randomBytes(12)
  const c = crypto.createCipheriv('aes-256-gcm', key, iv)
  c.setAAD(Buffer.from([type]))
  const ct = Buffer.concat([c.update(payload || Buffer.alloc(0)), c.final()])
  return frame(type, Buffer.concat([iv, ct, c.getAuthTag()]))
}

const unseal = (key, type, body) => {
  if (!body || body.length < 28) throw new Error('short frame')
  const d = crypto.createDecipheriv('aes-256-gcm', key, body.subarray(0, 12))
  d.setAAD(Buffer.from([type]))
  d.setAuthTag(body.subarray(body.length - 16))
  return Buffer.concat([d.update(body.subarray(12, body.length - 16)), d.final()])
}

const freePort = () => new Promise((res, rej) => {
  const s = net.createServer()
  s.once('error', rej)
  s.listen(0, '0.0.0.0', () => { const p = s.address().port; s.close(() => res(p)) })
})

// P-256: Node's createECDH supports this; x25519 is not a createECDH curve.
const ecdh = () => {
  const e = crypto.createECDH('prime256v1')
  e.generateKeys()
  return e
}

// ---------- punch packets: 24 bytes, HMAC-only, no per-packet IV ----------
const P_MAGIC = Buffer.from('C3PU')
const punchPacket = (key, ctr) => {
  const b = Buffer.allocUnsafe(24)
  P_MAGIC.copy(b, 0)
  b.writeUInt32BE(ctr >>> 0, 4)
  crypto.createHmac('sha256', key).update(b.subarray(0, 8)).digest().subarray(0, 16).copy(b, 8)
  return b
}
const isPunch = d => d.length === 24 && d.subarray(0, 4).equals(P_MAGIC)
const validPunch = (key, d) => {
  const mac = crypto.createHmac('sha256', key).update(d.subarray(0, 8)).digest().subarray(0, 16)
  return crypto.timingSafeEqual(mac, d.subarray(8, 24))
}

// ---------- wire adapters ----------
const tcpWire = sock => {
  const h = { data: [], close: [], error: [] }
  const w = {
    destroyed: false,
    kind: 'tcp',
    remoteAddress: sock.remoteAddress || null,
    write: b => { if (!w.destroyed) { try { sock.write(b) } catch {} } },
    destroy: () => { w.destroyed = true; try { sock.destroy() } catch {} },
    on: (ev, fn) => { (h[ev] ||= []).push(fn) }
  }
  sock.on('data', d => { for (const fn of h.data) fn(d) })
  sock.on('close', () => { w.destroyed = true; for (const fn of h.close) fn() })
  sock.on('error', () => { for (const fn of h.error) fn() })
  sock.setNoDelay(true)
  sock.setKeepAlive(true, 10000)
  return w
}

const wsWire = (ws, kind = 'ws') => {
  const h = { data: [], close: [], error: [] }
  const w = {
    destroyed: false,
    kind,
    remoteAddress: null,
    write: b => { if (!w.destroyed) { try { ws.send(b) } catch {} } },
    destroy: () => { w.destroyed = true; try { ws.terminate ? ws.terminate() : ws.close() } catch {} },
    on: (ev, fn) => { (h[ev] ||= []).push(fn) }
  }
  ws.on('message', d => { for (const fn of h.data) fn(Buffer.from(d)) })
  ws.on('close', () => { w.destroyed = true; for (const fn of h.close) fn() })
  ws.on('error', () => { for (const fn of h.error) fn() })
  return w
}

// ---------- mesh ----------
class Mesh {
  constructor(ident, port, opts = {}) {
    this.ident = ident
    this.id = ident.id
    this.peerId = { toString: () => this.id }
    this.wantPort = Number(port) > 0 ? Number(port) : 0
    this.wantWs = Number(opts.wsPort) > 0 ? Number(opts.wsPort) : 0
    this.wantUdp = !NO_UDP && opts.udp !== false
    this.port = this.wantPort
    this.wsPort = 0
    this.udpPort = 0
    this.conns = new Set()
    this.events = new Map()
    this.session = null
    this.join = null
    this.advertise = ''
    this.stopped = false
    this.punchKey = null
    this.punchCtr = 0
    this.punchTick = 0
    this.udpTargets = new Map()
    this.udpPeers = new Map()
    this.punchReplies = new Map()
  }

  on(type, fn) {
    if (!this.events.has(type)) this.events.set(type, new Set())
    this.events.get(type).add(fn)
    return () => this.events.get(type)?.delete(fn)
  }
  addEventListener(type, fn) { this.on(type, fn) }
  removeEventListener(type, fn) { this.events.get(type)?.delete(fn) }
  emit(type, detail) {
    for (const fn of this.events.get(type) || []) {
      try { fn({ detail }) } catch (e) { dbg('[net] handler', e?.message || e) }
    }
  }

  addrsList(advertise) {
    const out = new Set()
    if (!this.port && !this.wsPort) return []
    const push = host => {
      if (this.port) { const m = toMa(`${host}:${this.port}`, this.id); if (m) out.add(m) }
      if (this.wsPort) { const m = toMa(`${host}:${this.wsPort}`, this.id, true); if (m) out.add(m) }
    }
    for (const list of Object.values(os.networkInterfaces())) {
      for (const i of list || []) {
        if (i.family !== 'IPv4' || i.internal || !usableV4(i.address)) continue
        push(i.address)
      }
    }
    push('127.0.0.1')
    const ad = advertise || this.advertise
    if (ad) {
      const host = String(ad).match(/^\[([^\]]+)\]/)?.[1] || String(ad).split(':')[0]
      if (host) push(host)
    }
    return [...out].slice(0, MAX_ADDR)
  }

  getMultiaddrs() { return this.addrsList(this.advertise).map(a => ({ toString: () => a })) }
  getConnections() {
    return [...this.conns].filter(c => c.ready).map(c => ({ remotePeer: { toString: () => c.peerId || '?' } }))
  }
  hasReliable(peerId) {
    for (const c of this.conns) if (c.ready && !c.udp && c.peerId === peerId) return true
    return false
  }
  addUdpTarget(host, port) {
    if (!this.wantUdp || !host || !port) return
    if (port === this.port && (host === '127.0.0.1' || host === 'localhost')) return
    const k = `${host}:${port}`
    if (this.udpTargets.size >= 32 || this.udpTargets.has(k)) return
    this.udpTargets.set(k, { host, port })
  }

  async start() {
    this.server = net.createServer(sock => this.attach(tcpWire(sock), null))
    const listen = p => new Promise((res, rej) => {
      const onErr = e => { this.server.off('error', onErr); rej(e) }
      this.server.once('error', onErr)
      this.server.listen(p, () => { this.server.off('error', onErr); res() })
    })
    try { await listen(this.wantPort) } catch {
      const alt = await freePort()
      console.error(`! warning port ${this.wantPort} unavailable -- listening on ${alt}`)
      await listen(alt)
    }
    this.port = this.server.address().port
    this.server.on('error', () => {})

    if (this.wantWs) {
      const mod = await getWs()
      if (!mod) console.error('! warning ws package missing -- WebSocket transport disabled (npm i ws)')
      else {
        try {
          this.wss = new mod.WebSocketServer({ port: this.wantWs, perMessageDeflate: false })
          this.wss.on('connection', ws => this.attach(wsWire(ws), null))
          this.wss.on('error', e => dbg('[net] ws server', e?.message || e))
          await new Promise((res, rej) => {
            this.wss.once('listening', res)
            this.wss.once('error', rej)
          })
          this.wsPort = this.wantWs
        } catch (e) {
          console.error(`! warning WebSocket listen on ${this.wantWs} failed -- disabled`)
          dbg('[net] ws', e?.message || e)
        }
      }
    }

    // UDP on the same port number: separate namespace from TCP
    if (this.wantUdp) {
      try {
        this.udp = dgram.createSocket({ type: 'udp4', reuseAddr: true })
        this.udp.on('message', (d, r) => this.onUdp(d, r))
        this.udp.on('error', e => dbg('[net] udp', e?.message || e))
        await new Promise((res, rej) => {
          const onErr = e => { this.udp.off('error', onErr); rej(e) }
          this.udp.once('error', onErr)
          this.udp.bind(this.port, () => { this.udp.off('error', onErr); res() })
        })
        this.udpPort = this.port
        this.punchTimer = setInterval(() => this.tick(), 1000)
        this.punchTimer.unref?.()
      } catch (e) {
        console.error(`! warning UDP bind on ${this.port} failed -- hole punching disabled`)
        dbg('[net] udp bind', e?.message || e)
        this.wantUdp = false
      }
    }
    dbg('[net] listening tcp', this.port, 'ws', this.wsPort || 'off', 'udp', this.udpPort || 'off', 'id', this.id)
  }

  async stop() {
    this.stopped = true
    clearInterval(this.punchTimer)
    try { this.server?.close() } catch {}
    try { this.wss?.close() } catch {}
    try { this.udp?.close() } catch {}
    for (const c of this.conns) { try { c.sock.destroy() } catch {} }
    this.conns.clear()
  }

  sendPunch(host, port) {
    if (!this.punchKey || !this.udp) return
    this.punchCtr = (this.punchCtr + 1) >>> 0
    try { this.udp.send(punchPacket(this.punchKey, this.punchCtr), port, host) } catch {}
  }

  tick() {
    if (this.stopped || !this.punchKey) return
    this.punchTick++
    const now = Date.now()
    // expired udp peers
    for (const [k, p] of this.udpPeers) {
      if (now - p.ts < UDP_TTL) continue
      if (p.conn) { try { p.conn.sock.destroy() } catch {}; this.conns.delete(p.conn) }
      this.udpPeers.delete(k)
    }
    if (this.udpPeers.size === 0 || this.punchTick % 5 === 0) {
      for (const t of this.udpTargets.values()) this.sendPunch(t.host, t.port)
      if (this.udpPeers.size) for (const p of this.udpPeers.values()) this.sendPunch(p.host, p.port)
    }
    if (this.punchReplies.size > 256) this.punchReplies.clear()
  }

  ensureUdp(host, port) {
    const k = `${host}:${port}`
    let p = this.udpPeers.get(k)
    if (!p) {
      p = { host, port, peerId: null, ts: Date.now(), conn: null }
      this.udpPeers.set(k, p)
    }
    p.ts = Date.now()
    if (!p.conn && this.session) {
      const w = {
        destroyed: false,
        kind: 'udp',
        remoteAddress: host,
        write: b => { if (!w.destroyed) { try { this.udp.send(b, p.port, p.host) } catch {} } },
        destroy: () => { w.destroyed = true },
        on: () => {}
      }
      p.conn = { sock: w, hp: { host, port, ws: false }, peerId: null, ready: false, buf: Buffer.alloc(0), udp: true }
      this.conns.add(p.conn)
      this.sendHello(p.conn)
    }
    return p
  }

  onUdp(d, r) {
    if (!this.punchKey) return
    const now = Date.now()
    if (isPunch(d)) {
      if (!validPunch(this.punchKey, d)) return
      const k = `${r.address}:${r.port}`
      if (now - (this.punchReplies.get(k) || 0) > 300) {
        this.punchReplies.set(k, now)
        this.sendPunch(r.address, r.port)
      }
      if (this.session) this.ensureUdp(r.address, r.port)
      return
    }
    if (d.length < 6) return
    const len = d.readUInt32BE(0)
    if (len !== d.length - 4 || d[4] < 1 || d[4] > 16) return
    const p = this.ensureUdp(r.address, r.port)
    p.ts = now
    if (!p.conn) return
    try { this.onFrame(p.conn, d[4], d.subarray(5)) } catch (e) { dbg('[net] udp frame', e?.message || e) }
  }

  async dial(ma) {
    try {
      const hp = hpOf(ma)
      if (!hp || this.stopped) return false
      if (!hp.ws) this.addUdpTarget(hp.host, hp.port)
      if (!hp.ws && hp.port === this.port) return false
      if (hp.ws && hp.port === this.wsPort) return false
      for (const c of this.conns) {
        if (c.hp && c.hp.host === hp.host && c.hp.port === hp.port && c.hp.ws === hp.ws) return true
      }
      let w = null
      try { w = await connectWire(hp.host, hp.port, hp.ws, 6000) } catch { return false }
      this.attach(w, hp)
      return true
    } catch { return false }
  }

  attach(wire, hp) {
    if (this.stopped) { try { wire.destroy() } catch {}; return }
    if (hp && !hp.ws) this.addUdpTarget(hp.host, hp.port)
    const conn = { sock: wire, hp, peerId: null, ready: false, buf: Buffer.alloc(0) }
    this.conns.add(conn)
    wire.on('data', d => this.onData(conn, d))
    wire.on('close', () => {
      this.conns.delete(conn)
      if (conn.ready) this.emit('peer:disconnect', { toString: () => conn.peerId })
    })
    if (this.session) this.sendHello(conn)
  }

  onData(conn, d) {
    conn.buf = conn.buf.length ? Buffer.concat([conn.buf, d]) : d
    for (;;) {
      if (conn.buf.length < 4) return
      const len = conn.buf.readUInt32BE(0)
      if (len < 1 || len > MAX_FRAME) { try { conn.sock.destroy() } catch {}; return }
      if (conn.buf.length < 4 + len) return
      const body = conn.buf.subarray(4, 4 + len)
      conn.buf = conn.buf.subarray(4 + len)
      try { this.onFrame(conn, body[0], body.subarray(1)) } catch (e) {
        dbg('[net] frame', e?.message || e)
        try { conn.sock.destroy() } catch {}
        return
      }
    }
  }

  onFrame(conn, type, payload) {
    if (type === T_JOIN) return this.onJoin(conn, payload)
    if (!this.session) { try { conn.sock.destroy() } catch {}; return }
    const plain = unseal(this.session.aes, type, payload)
    if (type === T_HELLO) {
      let m
      try { m = JSON.parse(plain.toString('utf8')) } catch { return }
      if (!m || typeof m.id !== 'string') return
      if (m.id === this.id) { try { conn.sock.destroy() } catch {}; return }
      if (conn.peerId && conn.peerId !== m.id) return
      conn.peerId = m.id
      // one connection per peer per class: reliable and udp may coexist
      for (const other of this.conns) {
        if (other === conn || !other.ready || other.peerId !== m.id) continue
        if (!!other.udp === !!conn.udp) { try { conn.sock.destroy() } catch {}; return }
      }
      if (!conn.ready) {
        conn.ready = true
        const how = conn.udp ? 'udp' : conn.hp ? `${conn.hp.host}:${conn.hp.port}${conn.hp.ws ? ' ws' : ''}` : 'inbound'
        dbg('[net] peer', m.id, 'on', how)
        this.emit('peer:connect', { toString: () => m.id })
      }
      if (Array.isArray(m.addrs)) {
        const list = m.addrs.filter(a => typeof a === 'string' && /\/p2p\//.test(a)).slice(0, MAX_ADDR)
        if (list.length) this.emit('addrs', list)
      }
      return
    }
    this.emit('message', { conn, type, payload: plain })
  }

  sendBytes(conn, buf) {
    if (!conn || !buf) return
    conn.sock.write(buf)
  }
  sendSealed(conn, type, payload) {
    if (!this.session) return
    this.sendBytes(conn, seal(this.session.aes, type, payload))
  }
  // repeat > 1 retransmits only on udp conns (datagrams are lossy)
  sendAll(type, payload, except, repeat = 1) {
    if (!this.session) return
    let buf = null
    for (const c of this.conns) {
      if (c === except || !c.ready) continue
      if (c.udp && this.hasReliable(c.peerId)) continue
      buf = buf || seal(this.session.aes, type, payload)
      this.sendBytes(c, buf)
      if (c.udp && repeat > 1) {
        for (let i = 1; i < repeat; i++) {
          const t = setTimeout(() => this.sendBytes(c, buf), i * 250)
          t.unref?.()
        }
      }
    }
  }
  sendHello(conn) {
    if (!this.session) return
    const body = Buffer.from(JSON.stringify({ id: this.id, name: this.session.name, addrs: this.addrsList(this.advertise), port: this.port }))
    this.sendSealed(conn, T_HELLO, body)
  }

  onJoin(conn, payload) {
    if (!this.join) { try { conn.sock.destroy() } catch {}; return }
    let req
    try { req = JSON.parse(payload.toString('utf8')) } catch { return }
    const { p, h } = req || {}
    if (typeof p !== 'string' || typeof h !== 'string' || !/^[0-9a-f]{64}$/.test(h)) {
      try { conn.sock.destroy() } catch {}
      return
    }
    let list = []
    try { list = this.join.getInvites() } catch {}
    const entry = list.find(x => x && x.tpc === 'c3tok/' + h)
    if (!entry) { dbg('[net] no invite for', h.slice(0, 12)); try { conn.sock.destroy() } catch {}; return }
    const replay = this.join.seen.has(h)
    const res = this.join.onRequest(entry, h, replay)
    if (!res) { try { conn.sock.destroy() } catch {}; return }
    this.join.seen.add(h)
    const cpub = Buffer.from(p, 'base64')
    const eph = ecdh()
    const shared = eph.computeSecret(cpub)
    const salt = sha(Buffer.concat([cpub, eph.getPublicKey()].sort(Buffer.compare)))
    const k = Buffer.from(crypto.hkdfSync('sha256', shared, salt, Buffer.from('c3join'), 32))
    // complete frames already: send as-is, do not wrap again
    this.sendBytes(conn, frame(T_JOINOK, Buffer.from(JSON.stringify({ p: eph.getPublicKey().toString('base64') }))))
    this.sendBytes(conn, seal(k, T_HELLO, Buffer.from(JSON.stringify({ name: res.name, key: res.key }))))
    dbg('[net] token accepted')
    setTimeout(() => { try { conn.sock.destroy() } catch {} }, 3000).unref?.()
  }
}

// ---------- client wire ----------
async function connectWire(host, port, useWs, wait) {
  if (!useWs) {
    return await new Promise((res, rej) => {
      const sock = net.connect({ host, port })
      const t = setTimeout(() => { try { sock.destroy() } catch {}; rej(new Error('timeout')) }, wait)
      sock.once('connect', () => { clearTimeout(t); sock.setTimeout(0); res(tcpWire(sock)) })
      sock.once('error', e => { clearTimeout(t); rej(e) })
    })
  }
  const mod = await getWs()
  if (!mod) throw new Error('ws package missing (npm i ws)')
  const url = `ws://${host.includes(':') ? `[${host}]` : host}:${port}/c3`
  const ws = new mod.WebSocket(url, { perMessageDeflate: false })
  await new Promise((res, rej) => {
    const t = setTimeout(() => { try { ws.terminate() } catch {}; rej(new Error('timeout')) }, wait)
    ws.once('open', () => { clearTimeout(t); res() })
    ws.once('error', e => { clearTimeout(t); rej(e) })
  })
  return wsWire(ws, 'ws-client')
}

export async function makeNode(ident, port, opts = {}) {
  const mesh = new Mesh(ident, port, opts)
  mesh.doc = new Y.Doc()
  await mesh.start()
  return mesh
}

// ---------- token join ----------
export function joinResponder(mesh, getInvites, onRequest) {
  mesh.join = { getInvites, onRequest, seen: new Set() }
}

async function joinOnce(host, port, token, wait, useWs) {
  let wire = null
  try { wire = await connectWire(host, port, useWs, wait) } catch (e) {
    dbg('[net] join connect', host, port, useWs ? 'ws' : 'tcp', e?.message || e)
    return null
  }
  return await new Promise(resolve => {
    let done = false
    let buf = Buffer.alloc(0)
    let k = null
    let timer = null
    const fin = v => {
      if (done) return
      done = true
      clearTimeout(timer)
      try { wire.destroy() } catch {}
      resolve(v)
    }
    try {
      const eph = ecdh()
      const h = sha(String(token)).toString('hex')
      timer = setTimeout(() => fin(null), wait)
      wire.write(frame(T_JOIN, Buffer.from(JSON.stringify({ p: eph.getPublicKey().toString('base64'), h }))))
      wire.on('close', () => fin(null))
      wire.on('data', d => {
        try {
          buf = buf.length ? Buffer.concat([buf, d]) : d
          for (;;) {
            if (buf.length < 4) return
            const len = buf.readUInt32BE(0)
            if (len < 1 || len > MAX_FRAME) return fin(null)
            if (buf.length < 4 + len) return
            const body = buf.subarray(4, 4 + len)
            buf = buf.subarray(4 + len)
            const type = body[0]
            const payload = body.subarray(1)
            if (type === T_JOINOK) {
              const m = JSON.parse(payload.toString('utf8'))
              const spub = Buffer.from(m.p, 'base64')
              const shared = eph.computeSecret(spub)
              const salt = sha(Buffer.concat([eph.getPublicKey(), spub].sort(Buffer.compare)))
              k = Buffer.from(crypto.hkdfSync('sha256', shared, salt, Buffer.from('c3join'), 32))
            } else if (type === T_HELLO && k) {
              const m = JSON.parse(unseal(k, type, payload).toString('utf8'))
              if (m && typeof m.name === 'string' && typeof m.key === 'string') return fin({ name: m.name, key: m.key })
              return fin(null)
            }
          }
        } catch (e) { dbg('[net] join frame', e?.message || e); fin(null) }
      })
    } catch (e) { dbg('[net] join threw', e?.message || e); fin(null) }
  })
}

export async function joinCall(mesh, invite, wait = 8000) {
  for (const a of invite.a || []) {
    const hp = hpOf(a)
    if (!hp) continue
    if (!usableV4(hp.host) && !hp.host.includes(':') && hp.host !== 'localhost') continue
    if (!hp.ws) mesh.addUdpTarget(hp.host, hp.port)
    dbg('[net] join', hp.host, hp.port, hp.ws ? 'ws' : 'tcp')
    const res = await joinOnce(hp.host, hp.port, invite.t, wait, hp.ws)
    if (res) return { ok: 1, name: res.name, key: res.key }
  }
  return null
}

// ---------- encrypted sync ----------
export function sync(mesh, name, key, doc, advertise, onAddrs = () => {}) {
  const aes = Buffer.from(crypto.hkdfSync('sha256', Buffer.from(key), Buffer.from('c3salt'), Buffer.from('c3msg'), 32))
  mesh.doc = doc
  mesh.session = { name, key, aes }
  mesh.punchKey = aes
  if (advertise) mesh.advertise = advertise
  const parts = new Map()
  const seen = new Set()
  const sendVec = () => mesh.sendAll(T_VECTOR, Buffer.from(Y.encodeStateVector(doc)), null, 2)
  const sendAddrs = () => mesh.sendAll(T_ADDRS, Buffer.from(JSON.stringify(mesh.addrsList(advertise))))
  dbg('[net] session', name, 'id', mesh.id)

  const sendUpdate = u => {
    const data = Buffer.from(u)
    const id = crypto.createHash('sha1').update(data).digest().subarray(0, 8)
    const count = Math.max(1, Math.ceil(data.length / CHUNK))
    dbg('[net] send update', data.length, 'bytes in', count, 'chunk(s)')
    for (let i = 0; i < count; i++) {
      const h = Buffer.allocUnsafe(13)
      h[0] = T_UPDATE
      id.copy(h, 1)
      h.writeUInt16BE(i, 9)
      h.writeUInt16BE(count, 11)
      mesh.sendAll(T_UPDATE, Buffer.concat([h, data.subarray(i * CHUNK, (i + 1) * CHUNK)]), null, 3)
    }
  }

  mesh.on('message', ev => {
    const { conn, type, payload } = ev.detail || {}
    if (!type || !payload) return
    if (type === T_VECTOR) {
      const diff = Y.encodeStateAsUpdate(doc, payload)
      if (diff.length > 2) sendUpdate(diff)
    } else if (type === T_UPDATE) {
      if (payload.length < 13) return
      const id = payload.subarray(1, 9).toString('hex')
      const i = payload.readUInt16BE(9)
      const count = payload.readUInt16BE(11)
      if (count < 1 || count > 4096 || i >= count) return
      let e = parts.get(id)
      if (!e) { e = { count, got: 0, buf: [] }; parts.set(id, e) }
      if (e.count !== count || e.buf[i]) return
      e.buf[i] = Buffer.from(payload.subarray(13))
      e.got++
      if (e.got === e.count) {
        parts.delete(id)
        const full = Buffer.concat(e.buf)
        const hash = crypto.createHash('sha1').update(full).digest('hex')
        if (seen.has(hash)) return
        seen.add(hash)
        if (seen.size > 2048) seen.clear()
        dbg('[net] recv update', full.length, 'bytes')
        try { Y.applyUpdate(doc, full, 'remote') } catch { return }
        for (const c of mesh.conns) {
          if (c === conn || !c.ready) continue
          if (c.udp && mesh.hasReliable(c.peerId)) continue
          mesh.sendSealed(c, T_UPDATE, payload)
        }
      }
      if (parts.size > 256) parts.clear()
    } else if (type === T_ADDRS) {
      let addrs
      try { addrs = JSON.parse(payload.toString('utf8')) } catch { return }
      if (Array.isArray(addrs)) onAddrs(addrs.filter(a => typeof a === 'string' && /\/p2p\//.test(a)).slice(0, MAX_ADDR))
    }
  })

  mesh.on('addrs', ev => { if (Array.isArray(ev.detail)) onAddrs(ev.detail) })
  mesh.on('peer:connect', () => { sendVec(); sendAddrs() })
  doc.on('update', (u, origin) => {
    if (origin !== 'remote' && origin !== 'restore') sendUpdate(u)
  })

  for (const c of mesh.conns) if (!c.ready) mesh.sendHello(c)
  const timer = setInterval(() => { sendVec(); sendAddrs() }, 8000)
  timer.unref?.()
  sendVec()
  sendAddrs()
  return { sendVec, sendAddrs }
}