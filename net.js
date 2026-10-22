// net.js -- plain-TCP transport for c3.
// No libp2p, no DHT, no relays, no third-party discovery.
// Frame: [u32 length][u8 type][payload]. JOIN/JOINOK carry a P-256
// handshake; everything else is AES-256-GCM with the session key.
import crypto from 'node:crypto'
import net from 'node:net'
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
const MAX_ADDR = 8
const dbg = (...a) => { if (process.env.C3_DEBUG) console.error(...a) }
const sha = b => crypto.createHash('sha256').update(b).digest()

export const tokenTopic = tok => 'c3tok/' + sha(String(tok)).toString('hex')
export const tokenKey = tok => sha('c3tokkey\0' + String(tok))

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
export function toMa(hp, id) {
  const s = String(hp || '').trim()
  const m = s.match(/^\[([^\]]+)\]:(\d+)$/) || s.match(/^([^:]+)(?::(\d+))?$/)
  if (!m) return null
  const port = Number(m[2] || 8443)
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null
  const host = m[1]
  const base = host.includes(':') ? `/ip6/${host}`
    : (/^\d+\.\d+\.\d+\.\d+$/.test(host) ? `/ip4/${host}` : `/dns/${host}`)
  return `${base}/tcp/${port}/p2p/${id}`
}

const hpOf = ma => {
  const s = String(ma || '')
  let m = s.match(/^\/ip4\/([^/]+)\/tcp\/(\d+)/) || s.match(/^\/dns\/([^/]+)\/tcp\/(\d+)/)
  if (m) return { host: m[1], port: Number(m[2]) }
  m = s.match(/^\/ip6\/([^/]+)\/tcp\/(\d+)/)
  if (m) return { host: m[1], port: Number(m[2]) }
  return null
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

// ---------- mesh ----------
class Mesh {
  constructor(ident, port) {
    this.ident = ident
    this.id = ident.id
    this.peerId = { toString: () => this.id }
    this.wantPort = Number(port) > 0 ? Number(port) : 0
    this.port = this.wantPort
    this.conns = new Set()
    this.events = new Map()
    this.session = null
    this.join = null
    this.advertise = ''
    this.stopped = false
  }

  on(type, fn) {
    if (!this.events.has(type)) this.events.set(type, new Set())
    this.events.get(type).add(fn)
    return () => this.events.get(type)?.delete(fn)
  }
  addEventListener(type, fn) { this.on(type, fn) }
  removeEventListener(type, fn) { this.events.get(type)?.delete(fn) }
  // handlers always receive { detail }
  emit(type, detail) {
    for (const fn of this.events.get(type) || []) {
      try { fn({ detail }) } catch (e) { dbg('[net] handler', e?.message || e) }
    }
  }

  addrsList(advertise) {
    const out = new Set()
    const port = this.port || this.wantPort
    if (!port) return []
    for (const list of Object.values(os.networkInterfaces())) {
      for (const i of list || []) {
        if (i.family !== 'IPv4' || i.internal) continue
        if (!usableV4(i.address)) continue
        const ma = toMa(`${i.address}:${port}`, this.id)
        if (ma) out.add(ma)
      }
    }
    const lo = toMa(`127.0.0.1:${port}`, this.id)
    if (lo) out.add(lo)
    const ad = advertise || this.advertise
    if (ad) {
      const ma = toMa(ad, this.id)
      if (ma) out.add(ma)
    }
    return [...out].slice(0, MAX_ADDR + 2)
  }

  getMultiaddrs() { return this.addrsList(this.advertise).map(a => ({ toString: () => a })) }
  getConnections() {
    return [...this.conns].filter(c => c.ready).map(c => ({ remotePeer: { toString: () => c.peerId || '?' } }))
  }

  async start() {
    this.server = net.createServer(sock => this.attach(sock, null))
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
    dbg('[net] listening on', this.port, 'id', this.id)
  }

  async stop() {
    this.stopped = true
    try { this.server?.close() } catch {}
    for (const c of this.conns) { try { c.sock.destroy() } catch {} }
    this.conns.clear()
  }

  dial(ma) {
    try {
      const hp = hpOf(ma)
      if (!hp || this.stopped) return Promise.resolve(false)
      if (hp.port === this.port) return Promise.resolve(false)
      for (const c of this.conns) {
        if (c.hp && c.hp.host === hp.host && c.hp.port === hp.port) return Promise.resolve(true)
      }
      return new Promise(res => {
        const sock = net.connect({ host: hp.host, port: hp.port })
        sock.setTimeout(6000, () => { try { sock.destroy() } catch {} })
        sock.once('connect', () => { sock.setTimeout(0); this.attach(sock, hp); res(true) })
        sock.once('error', () => { try { sock.destroy() } catch {}; res(false) })
      })
    } catch { return Promise.resolve(false) }
  }

  attach(sock, hp) {
    if (this.stopped) { try { sock.destroy() } catch {}; return }
    const conn = { sock, hp, peerId: null, ready: false, buf: Buffer.alloc(0) }
    this.conns.add(conn)
    sock.setNoDelay(true)
    sock.setKeepAlive(true, 10000)
    sock.on('data', d => this.onData(conn, d))
    sock.on('error', () => {})
    sock.on('close', () => {
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
      // one live connection per peer: keep the first, drop the duplicate
      for (const other of this.conns) {
        if (other !== conn && other.ready && other.peerId === m.id) {
          try { conn.sock.destroy() } catch {}
          return
        }
      }
      if (!conn.ready) {
        conn.ready = true
        dbg('[net] peer', m.id, 'on', conn.hp ? `${conn.hp.host}:${conn.hp.port}` : 'inbound')
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

  // writes bytes as-is: callers pass an already framed or already sealed buffer
  sendBytes(conn, buf) {
    if (!conn || conn.sock.destroyed || !buf) return
    try { conn.sock.write(buf) } catch {}
  }
  sendSealed(conn, type, payload) {
    if (!this.session) return
    this.sendBytes(conn, seal(this.session.aes, type, payload))
  }
  sendAll(type, payload, except) {
    for (const c of this.conns) if (c !== except && c.ready) this.sendSealed(c, type, payload)
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
    // sendBytes: these are COMPLETE frames already, do not wrap them again
    this.sendBytes(conn, frame(T_JOINOK, Buffer.from(JSON.stringify({ p: eph.getPublicKey().toString('base64') }))))
    this.sendBytes(conn, seal(k, T_HELLO, Buffer.from(JSON.stringify({ name: res.name, key: res.key }))))
    dbg('[net] token accepted')
    setTimeout(() => { try { conn.sock.destroy() } catch {} }, 3000).unref?.()
  }
}

export async function makeNode(ident, port) {
  const mesh = new Mesh(ident, port)
  mesh.doc = new Y.Doc()
  await mesh.start()
  return mesh
}

// ---------- token join ----------
export function joinResponder(mesh, getInvites, onRequest) {
  mesh.join = { getInvites, onRequest, seen: new Set() }
}

function joinOnce(host, port, token, wait) {
  return new Promise(resolve => {
    let done = false
    let buf = Buffer.alloc(0)
    let k = null
    let sock = null
    let timer = null
    const fin = v => {
      if (done) return
      done = true
      clearTimeout(timer)
      try { sock?.destroy() } catch {}
      resolve(v)
    }
    try {
      const eph = ecdh()
      const h = sha(String(token)).toString('hex')
      sock = net.connect({ host, port })
      sock.setTimeout(wait, () => fin(null))
      sock.on('error', () => fin(null))
      sock.on('connect', () => {
        sock.write(frame(T_JOIN, Buffer.from(JSON.stringify({ p: eph.getPublicKey().toString('base64'), h }))))
      })
      timer = setTimeout(() => fin(null), wait)
      sock.on('data', d => {
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
    dbg('[net] join', hp.host, hp.port)
    const res = await joinOnce(hp.host, hp.port, invite.t, wait)
    if (res) return { ok: 1, name: res.name, key: res.key }
  }
  return null
}

// ---------- encrypted sync ----------
export function sync(mesh, name, key, doc, advertise, onAddrs = () => {}) {
  const aes = Buffer.from(crypto.hkdfSync('sha256', Buffer.from(key), Buffer.from('c3salt'), Buffer.from('c3msg'), 32))
  mesh.doc = doc
  mesh.session = { name, key, aes }
  if (advertise) mesh.advertise = advertise
  const parts = new Map()
  const seen = new Set()
  const sendVec = () => mesh.sendAll(T_VECTOR, Buffer.from(Y.encodeStateVector(doc)))
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
      mesh.sendAll(T_UPDATE, Buffer.concat([h, data.subarray(i * CHUNK, (i + 1) * CHUNK)]))
    }
  }

  // emit() wraps in { detail } -- unwrap here, that was the dropped-update bug
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
        for (const c of mesh.conns) if (c !== conn && c.ready) mesh.sendSealed(c, T_UPDATE, payload)
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