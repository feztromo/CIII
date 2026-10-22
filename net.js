// net.js -- libp2p transport, token join, encrypted gossip for c3.
// No DHT. No public relay. No third-party discovery.
import * as Y from 'yjs'
import { createLibp2p } from 'libp2p'
import { tcp } from '@libp2p/tcp'
import { noise } from '@chainsafe/libp2p-noise'
import { yamux } from '@chainsafe/libp2p-yamux'
import { identify } from '@libp2p/identify'
import { gossipsub } from '@chainsafe/libp2p-gossipsub'
import { generateKeyPair, privateKeyFromRaw } from '@libp2p/crypto/keys'
import { multiaddr } from '@multiformats/multiaddr'
import crypto from 'node:crypto'
import fs from 'node:fs'

const AUTH = '/c3/auth/1'
const T_ADDR = 0
const T_VEC = 1
const T_CHUNK = 2
const CHUNK = 32 * 1024
const MAX_ADDR = 8
const one = b => (async function* () { yield b })()
const isMa = a => typeof a === 'string' && /^\/(ip4|ip6|dns)\//.test(a) && /\/tcp\/\d{1,5}\/p2p\/[^/]+$/.test(a)

export async function loadKey(file) {
  try {
    return await privateKeyFromRaw(Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'base64'))
  } catch {
    const { privateKey } = await generateKeyPair('Ed25519')
    fs.writeFileSync(file, Buffer.from(privateKey.raw).toString('base64'), { mode: 0o600 })
    return privateKey
  }
}

export async function makeNode(key, port) {
  const n = await createLibp2p({
    privateKey: key,
    addresses: { listen: [`/ip4/0.0.0.0/tcp/${port}`] },
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    services: { identify: identify(), pubsub: gossipsub() }
  })
  try { await n.listen(`/ip6/::/tcp/${port}`) } catch {}
  return n
}

export function toMa(hp, id) {
  const s = String(hp || '').trim()
  const m = s.match(/^\[([^\]]+)\]:(\d+)$/) || s.match(/^([^:]+):(\d+)$/)
  if (!m) return null
  const port = Number(m[2])
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null
  const host = m[1]
  const base = host.includes(':') ? `/ip6/${host}`
    : (/^\d+\.\d+\.\d+\.\d+$/.test(host) ? `/ip4/${host}` : `/dns/${host}`)
  return `${base}/tcp/${port}/p2p/${id}`
}

export function addrsOf(n, advertise) {
  const out = new Set()
  for (const a of n.getMultiaddrs()) {
    let s = a.toString()
    if (/\/ip4\/(127\.|0\.0\.0\.0|169\.254\.)/.test(s)) continue
    if (/\/ip6\/(::1|::)\//.test(s) || /\/ip6\/fe80/.test(s)) continue
    if (!s.includes('/p2p/')) s += `/p2p/${n.peerId}`
    out.add(s)
  }
  if (advertise) {
    const m = toMa(advertise, n.peerId)
    if (m) out.add(m)
  }
  return [...out]
}

export function authServer(n, handler) {
  n.handle(AUTH, async ({ stream, connection }) => {
    let out = Buffer.from(JSON.stringify({ ok: 0 }))
    try {
      const chunks = []
      let len = 0
      for await (const c of stream.source) {
        len += c.length
        if (len > 8192) throw new Error('too big')
        chunks.push(Buffer.from(c.subarray()))
      }
      const req = JSON.parse(Buffer.concat(chunks).toString('utf8'))
      const res = await handler(req, connection.remotePeer.toString())
      if (res) out = Buffer.from(JSON.stringify(res))
    } catch {}
    try { await stream.sink(one(out)) } catch {}
  })
}

export async function authCall(n, addrs, req) {
  const body = Buffer.from(JSON.stringify(req))
  for (const a of addrs) {
    if (!isMa(a)) continue
    let stream = null
    try {
      stream = await Promise.race([
        n.dialProtocol(multiaddr(a), AUTH),
        new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 8000))
      ])
      await stream.sink(one(body))
      const chunks = []
      let len = 0
      for await (const c of stream.source) {
        len += c.length
        if (len > 8192) throw new Error('too big')
        chunks.push(Buffer.from(c.subarray()))
      }
      const res = JSON.parse(Buffer.concat(chunks).toString('utf8'))
      if (res?.ok) return res
    } catch {}
    finally { try { stream?.abort?.() } catch {} }
  }
  return null
}

export function sync(n, name, key, doc, advertise, onAddrs = () => {}) {
  const topic = crypto.createHash('sha256').update('c3topic\0' + name + '\0' + key).digest('hex')
  const aes = Buffer.from(crypto.hkdfSync('sha256', Buffer.from(key), Buffer.from('c3salt'), Buffer.from('c3msg'), 32))
  const parts = new Map()

  const seal = b => {
    const iv = crypto.randomBytes(12)
    const c = crypto.createCipheriv('aes-256-gcm', aes, iv)
    const ct = Buffer.concat([c.update(b), c.final()])
    return Buffer.concat([iv, ct, c.getAuthTag()])
  }
  const open = b => {
    const d = crypto.createDecipheriv('aes-256-gcm', aes, b.subarray(0, 12))
    d.setAuthTag(b.subarray(b.length - 16))
    return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()])
  }
  const pub = b => n.services.pubsub.publish(topic, seal(b)).catch(() => {})
  const sendVec = () => pub(Buffer.concat([Buffer.from([T_VEC]), Buffer.from(Y.encodeStateVector(doc))]))
  const sendAddr = () => pub(Buffer.concat([Buffer.from([T_ADDR]), Buffer.from(JSON.stringify(addrsOf(n, advertise)))]))

  const sendUpd = u => {
    const data = Buffer.from(u)
    const id = crypto.createHash('sha1').update(data).digest().subarray(0, 8)
    const count = Math.max(1, Math.ceil(data.length / CHUNK))
    for (let i = 0; i < count; i++) {
      const h = Buffer.allocUnsafe(13)
      h[0] = T_CHUNK
      id.copy(h, 1)
      h.writeUInt16BE(i, 9)
      h.writeUInt16BE(count, 11)
      pub(Buffer.concat([h, data.subarray(i * CHUNK, (i + 1) * CHUNK)]))
    }
  }

  n.services.pubsub.subscribe(topic)
  n.services.pubsub.addEventListener('message', evt => {
    if (evt.detail.topic !== topic) return
    let b
    try { b = open(Buffer.from(evt.detail.data)) } catch { return }
    const t = b[0]
    if (t === T_VEC) {
      const diff = Y.encodeStateAsUpdate(doc, b.subarray(1))
      if (diff.length > 2) sendUpd(diff)
    } else if (t === T_CHUNK) {
      if (b.length < 13) return
      const id = b.subarray(1, 9).toString('hex')
      const i = b.readUInt16BE(9)
      const count = b.readUInt16BE(11)
      if (count < 1 || count > 4096 || i >= count) return
      let e = parts.get(id)
      if (!e) { e = { count, got: 0, buf: [] }; parts.set(id, e) }
      if (e.count !== count || e.buf[i]) return
      e.buf[i] = Buffer.from(b.subarray(13))
      e.got++
      if (e.got === e.count) {
        parts.delete(id)
        try { Y.applyUpdate(doc, Buffer.concat(e.buf), 'remote') } catch {}
      }
      if (parts.size > 256) parts.clear()
    } else if (t === T_ADDR) {
      let addrs
      try { addrs = JSON.parse(b.subarray(1).toString('utf8')) } catch { return }
      if (Array.isArray(addrs)) onAddrs(addrs.filter(isMa).slice(0, MAX_ADDR))
    }
  })

  doc.on('update', (u, origin) => {
    if (origin !== 'remote' && origin !== 'restore') sendUpd(u)
  })
  n.addEventListener('peer:connect', () => { sendVec(); sendAddr() })
  sendVec()
  sendAddr()
  return { topic, sendVec, sendAddr }
}
