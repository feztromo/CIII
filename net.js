// net.js -- libp2p transport, token join, encrypted gossip for c3.
// Join rides on gossipsub, so there is no custom stream protocol to break
// across libp2p majors. No DHT. No public relay. No third-party discovery.
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
import net from 'node:net'

const T_ADDR = 0
const T_VEC = 1
const T_CHUNK = 2
const CHUNK = 32 * 1024
const MAX_ADDR = 8
const JOIN_WAIT = 15000
const isMa = a => typeof a === 'string' && /^\/(ip4|ip6|dns)\//.test(a) && /\/tcp\/\d{1,5}\/p2p\/[^/]+$/.test(a)
const dbg = (...a) => { if (process.env.C3_DEBUG) console.error(...a) }
const topicOf = evt => {
  const t = evt?.detail?.topic
  return typeof t === 'string' ? t : t ? Buffer.from(t).toString() : ''
}
const dataOf = evt => {
  const d = evt?.detail?.data
  return d ? Buffer.from(d.subarray ? d.subarray() : d) : Buffer.alloc(0)
}

// ---------- keyed AEAD ----------
const sealWith = (key, b) => {
  const iv = crypto.randomBytes(12)
  const c = crypto.createCipheriv('aes-256-gcm', key, iv)
  const ct = Buffer.concat([c.update(b), c.final()])
  return Buffer.concat([iv, ct, c.getAuthTag()])
}
const openWith = (key, b) => {
  if (b.length < 29) throw new Error('short')
  const d = crypto.createDecipheriv('aes-256-gcm', key, b.subarray(0, 12))
  d.setAuthTag(b.subarray(b.length - 16))
  return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()])
}
export const tokenKey = tok => crypto.createHash('sha256').update('c3tok\0' + tok).digest()
export const tokenTopic = tok => 'c3join/' + crypto.createHash('sha256').update('c3join\0' + tok).digest('hex')
export const syncTopic = (name, key) => crypto.createHash('sha256').update('c3topic\0' + name + '\0' + key).digest('hex')

// ---------- identity ----------
export async function loadKey(file) {
  try {
    return await privateKeyFromRaw(Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'base64'))
  } catch {
    const key = await generateKeyPair('Ed25519')
    fs.writeFileSync(file, Buffer.from(key.raw).toString('base64'), { mode: 0o600 })
    return key
  }
}

// ---------- node ----------
const freePort = () => new Promise((res, rej) => {
  const s = net.createServer()
  s.once('error', rej)
  s.listen(0, '0.0.0.0', () => { const p = s.address().port; s.close(() => res(p)) })
})

export async function makeNode(key, port) {
  const want = Number(port)
  const p = Number.isInteger(want) && want > 0 ? want : await freePort()
  const build = q => createLibp2p({
    privateKey: key,
    addresses: { listen: [`/ip4/0.0.0.0/tcp/${q}`] },
    transports: [tcp()],
    connectionEncrypters: [noise()],
    streamMuxers: [yamux()],
    services: {
      identify: identify(),
      pubsub: gossipsub({ allowPublishToZeroTopicPeers: true })
    }
  })
  let n
  try {
    n = await build(p)
  } catch (e) {
    dbg('[listen]', p, e?.message || e)
    const alt = await freePort()
    console.error(`! warning port ${p} unavailable -- listening on ${alt}`)
    n = await build(alt)
  }
  try { await n.listen(`/ip6/::/tcp/${p}`) } catch {}
  dbg('[node] peer', n.peerId.toString(), 'port', p)
  return n
}

// ---------- addressing ----------
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
    if (/\/ip4\/(0\.0\.0\.0|169\.254\.)/.test(s)) continue
    if (/\/ip6\/(::1|::|fe80)/.test(s)) continue
    if (!s.includes('/p2p/')) s += `/p2p/${n.peerId}`
    out.add(s)
  }
  if (advertise) {
    const m = toMa(advertise, n.peerId)
    if (m) out.add(m)
  }
  return [...out]
}

// ---------- token join (host side) ----------
export function joinResponder(n, getInvites, onRequest) {
  const active = new Map()
  const served = new Map()

  const refresh = () => {
    let list = []
    try { list = getInvites() } catch { return }
    const now = Date.now()
    for (const inv of list) {
      if (!inv?.tpc || !inv?.sk) continue
      if (!(inv.exp > now)) { active.delete(inv.tpc); continue }
      if (active.has(inv.tpc)) continue
      active.set(inv.tpc, { sk: Buffer.from(inv.sk, 'base64'), entry: inv })
      try { Promise.resolve(n.services.pubsub.subscribe(inv.tpc)).catch(() => {}) } catch {}
      dbg('[invite] listening on', inv.tpc)
    }
  }

  n.services.pubsub.addEventListener('message', evt => {
    const tpc = topicOf(evt)
    const a = active.get(tpc)
    if (!a) return
    let req
    try { req = JSON.parse(openWith(a.sk, dataOf(evt)).toString('utf8')) } catch { return }
    if (!req || typeof req.n !== 'string' || req.n.length > 64) return
    dbg('[invite] request on', tpc)
    let set = served.get(tpc)
    if (!set) { set = new Set(); served.set(tpc, set) }
    if (set.size > 256) set.clear()
    const res = onRequest(a.entry, req.n, set.has(req.n))
    if (!res) return
    set.add(req.n)
    const body = Buffer.from(JSON.stringify({ n: req.n, name: res.name, key: res.key }))
    try {
      Promise.resolve(n.services.pubsub.publish(tpc, sealWith(a.sk, body)))
        .catch(e => dbg('[invite] reply', e?.message || e))
    } catch (e) { dbg('[invite] reply threw', e?.message || e) }
  })

  refresh()
  const t = setInterval(refresh, 3000)
  t.unref?.()
}

// ---------- token join (joiner side) ----------
export async function joinCall(n, invite, wait = JOIN_WAIT) {
  const sk = tokenKey(invite.t)
  const tpc = tokenTopic(invite.t)
  const nonce = crypto.randomBytes(8).toString('hex')

  for (const a of invite.a) {
    if (!isMa(a)) continue
    try { n.dial(multiaddr(a)).catch(() => {}) } catch {}
  }
  try { Promise.resolve(n.services.pubsub.subscribe(tpc)).catch(() => {}) } catch {}
  dbg('[join] listening on', tpc)
  await new Promise(r => setTimeout(r, 500))

  let settle = () => {}
  const got = new Promise(r => { settle = r })
  const onMsg = evt => {
    if (topicOf(evt) !== tpc) return
    let m
    try { m = JSON.parse(openWith(sk, dataOf(evt)).toString('utf8')) } catch { return }
    if (m?.n !== nonce || typeof m.name !== 'string' || typeof m.key !== 'string') return
    settle({ ok: 1, name: m.name, key: m.key })
  }
  n.services.pubsub.addEventListener('message', onMsg)

  const body = sealWith(sk, Buffer.from(JSON.stringify({ n: nonce })))
  const until = Date.now() + wait
  let out = null
  while (!out && Date.now() < until) {
    try {
      Promise.resolve(n.services.pubsub.publish(tpc, body))
        .catch(e => dbg('[join] publish', e?.message || e))
    } catch (e) { dbg('[join] publish threw', e?.message || e) }
    out = await Promise.race([got, new Promise(r => setTimeout(() => r(null), 1500))])
  }

  try { n.services.pubsub.removeEventListener('message', onMsg) } catch {}
  try { Promise.resolve(n.services.pubsub.unsubscribe(tpc)).catch(() => {}) } catch {}
  if (!out) dbg('[join] no reply on', tpc)
  return out
}

// ---------- encrypted gossip sync ----------
export function sync(n, name, key, doc, advertise, onAddrs = () => {}) {
  const topic = syncTopic(name, key)
  const aes = Buffer.from(crypto.hkdfSync('sha256', Buffer.from(key), Buffer.from('c3salt'), Buffer.from('c3msg'), 32))
  const parts = new Map()
  dbg('[sync] topic', topic)
  dbg('[sync] peer', n.peerId.toString())

  // publish -- NOT subscribe
  const pub = b => {
    try {
      Promise.resolve(n.services.pubsub.publish(topic, sealWith(aes, b)))
        .catch(e => dbg('[sync] publish', e?.message || e))
    } catch (e) { dbg('[sync] publish threw', e?.message || e) }
  }

  const sendVec = () => pub(Buffer.concat([Buffer.from([T_VEC]), Buffer.from(Y.encodeStateVector(doc))]))
  const sendAddr = () => pub(Buffer.concat([Buffer.from([T_ADDR]), Buffer.from(JSON.stringify(addrsOf(n, advertise)))]))

  const sendUpd = u => {
    const data = Buffer.from(u)
    const id = crypto.createHash('sha1').update(data).digest().subarray(0, 8)
    const count = Math.max(1, Math.ceil(data.length / CHUNK))
    dbg('[sync] send update', data.length, 'bytes in', count, 'chunk(s)')
    for (let i = 0; i < count; i++) {
      const h = Buffer.allocUnsafe(13)
      h[0] = T_CHUNK
      id.copy(h, 1)
      h.writeUInt16BE(i, 9)
      h.writeUInt16BE(count, 11)
      pub(Buffer.concat([h, data.subarray(i * CHUNK, (i + 1) * CHUNK)]))
    }
  }

  try { Promise.resolve(n.services.pubsub.subscribe(topic)).catch(() => {}) } catch {}

  const reportMesh = () => {
    try {
      const subs = n.services.pubsub.getSubscribers(topic) || []
      dbg('[sync] subscribers', subs.length)
    } catch {}
  }
  const meshTimer = setInterval(reportMesh, 10000)
  meshTimer.unref?.()

  n.services.pubsub.addEventListener('message', evt => {
    if (topicOf(evt) !== topic) return
    let b
    try { b = openWith(aes, dataOf(evt)) } catch { return }
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
        dbg('[sync] recv update', Buffer.concat(e.buf).length, 'bytes')
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
  const timer = setInterval(() => { sendVec(); sendAddr() }, 8000)
  timer.unref?.()
  sendVec()
  sendAddr()
  return { topic, sendVec, sendAddr }
}