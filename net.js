import crypto from 'node:crypto'
import net from 'node:net'
import dgram from 'node:dgram'
import os from 'node:os'
import fs from 'node:fs'
import * as Y from 'yjs'

const MAGIC = Buffer.from('C3PU'), MAX = 64 << 20, CHUNK = 65536
const fr = (t, b) => { const p = b || Buffer.alloc(0), h = Buffer.allocUnsafe(5); h.writeUInt32BE(p.length + 1, 0); h[4] = t; return Buffer.concat([h, p]) }
const seal = (k, t, b) => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', k, iv); c.setAAD(Buffer.from([t])); return fr(t, Buffer.concat([iv, Buffer.concat([c.update(Buffer.from(b)), c.final()]), c.getAuthTag()])) }
const open = (k, t, b) => { const d = crypto.createDecipheriv('aes-256-gcm', k, b.subarray(0,12)); d.setAAD(Buffer.from([t])); d.setAuthTag(b.subarray(b.length-16)); return Buffer.concat([d.update(b.subarray(12,-16)), d.final()]) }

export const loadKey = async f => { try { const j = JSON.parse(fs.readFileSync(f)); if (/^[0-9a-f]{16}$/.test(j.id)) return j } catch {} const k = { id: crypto.randomBytes(8).toString('hex') }; fs.writeFileSync(f, JSON.stringify(k), { mode: 0o600 }); return k }
export const toMa = (s, id) => { const m = String(s).match(/^([^:]+):(\d+)$/); if (!m) return null; const h = m[1]; return `${/^\d+\./.test(h) ? '/ip4/'+h : '/dns/'+h}/tcp/${+m[2]}/p2p/${id}` }
export const addrsOf = (n, adv) => n.addrs(adv)

export async function makeNode(ident, wantPort) {
  const id = ident.id, my = new Set(['127.0.0.1'])
  for (const i of Object.values(os.networkInterfaces()).flat()) if (i.family === 'IPv4' && !i.internal) my.add(i.address)

  const n = { id, port: 0, conns: new Set(), targs: new Set(), udps: new Map(), ev: {}, aes: null, pKey: null, stopped: false, _ctr: 0 }
  const on = (e, f) => { (n.ev[e] ||= new Set()).add(f); return () => n.ev[e].delete(f) }
  const emit = (e, d) => n.ev[e]?.forEach(f => { try { f({detail:d}) } catch {} })
  n.on = on; n.addEventListener = on
  n.peerId = { toString: () => id }
  n.getConnections = () => [...n.conns].filter(c => c.ok).map(c => ({ remotePeer: { toString: () => c.pid || '?' } }))
  n.addrs = adv => { const o = new Set(), push = h => o.add(`${/^\d+\./.test(h) ? '/ip4/'+h : '/dns/'+h}/tcp/${n.port}/p2p/${id}`)
    for (const i of Object.values(os.networkInterfaces()).flat()) if (i.family === 'IPv4' && !i.internal) push(i.address)
    push('127.0.0.1'); if (adv) { const h = String(adv).split(':')[0]; if (h) push(h) } return [...o] }

  const tcp = net.createServer(s => {
    const c = { s, udp: false, buf: Buffer.alloc(0), pid: null, ok: false, host: s.remoteAddress, port: s.remotePort, w: b => { try { s.write(b) } catch {} }, d: () => { c.ok = false; try { s.destroy() } catch {} n.conns.delete(c) } }
    n.conns.add(c); s.on('close', () => { n.conns.delete(c); if (c.ok) emit('peer:disconnect', c) }).on('error', () => {}).setNoDelay(true).setKeepAlive(true, 10000)
    s.on('data', d => { c.buf = c.buf.length ? Buffer.concat([c.buf, d]) : d; while (c.buf.length >= 4) { const l = c.buf.readUInt32BE(0); if (l < 1 || l > MAX) return c.d(); if (c.buf.length < 4+l) return; const b = c.buf.subarray(4, 4+l); c.buf = c.buf.subarray(4+l); try { handle(c, b[0], b.subarray(1)) } catch { c.d() } } })
    if (n.aes) hello(c)
  })
  await new Promise((res, rej) => { tcp.once('error', rej); tcp.listen(+wantPort || 8421, res) })
  n.port = tcp.address().port

  const u = dgram.createSocket({ type: 'udp4', reuseAddr: true }); let ub = false
  u.on('message', (d, r) => {
    if (d.length === 24 && d[0] === 0x43 && d[1] === 0x33 && d[2] === 0x50 && d[3] === 0x55) {
      if (!n.pKey || my.has(r.address)) return
      const mac = crypto.createHmac('sha256', n.pKey).update(d.subarray(0,8)).digest().subarray(0,16)
      if (!crypto.timingSafeEqual(mac, d.subarray(8,24))) return
      punch(r.address, r.port, true)
      if (n.aes) hello(getUdp(r.address, r.port))
    } else if (d.length >= 5 && d.readUInt32BE(0) === d.length-4 && d[4] >= 1 && d[4] <= 16) {
      const c = getUdp(r.address, r.port); c.ts = Date.now(); try { handle(c, d[4], d.subarray(5)) } catch {}
    }
  })
  try { await new Promise((res, rej) => { u.once('error', rej); u.bind(n.port, () => { u.off('error', rej); res() }) }); u.setBroadcast(true); ub = true } catch { console.error('! UDP disabled') }

  const getUdp = (host, port) => { const k = `${host}:${port}`; let c = n.udps.get(k)
    if (!c) { c = { udp: true, host, port, buf: Buffer.alloc(0), pid: null, ok: false, ts: Date.now(), w: b => { try { u.send(b, port, host) } catch {} }, d: () => { c.ok = false; n.udps.delete(k); n.conns.delete(c) } }; n.udps.set(k, c); n.conns.add(c); if (n.aes) hello(c) }
    c.ts = Date.now(); return c }
  const punch = (h, p) => { if (!n.pKey || !ub) return; const b = Buffer.allocUnsafe(24); MAGIC.copy(b); b.writeUInt32BE(++n._ctr >>> 0, 4); crypto.createHmac('sha256', n.pKey).update(b.subarray(0,8)).digest().subarray(0,16).copy(b,8); try { u.send(b, p, h) } catch {} }
  const hello = c => { if (!n.aes) return; c.w(seal(n.aes, 3, Buffer.from(JSON.stringify({ id, addrs: n.addrs() })))) }
  const handle = (c, t, b) => {
    if (!n.aes) return c.d()
    if (t === 3) { const m = JSON.parse(open(n.aes, t, b).toString()); if (m.id === id) return c.d(); if (c.pid && c.pid !== m.id) return; c.pid = m.id; if (!c.ok) { c.ok = true; emit('peer:connect', c) } if (m.addrs) emit('addrs', m.addrs); return }
    emit('message', { conn: c, type: t, payload: open(n.aes, t, b) })
  }

  n.dial = async ma => { const m = String(ma).match(/^\/(?:ip4|dns)\/([^/]+)\/tcp\/(\d+)\/p2p\//); if (!m) return false; n.targs.add(`${m[1]}:${m[2]}`)
    try { const s = net.connect({ host: m[1], port: +m[2] }), c = { s, udp: false, buf: Buffer.alloc(0), pid: null, ok: false, host: m[1], port: +m[2], w: b => { try { s.write(b) } catch {} }, d: () => { c.ok = false; try { s.destroy() } catch {} n.conns.delete(c) } }
      await new Promise((res, rej) => { const t = setTimeout(() => { c.d(); rej('to') }, 5000); s.once('connect', () => { clearTimeout(t); res() }); s.once('error', e => { clearTimeout(t); rej(e) }) })
      n.conns.add(c); s.on('close', () => { n.conns.delete(c); if (c.ok) emit('peer:disconnect', c) }).on('error', () => {}).setNoDelay(true).setKeepAlive(true, 10000)
      s.on('data', d => { c.buf = c.buf.length ? Buffer.concat([c.buf, d]) : d; while (c.buf.length >= 4) { const l = c.buf.readUInt32BE(0); if (l < 1 || l > MAX) return c.d(); if (c.buf.length < 4+l) return; const b = c.buf.subarray(4, 4+l); c.buf = c.buf.subarray(4+l); try { handle(c, b[0], b.subarray(1)) } catch { c.d() } } })
      if (n.aes) hello(c); return true } catch { return false } }

  n.sendAll = (t, b, skip, rep = 1) => { if (!n.aes) return; const p = seal(n.aes, t, b); for (const c of n.conns) { if (!c.ok || c === skip) continue; c.w(p); if (c.udp && rep > 1) for (let i = 1; i < rep; i++) setTimeout(() => c.w(p), i * 150) } }
  n.stop = () => { n.stopped = true; tcp.close(); try { u.close() } catch {} n.conns.forEach(c => { try { c.d() } catch {} }) }

  const tick = setInterval(() => { if (n.stopped) return clearInterval(tick); if (n.pKey) { for (const t of n.targs) { const [h,p] = t.split(':'); punch(h, +p) } for (const c of n.udps.values()) punch(c.host, c.port); try { punch('255.255.255.255', n.port) } catch {} } if (n.aes) for (const c of n.conns) if (c.udp && !c.ok) hello(c); const now = Date.now(); for (const [k,c] of n.udps) if (now - c.ts > 30000) c.d() }, 1000)
  return n
}

export function sync(mesh, key, doc, advertise, onAddrs) {
  const aes = Buffer.from(crypto.hkdfSync('sha256', Buffer.from(key), Buffer.from('c3salt'), Buffer.from('msg'), 32))
  mesh.aes = aes; mesh.pKey = aes
  const parts = new Map()
  mesh.on('peer:connect', () => { mesh.sendAll(4, Buffer.from(Y.encodeStateVector(doc)), null, 2); onAddrs?.(mesh.addrs(advertise)) })
  mesh.on('message', ev => {
    const { conn, type, payload } = ev.detail || ev
    if (type === 4) { const d = Y.encodeStateAsUpdate(doc, payload); if (d.length > 2) mesh.sendAll(5, Buffer.from(d)) }
    else if (type === 5) {
      if (payload.length < 13) return
      const id = payload.subarray(1,9).toString('hex'), i = payload.readUInt16BE(9), n = payload.readUInt16BE(11), chunk = payload.subarray(13)
      if (n < 1 || i >= n) return; let o = parts.get(id); if (!o) { o = { n, got: 0, ch: [] }; parts.set(id, o) }
      if (o.n !== n || o.ch[i]) return; o.ch[i] = chunk; o.got++
      if (o.got === n) { parts.delete(id); try { Y.applyUpdate(doc, Buffer.concat(o.ch), 'remote') } catch { return } mesh.sendAll(5, payload, conn) }
      if (parts.size > 256) parts.clear()
    } else if (type === 6 && onAddrs) { let a; try { a = JSON.parse(payload.toString()) } catch { return } if (Array.isArray(a)) onAddrs(a.filter(x => typeof x === 'string').slice(0, 12)) }
  })
  doc.on('update', (u, o) => { if (o === 'remote' || o === 'restore') return; const data = Buffer.from(u), hash = crypto.createHash('sha1').update(data).digest().subarray(0, 8), n = Math.max(1, Math.ceil(data.length / CHUNK))
    for (let i = 0; i < n; i++) { const h = Buffer.allocUnsafe(13); h[0] = 5; hash.copy(h, 1); h.writeUInt16BE(i, 9); h.writeUInt16BE(n, 11); mesh.sendAll(5, Buffer.concat([h, data.subarray(i * CHUNK, (i + 1) * CHUNK)]), null, 3) } })
}