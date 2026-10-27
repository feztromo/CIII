#!/usr/bin/env node
// c3 -- minimal P2P live session.  Drop this + the new net.js into c3/, then:
//   node c3.js config
//   node c3.js connect
//   node c3.js share        <- paste once to the other peer
//   node c3.js peer "<ma>"  <- paste their share block here
// No host, no DHT, no relay.  One pasted address pair is enough; afterwards
// net.js retries UDP punches through ufw automatically.
import * as Y from 'yjs'
import readline from 'node:readline/promises'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import os from 'node:os'
import crypto from 'node:crypto'
import { loadKey, makeNode, sync, toMa } from './net.js'

const argv = process.argv.slice(2), cmd = argv[0]
const flag = n => { const i = argv.indexOf('--' + n); return i >= 0 && argv[i+1] ? argv[i+1] : undefined }
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
const SCAN_MS = 8000

const sleep = ms => new Promise(r => setTimeout(r, ms))
const die = m => { console.error(m); process.exit(1) }
const mkdirp = a => fs.mkdirSync(a, { recursive: true })
const atomicWrite = (abs, data) => { const tmp = abs + '.tmp-' + process.pid + '-' + crypto.randomBytes(4).toString('hex'); fs.writeFileSync(tmp, data); fs.renameSync(tmp, abs) }
const C = IS_WIN ? {r:'',d:'',red:'',grn:'',yel:'',cyn:''} : {r:'\x1b[0m', d:'\x1b[2m', red:'\x1b[31m', grn:'\x1b[32m', yel:'\x1b[33m', cyn:'\x1b[36m'}
const ui = {
  set(msg) { if (process.stdout.isTTY) process.stdout.write(`\r\x1b[K* c3 ${msg}`) },
  clear() { if (process.stdout.isTTY) process.stdout.write('\r\x1b[K') },
  say(...a) { this.clear(); console.log('* c3', ...a) },
  warn(...a) { this.clear(); console.error('! warning', ...a) }
}
const git = (...a) => execFileSync('git', a, { cwd: workDir, encoding: 'utf8', maxBuffer: 1 << 26 }).trim()
const gitOk = (...a) => { try { return git(...a) } catch { return null } }
const readConfig = () => { try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) } catch { return null } }

const sidOf = name => crypto.createHash('sha256').update('c3sid\0' + name).digest()
const sdirOf = name => { const d = path.join(SESSION_DIR, 's', sidOf(name).toString('hex').slice(0, 32)); mkdirp(d); return d }
const readKey = sdir => { try { return fs.readFileSync(path.join(sdir, 'key'), 'utf8').trim() } catch { return null } }
const writeKey = (sdir, key) => atomicWrite(path.join(sdir, 'key'), key)
const peersFile = sdir => path.join(sdir, 'peers.json')
const readPeers = sdir => { try { const a = JSON.parse(fs.readFileSync(peersFile(sdir), 'utf8')); return Array.isArray(a) ? a.filter(x => typeof x === 'string' && x.length < 500).slice(0, 64) : [] } catch { return [] } }
const readIdentity = () => { try { const j = JSON.parse(fs.readFileSync(path.join(SESSION_DIR, 'identity.key'), 'utf8')); if (/^[0-9a-f]{16}$/.test(j.id)) return j } catch {} return null }
const lanAddrs = (id, port) => {
  const out = []
  for (const list of Object.values(os.networkInterfaces())) {
    for (const i of list || []) {
      if (i.family !== 'IPv4' || i.internal || i.address.startsWith('169.254.')) continue
      const ma = toMa(`${i.address}:${port}`, id)
      if (ma) out.push(ma)
    }
  }
  return out
}

const DEFAULT_IGNORE = ['.git', '.c3', 'node_modules', 'dist', 'build', 'out', '.env*', '*.pem', 'id_rsa*', '*.log', '.DS_Store', 'Thumbs.db', 'desktop.ini', '*.tmp', '*.tmp-*']
let customRules = []
function globRe(p) {
  p = p.replace(/\/$/, '')
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
    try { execFileSync('git', ['check-ignore', '-q', '--', rel], { cwd: workDir, stdio: 'ignore' }); v = true } catch { v = false }
    if (ignoredCache.size > 50000) ignoredCache.clear()
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
  if (data.length > MAX_FILE) { ui.warn('skipped oversized file:', norm); return }
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
    if (bin) {
      const cur = blobs.get(entry.id)
      if (!cur || Buffer.compare(asBuf(cur), data) !== 0) { blobs.set(entry.id, new Uint8Array(data)); if (!seed) touched.add(norm) }
    } else {
      const t = texts.get(entry.id); if (t && applyDiff(t, data.toString('utf8')) && !seed) touched.add(norm)
    }
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
  const rel = safeRel(rawRel)
  if (!rel || rel !== rawRel) { ui.warn('blocked unsafe path:', rawRel); return }
  if (shouldIgnore(rel)) { ui.warn('blocked ignored path:', rel); return }
  const abs = path.join(workDir, rel)
  if (symlinkEscape(abs)) { ui.warn('blocked symlink:', rel); return }
  let data
  if (entry.bin) { const b = blobs.get(entry.id); data = b ? asBuf(b) : Buffer.alloc(0) }
  else data = Buffer.from(texts.get(entry.id)?.toString() ?? '', 'utf8')
  if (data.length > MAX_FILE) { ui.warn('blocked oversized:', rel); return }
  try {
    if (fs.existsSync(abs) && Buffer.compare(fs.readFileSync(abs), data) === 0) return
    mkdirp(path.dirname(abs)); atomicWrite(abs, data); lastWritten.set(rel, Date.now())
    try { const st = fs.statSync(abs); diskMeta.set(rel, st.mtimeMs + ':' + st.size) } catch {}
  } catch (err) { ui.warn('write failed:', rel, err.message) }
}
function scheduleWrite(rel) { clearTimeout(pendingWrites.get(rel)); pendingWrites.set(rel, setTimeout(() => { pendingWrites.delete(rel); writeToDisk(rel) }, WRITE_DEBOUNCE_MS)) }
function cancelWrite(rel) { clearTimeout(pendingWrites.get(rel)); pendingWrites.delete(rel) }
function flushWrites() { for (const [rel, t] of pendingWrites) { clearTimeout(t); writeToDisk(rel) } pendingWrites.clear() }

files.observe(ev => {
  for (const [key, change] of ev.keys) {
    if (change.action === 'delete') { const old = change.oldValue; if (old?.id && idToPath.get(old.id) === key) idToPath.delete(old.id) }
    else {
      const entry = files.get(key)
      if (change.action === 'update' && change.oldValue?.id && change.oldValue.id !== entry?.id) idToPath.delete(change.oldValue.id)
      if (entry?.id) idToPath.set(entry.id, key)
    }
  }
  if (!remote(ev.transaction)) return
  for (const [rawRel, change] of ev.keys) {
    const rel = safeRel(rawRel); if (!rel || rel !== rawRel) { ui.warn('blocked unsafe from peer:', rawRel); continue }
    if (shouldIgnore(rel)) { ui.warn('blocked ignored from peer:', rel); continue }
    if (change.action === 'delete') { touched.add(rel); cancelWrite(rel); fs.rmSync(path.join(workDir, rel), { force: true }) }
    else { touched.add(rel); scheduleWrite(rawRel) }
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
  if (backend.kind === 'git' && files.size) { const keep = new Set(files.keys()); for (const rel of walkTree()) if (!keep.has(rel)) fs.rmSync(path.join(workDir, rel), { force: true }) }
}

function makeBackend(config) {
  if (config.backend === 'git') {
    return {
      kind: 'git', excluded: null,
      prepare() {
        gitOk('fetch')
        if (gitOk('rev-parse', '--abbrev-ref', 'HEAD') === 'HEAD') {
          for (const b of ['main', 'master']) if (gitOk('rev-parse', '--verify', '--quiet', 'refs/heads/' + b)) { try { git('checkout', b); break } catch {} }
        }
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

async function connect() {
  const cfg0 = readConfig() ?? {}
  mkdirp(SESSION_DIR)
  const ident = await loadKey(path.join(SESSION_DIR, 'identity.key'))

  const wantPort = Number(flag('port') ?? cfg0.port ?? DEFAULT_PORT)
  if (!Number.isInteger(wantPort) || wantPort < 1 || wantPort > 65535) die('Bad --port.')
  const advertise = String(flag('advertise') ?? cfg0.advertise ?? '').trim()
  if (advertise && !toMa(advertise, 'x')) die('--advertise must be host:port.')

  const n = await makeNode(ident, wantPort)
  const port = n.port || wantPort
  const me = { name: gitOk('config', 'user.name') ?? (os.userInfo().username || 'peer') }

  const name = flag('name') ?? cfg0.name ?? die('No session name. Run `c3 config`.')
  const sdir = sdirOf(name)
  const sKey = flag('key') ?? process.env.C3_KEY ?? readKey(sdir)
  if (!sKey) die('No session key. Run `c3 config`, or paste a share block with --key.')
  if (flag('key')) writeKey(sdir, sKey)

  const cfg = { ...cfg0, name, port }
  if (advertise) cfg.advertise = advertise
  if (!cfg.backend) cfg.backend = fs.existsSync(path.join(workDir, '.git')) ? 'git' : 'none'
  atomicWrite(CONFIG_FILE, JSON.stringify(cfg, null, 2))
  atomicWrite(path.join(sdir, 'name'), JSON.stringify({ name }))

  const peers = new Set()
  let leaving = false, started = false, watcher = null
  let peerTimer = null, snapTimer = null, scanTimer = null, tick = null, dialTimer = null, addrsTimer = null
  const askedPeers = flag('peer') !== undefined
  const peerCount = () => new Set(n.getConnections().map(c => c.remotePeer.toString())).size

  const addPeer = a => {
    if (!sdir || typeof a !== 'string' || a.length > 500 || !/\/p2p\//.test(a)) return
    if (a.includes('/p2p/' + n.peerId)) return
    if (peers.has(a) || peers.size >= 64) return
    peers.add(a)
    clearTimeout(peerTimer)
    peerTimer = setTimeout(() => { try { atomicWrite(peersFile(sdir), JSON.stringify([...peers].slice(0, 64))) } catch {} }, 1000)
  }
  const dialPeers = () => {
    if (leaving) return
    for (const a of readPeers(sdir)) addPeer(a)
    const live = new Set(n.getConnections().map(c => c.remotePeer.toString()))
    let count = 0
    for (const a of peers) {
      if (count >= 8) break
      const m = a.match(/\/p2p\/([^/]+)$/)
      if (!m || live.has(m[1])) continue
      n.dial(a).catch(() => {})
      count++
    }
  }
  const waitFor = async (ms, cond) => { const until = Date.now() + ms; while (Date.now() < until) { if (cond()) return true; await sleep(200) } return cond() }

  for (const a of readPeers(sdir)) addPeer(a)
  if (flag('peer')) addPeer(flag('peer'))

  loadIgnoreRules()
  backend = makeBackend(cfg)
  backend.prepare()

  const stateFile = path.join(sdir, 'state.bin')
  const genFile = path.join(sdir, 'state.gen')
  const logFile = path.join(sdir, 'oplog')
  function appendLog(update) { try { const h = Buffer.allocUnsafe(4); h.writeUInt32BE(update.length, 0); fs.appendFileSync(logFile, Buffer.concat([h, Buffer.from(update)])) } catch {} }
  function snapshotNow() { try { atomicWrite(stateFile, Y.encodeStateAsUpdate(doc)); atomicWrite(genFile, backend.generation()); fs.rmSync(logFile, { force: true }) } catch {} }
  function scheduleSnapshot() { clearTimeout(snapTimer); snapTimer = setTimeout(snapshotNow, 5000) }
  function removeState() { for (const f of [stateFile, genFile, logFile]) { try { fs.rmSync(f, { force: true }) } catch {} } }
  function restoreState() {
    if (!fs.existsSync(stateFile)) return false
    try {
      const genThen = fs.existsSync(genFile) ? fs.readFileSync(genFile, 'utf8').trim() : null
      if (genThen && genThen !== backend.generation()) { ui.say('Saved state predates archive -- discarding.'); removeState(); return false }
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

  sync(n, sKey, doc, advertise, addrs => { for (const a of addrs) addPeer(a); dialPeers() })
  n.on('addrs', ev => { if (Array.isArray(ev.detail)) { for (const a of ev.detail) addPeer(a); dialPeers() } })

  doc.on('update', (update, origin) => { if (origin === 'restore') return; appendLog(update); scheduleSnapshot() })

  let lastGitignore = 0
  function scan() {
    try {
      let m = 0; try { m = fs.statSync(path.join(workDir, '.gitignore')).mtimeMs } catch {}
      if (m !== lastGitignore) { lastGitignore = m; ignoredCache.clear() }
      const list = walkTree(); const present = new Set(list); const now = Date.now()
      for (const rel of list) {
        if (pendingWrites.has(rel) || (lastWritten.get(rel) ?? 0) > now - 500) continue
        let st; try { st = fs.statSync(path.join(workDir, rel)) } catch { continue }
        const sig = st.mtimeMs + ':' + st.size; if (diskMeta.get(rel) === sig) continue; diskMeta.set(rel, sig); syncFromDisk(rel)
      }
      for (const rel of [...files.keys()]) { if (present.has(rel) || pendingWrites.has(rel) || (lastWritten.get(rel) ?? 0) > now - 500) continue; removeFromDoc(rel) }
    } catch {}
  }
  function quick(rel) {
    if (!rel) return; const now = Date.now(); if (pendingWrites.has(rel) || (lastWritten.get(rel) ?? 0) > now - 300) return
    let st; try { st = fs.statSync(path.join(workDir, rel)) } catch { if (files.has(rel)) removeFromDoc(rel); return }
    if (!st.isFile()) return; const sig = st.mtimeMs + ':' + st.size; if (diskMeta.get(rel) === sig) return; diskMeta.set(rel, sig); syncFromDisk(rel)
  }
  function startScan() {
    if (started) return; started = true; scan()
    try {
      watcher = fs.watch(workDir, { recursive: true }, (_evt, file) => {
        if (!file) return; const rel = String(file).split(path.sep).join('/')
        if (!rel || rel === '.git' || rel.startsWith('.git/') || rel === '.c3' || rel.startsWith('.c3/') || (c3InsideWork && (rel === c3Rel || rel.startsWith(c3Rel + '/')))) return
        quick(rel)
      })
      watcher.on('error', () => {})
    } catch { ui.warn('instant watching unavailable -- polling fallback') }
    scanTimer = setInterval(scan, SCAN_MS)
  }
  function seedFromDisk() {
    const seed = walkTree(); let bytes = 0
    for (const rel of seed) { try { bytes += fs.statSync(path.join(workDir, rel)).size } catch {} }
    if (!cfg.forceSeed && (seed.length > SEED_FILES || bytes > SEED_BYTES)) die(`Refusing to seed ${seed.length} files / ${(bytes / 1e6).toFixed(0)} MB. Set "forceSeed": true in config to override.`)
    ui.say(`Seeding ${seed.length} files.`)
    doc.transact(() => { for (const rel of seed) syncFromDisk(rel, true) }, 'disk')
    startScan()
  }

  async function confirmSave() {
    if (has('yes')) return true
    if (!process.stdin.isTTY) return false
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
    const a = (await rl.question(`Publish ${touched.size} changed path(s) to archive? [y/N] `)).trim().toLowerCase()
    rl.close()
    return a === 'y' || a === 'yes'
  }
  async function leave() {
    if (leaving) return; leaving = true
    clearInterval(scanTimer); clearTimeout(snapTimer); clearTimeout(peerTimer); clearInterval(tick); clearInterval(dialTimer); clearInterval(addrsTimer)
    try { watcher?.close() } catch {}; flushWrites(); snapshotNow(); ui.clear()
    try {
      const others = peerCount()
      if (others > 0) { ui.say(`Others still in session (${others}) -- keeping local state.`) }
      else if (touched.size === 0) { ui.say('Nothing changed.'); removeState() }
      else if (!(await confirmSave())) { ui.say('Skipped publishing.') }
      else {
        const r = backend.save(touched, { user: me.name, message: `Session snapshot ${new Date().toISOString()}` })
        if (r.saved === false) { ui.say('Nothing changed.'); removeState() }
        else if (r.pushed === false) ui.warn('Could not push -- commit kept locally.')
        else { removeState(); ui.say(r.forced ? 'Saved and pushed (force).' : 'Saved and pushed.') }
      }
    } catch (err) { console.error('Save failed:', err.message) } finally { try { await n.stop() } catch {}; process.exit(0) }
  }

  n.addEventListener('peer:connect', ev => { const pid = ev.detail?.pid ?? 'peer'; ui.say(`peer ${pid.slice(0, 8)} connected`); dialPeers() })
  n.addEventListener('peer:disconnect', () => ui.set(`live - ${peerCount()} peer(s)`))

  const addrsFile = path.join(sdir, 'addrs.json')
  const writeAddrs = () => { try { atomicWrite(addrsFile, JSON.stringify({ id: n.peerId.toString(), addrs: n.addrs(advertise), port })) } catch {} }
  addrsTimer = setInterval(writeAddrs, 5000); writeAddrs()

  dialPeers(); dialTimer = setInterval(dialPeers, 10000)
  ui.set('looking for peers...')
  await sleep(PEER_WAIT_MS)
  if (askedPeers && files.size === 0) await waitFor(STATE_WAIT_MS, () => files.size > 0)

  if (restored && files.size > 0) { ui.say('Ready from local state.'); reconcile(); startScan() }
  else if (files.size > 0) { ui.say(`Joined session with ${peerCount()} peer(s).`); reconcile(); startScan() }
  else if (askedPeers && !has('seed')) { ui.say('No state yet -- keeping directory as-is.'); ui.say('If this is a new session, pass --seed.'); startScan() }
  else { seedFromDisk() }

  tick = setInterval(() => { const p = peerCount(); ui.set(`live - ${p} peer${p === 1 ? '' : 's'} - ${files.size} files - ${backend.kind}${advertise ? ' - ad' : ''}`) }, 2000)
  ui.say('Ready. Ctrl+C to leave.')
  const bye = () => leave()
  process.on('SIGINT', bye); process.on('SIGTERM', bye)
}

async function configCmd() {
  const isGit = fs.existsSync(path.join(workDir, '.git'))
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  const ask = async (q, def) => {
    if (!process.stdin.isTTY) return def
    const a = (await rl.question(`${C.cyn}?${C.r} ${q}${def ? ` [${C.yel}${def}${C.r}]` : ':'} `)).trim()
    return a || def
  }
  ui.clear(); console.log(`c3 config -- ${workDir}`)
  const choice = await ask(`Backend
  1) git  - this project IS a git repo
  2) none - no auto-archive
  Pick 1/2`, isGit ? '1' : '2')
  const kind = { '1': 'git', '2': 'none' }[choice] || choice
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
  if (key.length < 20) ui.warn('Low-entropy key.')
  writeKey(sdir, key)
  const port = Number(flag('port') ?? await ask('Listening TCP/UDP port', String(DEFAULT_PORT)))
  if (!Number.isInteger(port) || port < 1 || port > 65535) die('Bad port.')
  const advertise = String(flag('advertise') ?? await ask('Reachable host:port (blank = LAN only)', '')).trim()
  if (advertise && !toMa(advertise, 'x')) die('Bad advertise.')
  const cfg = { backend: kind, name, port }
  if (advertise) cfg.advertise = advertise
  atomicWrite(CONFIG_FILE, JSON.stringify(cfg, null, 2))
  atomicWrite(path.join(sdir, 'name'), JSON.stringify({ name }))
  if (kind === 'git') {
    const ex = path.join(workDir, '.git', 'info', 'exclude')
    mkdirp(path.dirname(ex))
    const cur = fs.existsSync(ex) ? fs.readFileSync(ex, 'utf8') : ''
    if (!cur.split('\n').includes(c3Name + '/')) fs.appendFileSync(ex, '\n' + c3Name + '/\n')
  }
  rl.close(); ui.clear()
  console.log(`Config written: ${CONFIG_FILE}`)
  console.log('Start: node c3.js connect')
  console.log('Swap addresses once with `share` / `peer` if ufw is on.')
}

function shareCmd() {
  const cfg = readConfig() ?? die('No config.')
  const sdir = sdirOf(cfg.name)
  const key = readKey(sdir) ?? die('No key.')
  let addrs = []
  try { addrs = JSON.parse(fs.readFileSync(path.join(sdir, 'addrs.json'), 'utf8')).addrs ?? [] } catch {}
  if (!addrs.length) {
    const id = readIdentity()?.id ?? die('Run `connect` once first.')
    addrs = lanAddrs(id, Number(cfg.port ?? DEFAULT_PORT))
  }
  addrs = addrs.filter(a => typeof a === 'string' && /\/p2p\//.test(a) && !a.includes('/ip4/127.0.0.1/')).slice(0, 4)
  if (!addrs.length) die('No LAN address found. Start `connect` first.')
  ui.clear()
  console.log(`Share for "${cfg.name}" -- paste this block to the other peer:\n`)
  console.log(`name: ${cfg.name}`)
  console.log(`key:  ${key}`)
  addrs.forEach(a => console.log(`peer: ${a}`))
  console.log('\nThey join with:')
  console.log(`  node c3.js connect --name="${cfg.name}" --key="${key}" --peer="${addrs[0]}"`)
  console.log('\nThen they `share` and you `peer` their line.')
  console.log('ufw on = TCP fails, UDP punching retries automatically.')
}

function peerCmd() {
  const cfg = readConfig() ?? die('No config.')
  const sdir = sdirOf(cfg.name)
  const ma = String(argv[1] || '').trim()
  if (!/^\/(ip4|ip6|dns)\/.+\/p2p\/[^/]+$/.test(ma)) die('usage: node c3.js peer "/ip4/10.0.0.5/tcp/8443/p2p/<id>"')
  const list = readPeers(sdir)
  if (!list.includes(ma)) list.push(ma)
  atomicWrite(peersFile(sdir), JSON.stringify(list.slice(0, 64), null, 2))
  ui.say(`peer added: ${ma}`)
  ui.say('A running `connect` picks it up in ~10s.')
}

const usage = `usage: node c3.js <command> [flags]
Commands:
  config    interactive setup
  connect   join/start session
  share     print name + key + addrs (paste once)
  peer <ma> add a cached peer address
Flags:
  --name <n>   session name
  --key <k>    session key
  --peer <ma>  peer multiaddr
  --port <n>   listening port (default 8443)
  --advertise  reachable host:port
  --seed       publish this directory into empty session
  --yes        auto-confirm publish
Same session name + key = same room.`
loadIgnoreRules()
if (cmd === 'config') await configCmd()
else if (cmd === 'connect') await connect()
else if (cmd === 'share') shareCmd()
else if (cmd === 'peer') peerCmd()
else die(usage)