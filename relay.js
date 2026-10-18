#!/usr/bin/env node
// Zero-knowledge c3 relay. Deploy on any box with a public IP.
// Usage: node relay.js [port]
import { WebSocketServer } from 'ws'

const port = Number(process.argv[2] || 4444)
const rooms = new Map()

const wss = new WebSocketServer({ port })
wss.on('connection', (ws, req) => {
  const room = (req.url || '').slice(1) || 'default'
  if (!rooms.has(room)) rooms.set(room, new Set())
  const set = rooms.get(room)
  set.add(ws)

  ws.on('message', data => {
    for (const c of set) if (c !== ws && c.readyState === 1) c.send(data)
  })

  ws.on('close', () => set.delete(ws))
  ws.on('error', () => {})
})

wss.on('listening', () => {
  console.log(`c3 relay on ws://0.0.0.0:${port}`)
  console.log('Peers connect to ws://YOUR_IP:' + port + '/ROOM_HASH')
})