#!/usr/bin/env node
const net = require('net'), http = require('http'), fs = require('fs'), { WebSocketServer } = require('ws');

const UUID = process.env.UUID || '7bd180e8-1142-4387-93f5-03e8d750a896';
const DOMAIN = process.env.DOMAIN || 'cf.877774.xyz';
const PORT = +(process.env.SERVER_PORT || process.env.PORT || 3000);
const SUB_PATH = process.env.SUB_PATH || UUID.slice(-12);
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);
const UUID_BUF = Buffer.from(UUID.replace(/-/g, ''), 'hex');

function parseWs(m) {
  if (!Buffer.isBuffer(m) || m.length < 18 || m[0] !== 0 || !m.subarray(1, 17).equals(UUID_BUF)) return null;
  let i = 18 + m[17];
  if (i + 3 > m.length || m[i++] !== 1) return null;
  const port = m.readUInt16BE(i);
  const atyp = m[i += 2];
  i += 1;

  let host = '';
  if (atyp === 1) host = `${m[i++]}.${m[i++]}.${m[i++]}.${m[i++]}`;
  else if (atyp === 2) { const l = m[i++]; host = m.subarray(i, i += l).toString(); }
  else if (atyp === 3) { host = Array.from({length: 8}, (_, j) => m.readUInt16BE(i + j * 2).toString(16)).join(':'); i += 16; }
  else return null;

  return { host, port, data: i < m.length ? m.subarray(i) : null };
}

const server = http.createServer((req, res) => {
  const p = (req.url || '').split('?')[0];
  if (p === '/') {
    return fs.existsSync('index.html') ? fs.createReadStream('index.html').pipe(res) : res.end('OK\n');
  }
  if (p === `/${SUB_PATH}`) {
    const tls = DOMAIN !== '127.0.0.1' ? 'tls' : 'none';
    const uri = `vless://${UUID}@${DOMAIN}:${tls === 'tls' ? 443 : PORT}?encryption=none&security=${tls}&sni=${DOMAIN}&fp=chrome&type=ws&path=%2F${WSPATH}#Node`;
    return res.end(Buffer.from(uri).toString('base64') + '\n');
  }
  res.writeHead(404).end();
});

const wss = new WebSocketServer({ server, path: `/${WSPATH}`, perMessageDeflate: false });

wss.on('connection', ws => {
  let tcp, closed = false;
  const close = () => { if (!closed) { closed = true; tcp?.destroy(); if (ws.readyState <= 1) ws.close(); } };
  const timer = setTimeout(close, 10000);

  ws.once('message', msg => {
    clearTimeout(timer);
    const req = parseWs(msg);
    if (!req) return close();

    ws.send(Buffer.from([0, 0]), { binary: true });
    tcp = net.connect({ host: req.host, port: req.port }, () => {
      tcp.setNoDelay(true);
      if (req.data) tcp.write(req.data);
      tcp.on('data', b => {
        if (ws.readyState === 1) ws.send(b, { binary: true }, () => tcp.isPaused() && ws.bufferedAmount < 65536 && tcp.resume());
        if (ws.bufferedAmount > 262144) tcp.pause();
      });
      ws.on('message', b => !tcp.write(b) && ws.pause());
      tcp.on('drain', () => ws.readyState === 1 && ws.resume());
    });
    tcp.on('error', close).on('close', close);
  });
  ws.on('error', close).on('close', close);
});

server.listen(PORT, '0.0.0.0', () => console.log(`Port ${PORT}`));
