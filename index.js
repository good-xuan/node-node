#!/usr/bin/env node

const net = require('net');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { Buffer } = require('buffer');
const { WebSocketServer } = require('ws');

// 环境变量
const UUID = process.env.UUID || '7bd180e8-1142-4387-93f5-03e8d750a896';
const DOMAIN = process.env.DOMAIN || '127.0.0.1';
const PORT = parseInt(process.env.SERVER_PORT || process.env.PORT || 3000, 10);
const SUB_PATH = process.env.SUB_PATH || UUID.slice(-12);
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);

const UUID_BUF = Buffer.from(UUID.replace(/-/g, ''), 'hex');

// 1. 内部纯净 HTTP 服务
const httpServer = http.createServer((req, res) => {
  const pathname = (req.url || '').split('?')[0];

  if (pathname === '/') {
    const indexPath = path.join(__dirname, 'index.html');
    if (fs.existsSync(indexPath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return fs.createReadStream(indexPath).pipe(res);
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('OK\n');
  }

  if (pathname === `/${SUB_PATH}`) {
    const tls = DOMAIN !== '127.0.0.1' ? 'tls' : 'none';
    const port = tls === 'tls' ? 443 : PORT;
    const vlessUri = `vless://${UUID}@${DOMAIN}:${port}?encryption=none&security=${tls}&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#Node`;
    const b64Sub = Buffer.from(vlessUri).toString('base64');

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end(b64Sub + '\n');
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found\n');
});

// 2. WebSocket 代理
const wss = new WebSocketServer({ 
  noServer: true,
  perMessageDeflate: false,
  maxPayload: 64 * 1024 * 1024 
});

httpServer.on('upgrade', (req, socket, head) => {
  const pathname = (req.url || '').split('?')[0];
  if (pathname !== `/${WSPATH}`) {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', (ws) => {
  let tcpSocket = null;
  let isClosed = false;

  const destroy = () => {
    if (isClosed) return;
    isClosed = true;
    if (tcpSocket) {
      tcpSocket.destroy();
      tcpSocket = null;
    }
    if (ws.readyState === 1 || ws.readyState === 0) {
      ws.close();
    }
  };

  const timer = setTimeout(destroy, 10000);

  ws.once('message', (msg) => {
    clearTimeout(timer);

    if (!Buffer.isBuffer(msg) || msg.length < 18 || msg[0] !== 0) return destroy();
    if (!msg.subarray(1, 17).equals(UUID_BUF)) return destroy();

    try {
      let idx = 18 + msg[17];
      if (idx + 3 > msg.length || msg[idx] !== 1) return destroy();

      idx += 1;
      const port = msg.readUInt16BE(idx);
      idx += 2;
      const atyp = msg[idx];
      idx += 1;

      let host = '';
      if (atyp === 1) {
        host = `${msg[idx]}.${msg[idx + 1]}.${msg[idx + 2]}.${msg[idx + 3]}`;
        idx += 4;
      } else if (atyp === 2) {
        const hostLen = msg[idx];
        idx += 1;
        host = msg.subarray(idx, idx + hostLen).toString('utf-8');
        idx += hostLen;
      } else if (atyp === 3) {
        const parts = [];
        for (let j = idx; j < idx + 16; j += 2) {
          parts.push(msg.readUInt16BE(j).toString(16));
        }
        host = parts.join(':');
        idx += 16;
      } else {
        return destroy();
      }

      ws.send(Buffer.from([0, 0]), { binary: true });

      tcpSocket = net.connect({ host, port }, () => {
        tcpSocket.setNoDelay(true);
        tcpSocket.setKeepAlive(true, 30000);

        if (idx < msg.length) {
          tcpSocket.write(msg.subarray(idx));
        }

        // 下行流量 + 背压
        tcpSocket.on('data', (chunk) => {
          if (ws.readyState !== 1) return;
          ws.send(chunk, { binary: true }, () => {
            if (tcpSocket && tcpSocket.isPaused() && ws.bufferedAmount < 65536) {
              tcpSocket.resume();
            }
          });
          if (ws.bufferedAmount > 262144) {
            tcpSocket.pause();
          }
        });

        // 上行流量 + 背压
        ws.on('message', (chunk) => {
          if (!tcpSocket || isClosed) return;
          if (!tcpSocket.write(chunk)) {
            ws.pause();
          }
        });

        tcpSocket.on('drain', () => {
          if (ws.readyState === 1) ws.resume();
        });
      });

      tcpSocket.on('error', destroy);
      tcpSocket.on('close', destroy);
      tcpSocket.on('end', destroy);

    } catch {
      destroy();
    }
  });

  ws.on('error', destroy);
  ws.on('close', destroy);
});

// 3. 外层 TCP 嗅探网关：过滤直接把非 HTTP 报文当成 HTTP 传进系统的恶意流量
const rawTcpServer = net.createServer((socket) => {
  socket.once('data', (firstChunk) => {
    // 检查是否为常见合法 HTTP Method 首字符 (G/P/H/D/O/C/P)
    const firstByte = firstChunk[0];
    const isHttp = [0x47, 0x50, 0x48, 0x44, 0x4f, 0x43].includes(firstByte); // 'G','P','H','D','O','C'

    if (!isHttp) {
      // 遇到 TLS 握手包 (0x16) 或畸形二进制扫描，直接断开，绝不喂给 HTTP parser
      socket.destroy();
      return;
    }

    // 将首包重新注入内部 HTTP 服务器处理
    socket.pause();
    socket.unshift(firstChunk);
    httpServer.emit('connection', socket);
    process.nextTick(() => socket.resume());
  });

  socket.on('error', () => socket.destroy());
});

rawTcpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
