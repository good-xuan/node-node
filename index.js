#!/usr/bin/env node

const http = require('http');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { pipeline } = require('stream');
const { Buffer } = require('buffer');
const { WebSocket, createWebSocketStream } = require('ws');

// 基础环境变量
const UUID = process.env.UUID || '7bd180e8-1142-4387-93f5-03e8d750a896';
const DOMAIN = process.env.DOMAIN || 'cf.877774.xyz';
const PORT = parseInt(process.env.SERVER_PORT || process.env.PORT || 3000, 10);
const SUB_PATH = process.env.SUB_PATH || UUID.slice(-12);
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);

// 缓存 16 字节原始 UUID 二进制
const UUID_BUF = Buffer.from(UUID.replace(/-/g, ''), 'hex');

// HTTP 路由处理
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
    const vlessUri = `vless://${UUID}@${DOMAIN}:${port}?encryption=none&security=${tls}&sni=${DOMAIN}&fp=chrome&type=ws&path=%2F${WSPATH}#Node`;
    const b64Sub = Buffer.from(vlessUri).toString('base64');

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end(b64Sub + '\n');
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found\n');
});

// WebSocket 代理层
const wss = new WebSocket.Server({ server: httpServer });

wss.on('connection', (ws, req) => {
  const pathname = (req.url || '').split('?')[0];
  if (pathname !== `/${WSPATH}`) {
    return ws.close();
  }

  // 首包接收超时（防止只建连不发数据的挂起连接）
  const handshakeTimer = setTimeout(() => ws.close(), 10000);

  ws.once('message', msg => {
    clearTimeout(handshakeTimer);

    // 校验 VLESS 首包
    if (!Buffer.isBuffer(msg) || msg.length < 18 || msg[0] !== 0) {
      return ws.close();
    }
    if (!msg.subarray(1, 17).equals(UUID_BUF)) {
      return ws.close();
    }

    try {
      let idx = 18 + msg[17];
      if (idx + 3 > msg.length || msg[idx] !== 1) { // 仅处理 TCP (CMD=1)
        return ws.close();
      }

      idx += 1;
      const port = msg.readUInt16BE(idx);
      idx += 2;
      const atyp = msg[idx];
      idx += 1;

      let host = '';
      if (atyp === 1) {        // IPv4
        host = `${msg[idx]}.${msg[idx + 1]}.${msg[idx + 2]}.${msg[idx + 3]}`;
        idx += 4;
      } else if (atyp === 2) { // 域名
        const hostLen = msg[idx];
        idx += 1;
        host = msg.subarray(idx, idx + hostLen).toString('utf-8');
        idx += hostLen;
      } else if (atyp === 3) { // IPv6
        const parts = [];
        for (let j = idx; j < idx + 16; j += 2) {
          parts.push(msg.readUInt16BE(j).toString(16));
        }
        host = parts.join(':');
        idx += 16;
      } else {
        return ws.close();
      }

      // 回复 VLESS 握手响应
      ws.send(Buffer.from([0, 0]));

      // 建立目标 TCP 连接
      const tcpSocket = net.connect({ host, port }, () => {
        tcpSocket.setNoDelay(true); // 禁用 Nagle 降低双向延迟
        tcpSocket.setKeepAlive(true, 30000);

        // 下发首包携带的剩余 Payload
        if (idx < msg.length) {
          tcpSocket.write(msg.subarray(idx));
        }

        const wsStream = createWebSocketStream(ws);

        // pipeline 保证任意一方断开或出错时安全释放句柄，防止内存泄露
        pipeline(wsStream, tcpSocket, () => {});
        pipeline(tcpSocket, wsStream, () => {});
      });

      tcpSocket.on('error', () => ws.close());

    } catch {
      ws.close();
    }
  });

  ws.on('error', () => {});
});

// 监听指定端口
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port ${PORT}`);
});