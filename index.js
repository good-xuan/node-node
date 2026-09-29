#!/usr/bin/env node

const http = require('http');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { Buffer } = require('buffer');
const { WebSocket } = require('ws');

// 环境变量配置
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

// WebSocket 代理层（关闭自带 perMessageDeflate 避免压缩消耗 CPU）
const wss = new WebSocket.Server({ 
  server: httpServer,
  perMessageDeflate: false,
  maxPayload: 64 * 1024 * 1024 
});

wss.on('connection', (ws, req) => {
  const pathname = (req.url || '').split('?')[0];
  if (pathname !== `/${WSPATH}`) {
    return ws.close();
  }

  let tcpSocket = null;
  let isClosed = false;

  // 资源统一清理函数
  const destroy = () => {
    if (isClosed) return;
    isClosed = true;
    if (tcpSocket) {
      tcpSocket.destroy();
      tcpSocket = null;
    }
    if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
      ws.close();
    }
  };

  const handshakeTimer = setTimeout(destroy, 10000);

  // 首包处理握手
  ws.once('message', (msg) => {
    clearTimeout(handshakeTimer);

    if (!Buffer.isBuffer(msg) || msg.length < 18 || msg[0] !== 0) {
      return destroy();
    }
    if (!msg.subarray(1, 17).equals(UUID_BUF)) {
      return destroy();
    }

    try {
      let idx = 18 + msg[17];
      if (idx + 3 > msg.length || msg[idx] !== 1) { // 仅处理 TCP (CMD = 1)
        return destroy();
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
        return destroy();
      }

      // 回复 VLESS 握手响应
      ws.send(Buffer.from([0, 0]), { binary: true });

      // 直连目标服务器
      tcpSocket = net.connect({ host, port }, () => {
        tcpSocket.setNoDelay(true); // 禁用 Nagle
        tcpSocket.setKeepAlive(true, 30000);

        // 发送首包剩余 payload
        if (idx < msg.length) {
          tcpSocket.write(msg.subarray(idx));
        }

        // ================= 极速直通管道 + 严格背压 =================

        // 1. TCP -> WebSocket (下行流量：通常带宽最大)
        tcpSocket.on('data', (chunk) => {
          if (ws.readyState !== WebSocket.OPEN) return;

          ws.send(chunk, { binary: true }, () => {
            // WS 发送完毕后，若之前被暂停则恢复接收
            if (tcpSocket && tcpSocket.isPaused() && ws.bufferedAmount < 65536) {
              tcpSocket.resume();
            }
          });

          // 如果客户端消费慢，WS 缓冲区堆积超过 256KB，暂停从 TCP 读，保护内存
          if (ws.bufferedAmount > 262144) {
            tcpSocket.pause();
          }
        });

        // 2. WebSocket -> TCP (上行流量)
        ws.on('message', (chunk) => {
          if (!tcpSocket || isClosed) return;

          const canWrite = tcpSocket.write(chunk);
          // 如果系统内核 TCP 缓冲区满了，先暂停 WS 接收
          if (!canWrite) {
            ws.pause();
          }
        });

        // 内核 TCP 缓冲区排空，通知 WS 恢复接收上行流量
        tcpSocket.on('drain', () => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.resume();
          }
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

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
