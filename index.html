#!/usr/bin/env node

'use strict';

const http = require('http');
const net = require('net');
const fs = require('fs');
const crypto = require('crypto');
const { WebSocketServer, WebSocket } = require('ws');

const UUID = process.env.UUID || '7bd180e8-1142-4387-93f5-03e8d750a896';
const DOMAIN = process.env.DOMAIN || 'cf.877774.xyz';
const PORT = Number(process.env.SERVER_PORT || process.env.PORT || 3000);

const SUB_PATH = process.env.SUB_PATH || UUID.slice(-12);
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);

const MAX_WS_QUEUE = 4 * 1024 * 1024;
const WS_HIGH_WATERMARK = 512 * 1024;
const WS_LOW_WATERMARK = 128 * 1024;
const CONNECT_TIMEOUT = 10_000;
const IDLE_PING_INTERVAL = 30_000;

if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(UUID)) {
  throw new Error('Invalid UUID');
}

const UUID_BUF = Buffer.from(UUID.replace(/-/g, ''), 'hex');

function parseVlessRequest(data) {
  if (!Buffer.isBuffer(data)) {
    data = Buffer.from(data);
  }

  // version(1) + uuid(16) + addonLength(1)
  if (data.length < 18) return null;

  if (data[0] !== 0) return null;
  if (!data.subarray(1, 17).equals(UUID_BUF)) return null;

  const addonLength = data[17];
  let offset = 18 + addonLength;

  // command(1) + port(2) + address type(1)
  if (offset + 4 > data.length) return null;

  const command = data[offset++];
  if (command !== 1) {
    // 只支持 TCP
    return null;
  }

  const port = data.readUInt16BE(offset);
  offset += 2;

  const addressType = data[offset++];

  let host;

  if (addressType === 1) {
    // IPv4
    if (offset + 4 > data.length) return null;

    host = Array.from(data.subarray(offset, offset + 4)).join('.');
    offset += 4;
  } else if (addressType === 2) {
    // Domain
    if (offset + 1 > data.length) return null;

    const length = data[offset++];

    if (offset + length > data.length) return null;

    host = data.subarray(offset, offset + length).toString('utf8');
    offset += length;

    if (!host || host.length > 253) return null;
  } else if (addressType === 3) {
    // IPv6
    if (offset + 16 > data.length) return null;

    const parts = [];

    for (let i = 0; i < 8; i++) {
      parts.push(data.readUInt16BE(offset + i * 2).toString(16));
    }

    host = parts.join(':');
    offset += 16;
  } else {
    return null;
  }

  return {
    host,
    port,
    payload: offset < data.length ? data.subarray(offset) : null
  };
}

function safeCloseWebSocket(ws) {
  if (ws.readyState === WebSocket.OPEN ||
      ws.readyState === WebSocket.CONNECTING) {
    try {
      ws.close();
    } catch (_) {
      try {
        ws.terminate();
      } catch (_) {}
    }
  }
}

function createHttpServer() {
  return http.createServer((req, res) => {
    const pathname = (req.url || '').split('?')[0];

    if (pathname === '/') {
      if (fs.existsSync('index.html')) {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8'
        });

        fs.createReadStream('index.html')
          .on('error', () => {
            if (!res.headersSent) res.writeHead(500);
            res.end('Internal Server Error\n');
          })
          .pipe(res);

        return;
      }

      res.writeHead(200, {
        'Content-Type': 'text/plain; charset=utf-8'
      });
      res.end('OK\n');
      return;
    }

    if (pathname === `/${SUB_PATH}`) {
      const tlsEnabled = DOMAIN !== '127.0.0.1' && DOMAIN !== 'localhost';
      const security = tlsEnabled ? 'tls' : 'none';
      const port = tlsEnabled ? 443 : PORT;

      const uri =
        `vless://${UUID}@${DOMAIN}:${port}` +
        `?encryption=none` +
        `&security=${security}` +
        `&sni=${encodeURIComponent(DOMAIN)}` +
        `&fp=chrome` +
        `&type=ws` +
        `&host=${encodeURIComponent(DOMAIN)}` +
        `&path=%2F${encodeURIComponent(WSPATH)}` +
        `#Node`;

      const encoded = Buffer.from(uri).toString('base64');

      res.writeHead(200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store'
      });
      res.end(`${encoded}\n`);
      return;
    }

    res.writeHead(404);
    res.end('Not Found\n');
  });
}

const server = createHttpServer();

const wss = new WebSocketServer({
  server,
  path: `/${WSPATH}`,
  perMessageDeflate: false,
  maxPayload: 2 * 1024 * 1024
});

wss.on('connection', (ws, request) => {
  let tcp = null;
  let closed = false;
  let connected = false;
  let tcpBlocked = false;

  let wsQueue = [];
  let wsQueueBytes = 0;

  const connectTimer = setTimeout(() => {
    closeConnection();
  }, CONNECT_TIMEOUT);

  const pingTimer = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.ping();
      } catch (_) {
        closeConnection();
      }
    }
  }, IDLE_PING_INTERVAL);

  function cleanup() {
    clearTimeout(connectTimer);
    clearInterval(pingTimer);

    wsQueue = [];
    wsQueueBytes = 0;
  }

  function closeConnection() {
    if (closed) return;

    closed = true;
    cleanup();

    if (tcp && !tcp.destroyed) {
      tcp.destroy();
    }

    safeCloseWebSocket(ws);
  }

  function enqueueWsData(data) {
    const chunk = Buffer.isBuffer(data) ? data : Buffer.from(data);

    wsQueueBytes += chunk.length;

    if (wsQueueBytes > MAX_WS_QUEUE) {
      closeConnection();
      return;
    }

    wsQueue.push(chunk);
    flushWsQueue();
  }

  function flushWsQueue() {
    if (closed || !connected || !tcp || tcp.destroyed) return;
    if (tcpBlocked) return;

    while (wsQueue.length > 0) {
      const chunk = wsQueue.shift();
      wsQueueBytes -= chunk.length;

      const writable = tcp.write(chunk);

      if (!writable) {
        tcpBlocked = true;
        break;
      }
    }
  }

  function handleWsMessage(data, isBinary) {
    if (closed || !isBinary) {
      closeConnection();
      return;
    }

    if (!connected) {
      enqueueWsData(data);
      return;
    }

    if (!tcp || tcp.destroyed) {
      closeConnection();
      return;
    }

    if (!tcp.write(data)) {
      tcpBlocked = true;
    }
  }

  function sendTcpData(data) {
    if (closed || ws.readyState !== WebSocket.OPEN) {
      closeConnection();
      return;
    }

    try {
      ws.send(data, { binary: true }, () => {
        if (closed || !tcp || tcp.destroyed) return;

        if (
          tcpBlocked &&
          ws.bufferedAmount <= WS_LOW_WATERMARK
        ) {
          tcpBlocked = false;
          tcp.resume();
        }
      });

      if (
        ws.bufferedAmount >= WS_HIGH_WATERMARK &&
        tcp &&
        !tcp.destroyed
      ) {
        tcp.pause();
      }
    } catch (_) {
      closeConnection();
    }
  }

  function connectTarget(req) {
    tcp = net.createConnection({
      host: req.host,
      port: req.port
    });

    tcp.setNoDelay(true);
    tcp.setKeepAlive(true, 30_000);

    tcp.once('connect', () => {
      if (closed) return;

      connected = true;
      clearTimeout(connectTimer);

      // 只有目标连接成功后才返回 VLESS 响应头
      if (ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(Buffer.from([0, 0]), { binary: true });
        } catch (_) {
          closeConnection();
          return;
        }
      }

      // 发送首包中携带的剩余数据
      if (req.payload && req.payload.length > 0) {
        enqueueWsData(req.payload);
      }

      // 发送连接建立前暂存的 WebSocket 数据
      flushWsQueue();
    });

    tcp.on('data', sendTcpData);

    tcp.on('drain', () => {
      if (closed) return;

      tcpBlocked = false;
      flushWsQueue();

      if (
        ws.readyState === WebSocket.OPEN &&
        ws.bufferedAmount <= WS_LOW_WATERMARK
      ) {
        tcp.resume();
      }
    });

    tcp.on('error', () => {
      closeConnection();
    });

    tcp.on('close', () => {
      closeConnection();
    });
  }

  ws.once('message', (firstMessage, isBinary) => {
    if (closed || !isBinary) {
      closeConnection();
      return;
    }

    const requestInfo = parseVlessRequest(firstMessage);

    if (!requestInfo) {
      closeConnection();
      return;
    }

    /*
     * 立即注册后续消息监听。
     * 目标 TCP 尚未连接时，数据会进入 wsQueue，
     * 避免 Node.js EventEmitter 因没有 listener 而丢包。
     */
    ws.on('message', handleWsMessage);

    connectTarget(requestInfo);
  });

  ws.on('error', () => {
    closeConnection();
  });

  ws.on('close', () => {
    closeConnection();
  });
});

server.on('clientError', (err, socket) => {
  socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`VLESS WebSocket server listening on :${PORT}`);
  console.log(`WebSocket path: /${WSPATH}`);
  console.log(`Subscription path: /${SUB_PATH}`);
});
