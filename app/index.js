// app/index.js
// 最小可运行示例：演示如何从环境变量读取密钥
// 真实开发中，direnv 会自动注入 DATABASE_URL 等

const port = process.env.PORT || 3000;
const hasDb = !!process.env.DATABASE_URL;
const hasRedis = !!process.env.REDIS_URL;

const server = require('http').createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok',
      secrets_loaded: {
        database: hasDb,
        redis: hasRedis,
      },
      timestamp: new Date().toISOString(),
    }));
  } else {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Hello from my-first-app! 密钥管理已经生效。\n');
  }
});

server.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
  console.log(`📊 Secrets loaded: DB=${hasDb}, Redis=${hasRedis}`);
});
