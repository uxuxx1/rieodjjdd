const http = require('http');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const dbPath = path.join(__dirname, 'chat.db');
const db = new sqlite3.Database(dbPath);

let clients = [];
// Хранилище таймаутов для IP-адресов
const cooldowns = new Map();

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        text TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )`);
});

const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    if (req.url === '/' && req.method === 'GET') {
        fs.readFile(path.join(__dirname, 'index.html'), (err, content) => {
            if (err) {
                res.writeHead(500);
                res.end('error loading index.html');
            } else {
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(content);
            }
        });
    } 
    
    else if (req.url.startsWith('/messages') && req.method === 'GET') {
        const urlParams = new URL(req.url, `http://${req.headers.host}`);
        const lastId = parseInt(urlParams.searchParams.get('lastId') || '-1');

        db.all('SELECT * FROM messages WHERE id > ? ORDER BY id ASC', [lastId], (err, rows) => {
            if (err) {
                res.writeHead(500);
                res.end();
                return;
            }

            if (rows.length > 0) {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(rows));
            } else {
                clients.push({ res, lastId });
            }
        });
    } 
    
    else if (req.url === '/send' && req.method === 'POST') {
        // Получаем IP-адрес клиента (с учетом проксирования Railway)
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const now = Date.now();

        // Проверка таймаута на бэкенде (2000 мс = 2 секунды)
        if (cooldowns.has(ip)) {
            const lastTime = cooldowns.get(ip);
            if (now - lastTime < 2000) {
                res.writeHead(429, { 'Content-Type': 'text/plain' });
                res.end('too many requests: wait 2 seconds');
                return;
            }
        }

        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => {
            try {
                const data = JSON.parse(body);
                const text = data.text ? data.text.trim() : '';

                if (text.length > 0 && text.length <= 100) {
                    // Обновляем время последней отправки для этого IP
                    cooldowns.set(ip, now);

                    const timestamp = new Date().toLocaleTimeString();

                    db.run('INSERT INTO messages (text, timestamp) VALUES (?, ?)', [text, timestamp], function(err) {
                        if (err) return;

                        const newMsg = { id: this.lastID, text, timestamp };

                        db.run(`DELETE FROM messages WHERE id NOT IN (
                            SELECT id FROM messages ORDER BY id DESC LIMIT 100
                        )`);

                        const currentClients = clients;
                        clients = [];
                        currentClients.forEach(client => {
                            client.res.writeHead(200, { 'Content-Type': 'application/json' });
                            client.res.end(JSON.stringify([newMsg]));
                        });
                    });
                    
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true }));
                } else {
                    res.writeHead(400);
                    res.end('bad request: length must be 1-100 chars');
                }
            } catch (e) {
                res.writeHead(400);
                res.end();
            }
        });
    } 
    
    else {
        res.writeHead(404);
        res.end();
    }
});

// Периодическая очистка старых IP из памяти, чтобы не забивать RAM
setInterval(() => {
    const now = Date.now();
    for (const [ip, time] of cooldowns.entries()) {
        if (now - time > 5000) {
            cooldowns.delete(ip);
        }
    }
}, 10000);

const port = Number(process.env.PORT) || 8080;
server.listen(port, '0.0.0.0', () => {
    console.log(`chat engine active on port ${port}`);
});
