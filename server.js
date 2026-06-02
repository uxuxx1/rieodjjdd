const http = require('http');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');

const dbPath = path.join(__dirname, 'chat.db');
const db = new sqlite3.Database(dbPath);

let clients = [];
// Хранилище таймаутов для IP+UserAgent
const cooldowns = new Map();
// Лимит сообщений в минуту (25)
const rateLimit = new Map();

function getRealIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.socket.remoteAddress;
}

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        text TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        user_hash TEXT NOT NULL
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
        const realIp = getRealIp(req);
        const now = Date.now();
        
        const userAgent = req.headers['user-agent'] || 'unknown';
        const fingerprint = crypto.createHash('md5').update(realIp + userAgent).digest('hex');
        
        // Лимит 25 сообщений в минуту
        const minuteKey = `${fingerprint}_${Math.floor(now / 60000)}`;
        if (rateLimit.has(minuteKey) && rateLimit.get(minuteKey) >= 25) {
            res.writeHead(429, { 'Content-Type': 'text/plain' });
            res.end('too many messages: max 25 per minute');
            return;
        }
        
        // Кулдаун 2 секунды
        if (cooldowns.has(fingerprint)) {
            const lastTime = cooldowns.get(fingerprint);
            if (now - lastTime < 2000) {
                res.writeHead(429, { 'Content-Type': 'text/plain' });
                res.end('too many requests: wait 2 seconds');
                return;
            }
        }

        let body = '';
        req.on('data', chunk => { 
            if (body.length > 1024) {
                res.writeHead(413);
                res.end();
                req.destroy();
                return;
            }
            body += chunk.toString(); 
        });
        
        req.on('end', () => {
            try {
                const data = JSON.parse(body);
                const text = data.text ? data.text.trim() : '';

                if (text.length > 0 && text.length <= 100) {
                    // Проверка на повторяющиеся символы (спам)
                    const repeatPattern = /(.)\1{9,}/;
                    if (repeatPattern.test(text)) {
                        res.writeHead(400);
                        res.end('no spam patterns allowed');
                        return;
                    }
                    
                    cooldowns.set(fingerprint, now);
                    rateLimit.set(minuteKey, (rateLimit.get(minuteKey) || 0) + 1);
                    
                    const timestamp = new Date().toLocaleTimeString();
                    
                    db.run('INSERT INTO messages (text, timestamp, user_hash) VALUES (?, ?, ?)', 
                        [text, timestamp, fingerprint.substring(0, 8)], 
                        function(err) {
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

// Очистка старых записей каждые 30 секунд
setInterval(() => {
    const now = Date.now();
    for (const [key, time] of cooldowns.entries()) {
        if (now - time > 5000) {
            cooldowns.delete(key);
        }
    }
    
    // Очистка rate limit
    const currentMinute = Math.floor(now / 60000);
    for (const [key, _] of rateLimit.entries()) {
        const keyMinute = parseInt(key.split('_')[1]);
        if (keyMinute < currentMinute - 1) {
            rateLimit.delete(key);
        }
    }
}, 30000);

const port = Number(process.env.PORT) || 8080;
server.listen(port, '0.0.0.0', () => {
    console.log(`chat engine active on port ${port}`);
});
