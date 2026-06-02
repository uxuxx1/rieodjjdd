const http = require('http');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');

const dbPath = path.join(__dirname, 'chat.db');
const db = new sqlite3.Database(dbPath);

let clients = [];
const cooldowns = new Map();
const dailyCounts = new Map();
const bannedIPs = new Map(); // IP -> причина и время бана

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        text TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        ip_hash TEXT NOT NULL
    )`);
    
    // Таблица для жалоб
    db.run(`CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_ip_hash TEXT NOT NULL,
        reporter_ip_hash TEXT NOT NULL,
        reason TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )`);
});

function getRealIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.socket.remoteAddress;
}

function hashIp(ip) {
    return crypto.createHash('sha256').update(ip).digest('hex').substring(0, 16);
}

function isBanned(ip) {
    if (bannedIPs.has(ip)) {
        const banTime = bannedIPs.get(ip);
        if (Date.now() - banTime < 3600000) { // Бан на час
            return true;
        } else {
            bannedIPs.delete(ip); // Снимаем бан через час
        }
    }
    return false;
}

const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    const ip = getRealIp(req);
    const ipHash = hashIp(ip);
    
    // Проверка бана
    if (isBanned(ip)) {
        res.writeHead(403);
        res.end('BANNED: Spamming detected');
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
    
    else if (req.url === '/report' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            try {
                const { targetId, reason } = JSON.parse(body);
                
                // Получаем IP автора сообщения из БД
                db.get('SELECT ip_hash FROM messages WHERE id = ?', [targetId], (err, msg) => {
                    if (err || !msg) {
                        res.writeHead(404);
                        res.end('Message not found');
                        return;
                    }
                    
                    // Секретные слова для бана
                    const banKeywords = ['спамер', 'спам', 'спамит', 'spammer', 'spam', 'бот', 'flood'];
                    const shouldBan = banKeywords.some(keyword => 
                        reason.toLowerCase().includes(keyword)
                    );
                    
                    if (shouldBan) {
                        // Нужно найти реальный IP по хэшу (в проде так не делают, но у нас маленький чат)
                        // В реальности нужно хранить соответствие IP -> хэш, но для простоты:
                        bannedIPs.set(ip, Date.now());
                        console.log(`[BAN] IP ${ip} banned for reason: ${reason}`);
                    }
                    
                    // Сохраняем жалобу в БД
                    const timestamp = new Date().toISOString();
                    db.run('INSERT INTO reports (target_ip_hash, reporter_ip_hash, reason, timestamp) VALUES (?, ?, ?, ?)',
                        [msg.ip_hash, ipHash, reason, timestamp]);
                    
                    res.writeHead(200);
                    res.end(JSON.stringify({ success: true, banned: shouldBan }));
                });
            } catch(e) {
                res.writeHead(400);
                res.end();
            }
        });
        return;
    }
    
    else if (req.url.startsWith('/messages') && req.method === 'GET') {
        const urlParams = new URL(req.url, `http://${req.headers.host}`);
        const lastId = parseInt(urlParams.searchParams.get('lastId') || '-1');

        db.all('SELECT id, text, timestamp FROM messages WHERE id > ? ORDER BY id ASC', [lastId], (err, rows) => {
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
        const now = Date.now();
        
        // Лимит 30 сообщений в день
        const today = new Date().toDateString();
        let daily = dailyCounts.get(ip) || { count: 0, day: today };
        if (daily.day !== today) {
            daily = { count: 0, day: today };
        }
        if (daily.count >= 30) {
            res.writeHead(429);
            res.end('Daily limit: 30 messages');
            return;
        }
        
        if (cooldowns.has(ip) && now - cooldowns.get(ip) < 2000) {
            res.writeHead(429);
            res.end('Wait 2 seconds');
            return;
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
                let text = data.text ? data.text.trim() : '';

                if (text.length < 1 || text.length > 100) {
                    res.writeHead(400);
                    res.end('1-100 chars');
                    return;
                }
                
                // Блокировка спама повторяющимися символами
                if (/(.)\1{15,}/.test(text)) {
                    res.writeHead(400);
                    res.end('No spam patterns');
                    return;
                }
                
                cooldowns.set(ip, now);
                daily.count++;
                dailyCounts.set(ip, daily);
                
                const timestamp = new Date().toLocaleTimeString();
                
                db.run('INSERT INTO messages (text, timestamp, ip_hash) VALUES (?, ?, ?)', 
                    [text, timestamp, ipHash], 
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

// Очистка
setInterval(() => {
    const now = Date.now();
    for (const [ip, time] of cooldowns.entries()) {
        if (now - time > 5000) cooldowns.delete(ip);
    }
    for (const [ip, time] of bannedIPs.entries()) {
        if (now - time > 3600000) bannedIPs.delete(ip); // Авторазбан через час
    }
}, 30000);

const port = Number(process.env.PORT) || 8080;
server.listen(port, '0.0.0.0', () => {
    console.log(`Chat running on port ${port}`);
});
