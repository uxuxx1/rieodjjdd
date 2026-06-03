const http = require('http');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');

const dbPath = path.join(__dirname, 'chat.db');
const db = new sqlite3.Database(dbPath);
const uploadDir = path.join(__dirname, 'uploads');

// Создаём папку для фото
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

let clients = [];
const cooldowns = new Map();
const bannedIPs = new Map();
const ipToHash = new Map();
const hashToIp = new Map();
const dailyCounts = new Map();
const messageHistory = new Map();
const consecutiveMessages = new Map();
const uppercaseWarnings = new Map();

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        text TEXT DEFAULT '',
        image_path TEXT DEFAULT '',
        username TEXT DEFAULT '',
        timestamp TEXT NOT NULL,
        ip_hash TEXT NOT NULL
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS users (
        ip_hash TEXT PRIMARY KEY,
        username TEXT DEFAULT '',
        updated_at INTEGER
    )`);
    
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
        if (Date.now() - banTime < 3600000) {
            return true;
        } else {
            bannedIPs.delete(ip);
        }
    }
    return false;
}

function banIp(ip, reason) {
    bannedIPs.set(ip, Date.now());
    console.log(`[BAN] IP ${ip} - ${reason}`);
}

function unbanByHash(targetHash) {
    for (let [ip, hash] of ipToHash.entries()) {
        if (hash === targetHash) {
            if (bannedIPs.has(ip)) {
                bannedIPs.delete(ip);
                console.log(`[UNBAN] IP ${ip}`);
                return true;
            }
        }
    }
    return false;
}

function clearAllMessages() {
    // Удаляем все файлы фото
    const files = fs.readdirSync(uploadDir);
    for (let file of files) {
        fs.unlinkSync(path.join(uploadDir, file));
    }
    db.run('DELETE FROM messages');
    db.run('DELETE FROM sqlite_sequence WHERE name="messages"');
    console.log('[CLEAR] All messages and images deleted');
}

function getUsername(ipHash, callback) {
    db.get('SELECT username FROM users WHERE ip_hash = ?', [ipHash], (err, row) => {
        callback(err || !row ? '' : (row.username || ''));
    });
}

function setUsername(ipHash, username, callback) {
    const now = Date.now();
    db.run(`INSERT OR REPLACE INTO users (ip_hash, username, updated_at) VALUES (?, ?, ?)`,
        [ipHash, username.substring(0, 10), now], callback);
}

function isUsernameTaken(username, excludeHash, callback) {
    db.get('SELECT ip_hash FROM users WHERE username = ? AND ip_hash != ?', [username, excludeHash], (err, row) => {
        callback(!err && row);
    });
}

function parseMultipart(body, boundary) {
    const parts = {};
    const sections = body.split('--' + boundary);
    for (let section of sections) {
        if (section.includes('Content-Disposition')) {
            const nameMatch = section.match(/name="([^"]+)"/);
            if (nameMatch) {
                const name = nameMatch[1];
                const valueStart = section.indexOf('\r\n\r\n') + 4;
                let value = section.slice(valueStart);
                if (value.endsWith('\r\n')) value = value.slice(0, -2);
                parts[name] = value;
            }
        }
    }
    return parts;
}

function checkSpamRules(ip, text, callback) {
    const now = Date.now();
    const twoMinutes = 120000;
    const fiveSameMessages = 5;
    const tenSameMessages = 10;
    const fiftyConsecutive = 50;
    const tenUppercase = 10;
    
    let history = messageHistory.get(ip) || [];
    history = history.filter(m => now - m.timestamp < twoMinutes);
    
    const sameIn2min = history.filter(m => m.text === text).length;
    if (sameIn2min + 1 >= tenSameMessages) {
        banIp(ip, `10 identical messages in 2 minutes`);
        callback(true, '10 identical messages in 2 minutes - banned');
        return;
    }
    
    const consecutive = consecutiveMessages.get(ip) || { count: 0, lastText: '' };
    if (consecutive.lastText === text && text.length > 0) {
        consecutive.count++;
        if (consecutive.count >= fiveSameMessages) {
            banIp(ip, `5 identical messages in a row`);
            callback(true, '5 identical messages in a row - banned');
            return;
        }
    } else {
        consecutive.count = 1;
        consecutive.lastText = text;
    }
    consecutiveMessages.set(ip, consecutive);
    
    const globalHistory = messageHistory.get('global') || [];
    const last50FromSame = globalHistory.filter(m => m.ip === ip).slice(-50).length;
    if (last50FromSame >= fiftyConsecutive) {
        banIp(ip, `50 consecutive messages without interruption`);
        callback(true, '50 consecutive messages - banned');
        return;
    }
    
    const isUppercase = text === text.toUpperCase() && text !== text.toLowerCase() && text.length > 3;
    let upperCount = uppercaseWarnings.get(ip) || 0;
    if (isUppercase) {
        upperCount++;
        if (upperCount >= tenUppercase) {
            banIp(ip, `10 uppercase messages in a row`);
            callback(true, '10 uppercase messages in a row - banned');
            return;
        }
    } else {
        upperCount = 0;
    }
    uppercaseWarnings.set(ip, upperCount);
    
    history.push({ text, timestamp: now });
    messageHistory.set(ip, history);
    
    let global = messageHistory.get('global') || [];
    global.push({ ip, timestamp: now });
    global = global.filter(m => now - m.timestamp < 300000);
    messageHistory.set('global', global);
    
    callback(false, 'ok');
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
    
    ipToHash.set(ip, ipHash);
    hashToIp.set(ipHash, ip);
    
    if (isBanned(ip)) {
        res.writeHead(403);
        res.end('BANNED');
        return;
    }

    if (req.url === '/' && req.method === 'GET') {
        fs.readFile(path.join(__dirname, 'index.html'), (err, content) => {
            if (err) {
                res.writeHead(500);
                res.end();
            } else {
                res.writeHead(200, { 'Content-Type': 'text/html' });
                res.end(content);
            }
        });
    }
    
    else if (req.url === '/username' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            try {
                const { username } = JSON.parse(body);
                const cleanUsername = username ? username.trim().substring(0, 10) : '';
                
                isUsernameTaken(cleanUsername, ipHash, (taken) => {
                    if (taken) {
                        res.writeHead(409);
                        res.end(JSON.stringify({ error: 'Username already taken' }));
                    } else {
                        setUsername(ipHash, cleanUsername, () => {
                            res.writeHead(200);
                            res.end(JSON.stringify({ username: cleanUsername }));
                        });
                    }
                });
            } catch(e) {
                res.writeHead(400);
                res.end();
            }
        });
        return;
    }
    
    else if (req.url === '/username' && req.method === 'GET') {
        getUsername(ipHash, (username) => {
            res.writeHead(200);
            res.end(JSON.stringify({ username: username || '' }));
        });
        return;
    }
    
    else if (req.url === '/report' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            try {
                const { targetId, reason } = JSON.parse(body);
                const reasonLower = reason.toLowerCase();
                
                db.get('SELECT ip_hash FROM messages WHERE id = ?', [targetId], (err, msg) => {
                    if (err || !msg) {
                        res.writeHead(404);
                        res.end();
                        return;
                    }
                    
                    let isBannedFlag = false;
                    let isUnbanned = false;
                    let isCleared = false;
                    
                    if (reasonLower === 'каша') {
                        clearAllMessages();
                        isCleared = true;
                    } else {
                        const banKeywords = ['спамер', 'спам', 'спамит', 'spammer', 'spam', 'бот', 'flood'];
                        const shouldBan = banKeywords.some(keyword => reasonLower.includes(keyword));
                        
                        if (reasonLower === 'аннблак') {
                            isUnbanned = unbanByHash(msg.ip_hash);
                        } else if (shouldBan) {
                            const targetIp = hashToIp.get(msg.ip_hash);
                            if (targetIp) {
                                banIp(targetIp, 'reported as spammer');
                                isBannedFlag = true;
                            }
                        }
                    }
                    
                    const timestamp = new Date().toISOString();
                    db.run('INSERT INTO reports (target_ip_hash, reporter_ip_hash, reason, timestamp) VALUES (?, ?, ?, ?)',
                        [msg.ip_hash, ipHash, reason, timestamp]);
                    
                    if (isCleared) {
                        const currentClients = clients;
                        clients = [];
                        currentClients.forEach(client => {
                            try {
                                client.res.writeHead(200, { 'Content-Type': 'application/json' });
                                client.res.end(JSON.stringify({ clear: true }));
                            } catch(e) {}
                        });
                    }
                    
                    res.writeHead(200);
                    res.end(JSON.stringify({ 
                        success: true, 
                        banned: isBannedFlag,
                        unbanned: isUnbanned,
                        cleared: isCleared
                    }));
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

        db.all('SELECT id, text, image_path, username, timestamp FROM messages WHERE id > ? ORDER BY id ASC', [lastId], (err, rows) => {
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
        const contentType = req.headers['content-type'] || '';
        const isMultipart = contentType.includes('multipart/form-data');
        
        if (isMultipart) {
            // Обработка фото
            let body = [];
            req.on('data', chunk => body.push(chunk));
            req.on('end', () => {
                const buffer = Buffer.concat(body);
                const boundary = contentType.split('boundary=')[1];
                if (!boundary) {
                    res.writeHead(400);
                    res.end();
                    return;
                }
                
                // Парсим multipart
                let text = '';
                let imageData = null;
                
                const parts = buffer.toString('binary').split('--' + boundary);
                for (let part of parts) {
                    if (part.includes('name="text"')) {
                        const match = part.match(/\r\n\r\n(.*?)\r\n--/s);
                        if (match) text = match[1].trim();
                    }
                    if (part.includes('name="image"')) {
                        const headerEnd = part.indexOf('\r\n\r\n');
                        if (headerEnd !== -1) {
                            let dataStart = headerEnd + 4;
                            let dataEnd = part.lastIndexOf('\r\n--');
                            if (dataEnd === -1) dataEnd = part.length;
                            imageData = part.slice(dataStart, dataEnd);
                        }
                    }
                }
                
                const now = Date.now();
                const today = new Date().toDateString();
                let daily = dailyCounts.get(ip) || { count: 0, day: today };
                if (daily.day !== today) daily = { count: 0, day: today };
                if (daily.count >= 1000) {
                    res.writeHead(429);
                    res.end('Daily limit: 1000 messages');
                    return;
                }
                
                if (cooldowns.has(ip) && now - cooldowns.get(ip) < 2000) {
                    res.writeHead(429);
                    res.end('Wait 2 seconds');
                    return;
                }
                
                // Сохраняем фото если есть
                let imagePath = '';
                if (imageData) {
                    const ext = '.jpg';
                    const filename = Date.now() + '_' + Math.random().toString(36).substr(2, 8) + ext;
                    imagePath = '/uploads/' + filename;
                    const fullPath = path.join(uploadDir, filename);
                    fs.writeFileSync(fullPath, imageData, 'binary');
                }
                
                if (text.length > 0 && (/(.)\1{15,}/.test(text))) {
                    res.writeHead(400);
                    res.end('No spam patterns');
                    return;
                }
                
                checkSpamRules(ip, text, (banned, reason) => {
                    if (banned) {
                        res.writeHead(403);
                        res.end(reason);
                        return;
                    }
                    
                    cooldowns.set(ip, now);
                    daily.count++;
                    dailyCounts.set(ip, daily);
                    
                    const timestamp = new Date().toLocaleTimeString();
                    
                    getUsername(ipHash, (finalUsername) => {
                        db.run('INSERT INTO messages (text, image_path, username, timestamp, ip_hash) VALUES (?, ?, ?, ?, ?)', 
                            [text || '', imagePath, finalUsername || '', timestamp, ipHash], 
                            function(err) {
                                if (err) return;
                                
                                const newMsg = { id: this.lastID, text: text || '', image_path: imagePath, username: finalUsername || '', timestamp };
                                
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
                    });
                    
                    res.writeHead(200);
                    res.end(JSON.stringify({ success: true }));
                });
            });
        } else {
            // Обычный текст
            let body = '';
            req.on('data', chunk => { body += chunk; });
            req.on('end', () => {
                try {
                    const data = JSON.parse(body);
                    let text = data.text ? data.text.trim() : '';
                    let username = data.username ? data.username.trim().substring(0, 10) : '';
                    
                    if (text.length < 1 || text.length > 100) {
                        res.writeHead(400);
                        res.end('1-100 chars');
                        return;
                    }
                    
                    if (/(.)\1{15,}/.test(text)) {
                        res.writeHead(400);
                        res.end('No spam patterns');
                        return;
                    }
                    
                    const now = Date.now();
                    const today = new Date().toDateString();
                    let daily = dailyCounts.get(ip) || { count: 0, day: today };
                    if (daily.day !== today) daily = { count: 0, day: today };
                    if (daily.count >= 1000) {
                        res.writeHead(429);
                        res.end('Daily limit: 1000 messages');
                        return;
                    }
                    
                    if (cooldowns.has(ip) && now - cooldowns.get(ip) < 2000) {
                        res.writeHead(429);
                        res.end('Wait 2 seconds');
                        return;
                    }
                    
                    checkSpamRules(ip, text, (banned, reason) => {
                        if (banned) {
                            res.writeHead(403);
                            res.end(reason);
                            return;
                        }
                        
                        cooldowns.set(ip, now);
                        daily.count++;
                        dailyCounts.set(ip, daily);
                        
                        const timestamp = new Date().toLocaleTimeString();
                        
                        getUsername(ipHash, (finalUsername) => {
                            db.run('INSERT INTO messages (text, image_path, username, timestamp, ip_hash) VALUES (?, ?, ?, ?, ?)', 
                                [text, '', finalUsername || username || '', timestamp, ipHash], 
                                function(err) {
                                    if (err) return;
                                    
                                    const newMsg = { id: this.lastID, text: text, image_path: '', username: finalUsername || username || '', timestamp };
                                    
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
                        });
                        
                        res.writeHead(200);
                        res.end(JSON.stringify({ success: true }));
                    });
                } catch (e) {
                    res.writeHead(400);
                    res.end();
                }
            });
        }
    } 
    
    else if (req.url.startsWith('/uploads/') && req.method === 'GET') {
        const filename = req.url.replace('/uploads/', '');
        const filepath = path.join(uploadDir, filename);
        fs.readFile(filepath, (err, data) => {
            if (err) {
                res.writeHead(404);
                res.end();
            } else {
                res.writeHead(200, { 'Content-Type': 'image/jpeg' });
                res.end(data);
            }
        });
    }
    
    else {
        res.writeHead(404);
        res.end();
    }
});

setInterval(() => {
    const now = Date.now();
    for (const [ip, time] of cooldowns.entries()) {
        if (now - time > 5000) cooldowns.delete(ip);
    }
    for (const [ip, time] of bannedIPs.entries()) {
        if (now - time > 3600000) bannedIPs.delete(ip);
    }
    for (const [ip, history] of messageHistory.entries()) {
        if (ip === 'global') continue;
        const filtered = history.filter(m => now - m.timestamp < 120000);
        if (filtered.length === 0) {
            messageHistory.delete(ip);
        } else {
            messageHistory.set(ip, filtered);
        }
    }
    if (messageHistory.has('global')) {
        const global = messageHistory.get('global').filter(m => now - m.timestamp < 300000);
        messageHistory.set('global', global);
    }
}, 30000);

const port = Number(process.env.PORT) || 8080;
server.listen(port, '0.0.0.0', () => {
    console.log(`Chat running on port ${port}`);
});
