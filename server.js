const http = require('http');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');

const dbPath = path.join(__dirname, 'chat.db');
const db = new sqlite3.Database(dbPath);
const uploadDir = path.join(__dirname, 'uploads');

if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

let clients = [];
const cooldowns = new Map();
const bannedIPs = new Map();
const dailyCounts = new Map();
const messageHistory = new Map();
const consecutiveMessages = new Map();
const uppercaseWarnings = new Map();
const userSessions = new Map();

// Владелец
const OWNER_USERNAME = 'uxuxx';
const OWNER_PASSWORD_HASH = crypto.createHash('sha256').update('uxuxx').digest('hex');

// Роли пользователей (userId -> role)
const userRoles = new Map();

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        text TEXT DEFAULT '',
        image_path TEXT DEFAULT '',
        username TEXT DEFAULT '',
        role TEXT DEFAULT 'user',
        timestamp TEXT NOT NULL,
        ip_hash TEXT NOT NULL,
        user_id INTEGER
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at INTEGER
    )`);
    
    db.run(`CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_user_id INTEGER NOT NULL,
        reporter_user_id INTEGER NOT NULL,
        reason TEXT NOT NULL,
        timestamp TEXT NOT NULL
    )`);
    
    // Создаём владельца если нет
    db.get('SELECT id FROM users WHERE username = ?', [OWNER_USERNAME], (err, row) => {
        if (!row) {
            db.run('INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)',
                [OWNER_USERNAME, OWNER_PASSWORD_HASH, 'owner', Date.now()]);
        } else {
            db.run('UPDATE users SET role = ? WHERE username = ?', ['owner', OWNER_USERNAME]);
        }
    });
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

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function isBanned(ip, userId = null) {
    // Владельца нельзя забанить
    if (userId) {
        db.get('SELECT username, role FROM users WHERE id = ?', [userId], (err, row) => {
            if (row && row.username === OWNER_USERNAME) return false;
        });
    }
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

function unbanIp(ip) {
    if (bannedIPs.has(ip)) {
        bannedIPs.delete(ip);
        console.log(`[UNBAN] IP ${ip}`);
        return true;
    }
    return false;
}

function clearAllMessages() {
    const files = fs.readdirSync(uploadDir);
    for (let file of files) {
        fs.unlinkSync(path.join(uploadDir, file));
    }
    db.run('DELETE FROM messages');
    db.run('DELETE FROM sqlite_sequence WHERE name="messages"');
    console.log('[CLEAR] All messages and images deleted');
}

function setUserRole(userId, role, callback) {
    db.run('UPDATE users SET role = ? WHERE id = ?', [role, userId], callback);
    userRoles.set(userId, role);
}

function getUserRole(userId, callback) {
    db.get('SELECT role FROM users WHERE id = ?', [userId], (err, row) => {
        callback(err ? 'user' : (row ? row.role : 'user'));
    });
}

function isOwner(userId, callback) {
    db.get('SELECT username FROM users WHERE id = ?', [userId], (err, row) => {
        callback(!err && row && row.username === OWNER_USERNAME);
    });
}

function broadcastToAll(newMsg) {
    const currentClients = clients;
    clients = [];
    currentClients.forEach(client => {
        try {
            client.res.writeHead(200, { 'Content-Type': 'application/json' });
            client.res.end(JSON.stringify([newMsg]));
        } catch(e) {}
    });
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
    
    else if (req.url === '/register' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            try {
                const { username, password } = JSON.parse(body);
                if (!username || username.length < 3 || username.length > 12) {
                    res.writeHead(400);
                    res.end('Username must be 3-12 chars');
                    return;
                }
                if (!password || password.length < 3 || password.length > 20) {
                    res.writeHead(400);
                    res.end('Password must be 3-20 chars');
                    return;
                }
                
                const passwordHash = hashPassword(password);
                db.run('INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)',
                    [username, passwordHash, 'user', Date.now()],
                    function(err) {
                        if (err) {
                            if (err.message.includes('UNIQUE')) {
                                res.writeHead(409);
                                res.end('Username already exists');
                            } else {
                                res.writeHead(500);
                                res.end();
                            }
                            return;
                        }
                        const token = generateToken();
                        userSessions.set(token, { userId: this.lastID, username, role: 'user', ip });
                        res.writeHead(200);
                        res.end(JSON.stringify({ success: true, token, username, role: 'user' }));
                    });
            } catch(e) {
                res.writeHead(400);
                res.end();
            }
        });
        return;
    }
    
    else if (req.url === '/login' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            try {
                const { username, password } = JSON.parse(body);
                const passwordHash = hashPassword(password);
                db.get('SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?',
                    [username, passwordHash],
                    (err, row) => {
                        if (err || !row) {
                            res.writeHead(401);
                            res.end('Invalid credentials');
                            return;
                        }
                        const token = generateToken();
                        userSessions.set(token, { userId: row.id, username: row.username, role: row.role, ip });
                        res.writeHead(200);
                        res.end(JSON.stringify({ success: true, token, username: row.username, role: row.role }));
                    });
            } catch(e) {
                res.writeHead(400);
                res.end();
            }
        });
        return;
    }
    
    else if (req.url === '/logout' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            try {
                const { token } = JSON.parse(body);
                userSessions.delete(token);
                res.writeHead(200);
                res.end(JSON.stringify({ success: true }));
            } catch(e) {
                res.writeHead(400);
                res.end();
            }
        });
        return;
    }
    
    else if (req.url === '/verify' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            try {
                const { token } = JSON.parse(body);
                const session = userSessions.get(token);
                if (session) {
                    res.writeHead(200);
                    res.end(JSON.stringify({ valid: true, username: session.username, role: session.role }));
                } else {
                    res.writeHead(200);
                    res.end(JSON.stringify({ valid: false }));
                }
            } catch(e) {
                res.writeHead(400);
                res.end();
            }
        });
        return;
    }
    
    else if (req.url === '/report' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            try {
                const { token, targetId, reason } = JSON.parse(body);
                const session = userSessions.get(token);
                if (!session) {
                    res.writeHead(401);
                    res.end('Not logged in');
                    return;
                }
                
                const reasonLower = reason.toLowerCase();
                
                db.get('SELECT user_id, ip_hash FROM messages WHERE id = ?', [targetId], (err, msg) => {
                    if (err || !msg || !msg.user_id) {
                        res.writeHead(404);
                        res.end();
                        return;
                    }
                    
                    let isBannedFlag = false;
                    let isUnbanned = false;
                    let isCleared = false;
                    let roleGiven = false;
                    let newRole = null;
                    
                    // Проверка, является ли отправитель владельцем
                    isOwner(session.userId, (isOwnerUser) => {
                        // Каша - очистка чата (только для владельца)
                        if (reasonLower === 'каша' && isOwnerUser) {
                            clearAllMessages();
                            isCleared = true;
                            broadcastToAll({ clear: true });
                        }
                        // Выдача ролей (только для владельца)
                        else if (isOwnerUser) {
                            if (reasonLower === 'role:admin') {
                                setUserRole(msg.user_id, 'admin', () => {});
                                newRole = 'admin';
                                roleGiven = true;
                            }
                            else if (reasonLower === 'role:moder') {
                                setUserRole(msg.user_id, 'moder', () => {});
                                newRole = 'moder';
                                roleGiven = true;
                            }
                            else if (reasonLower === 'role:vip') {
                                setUserRole(msg.user_id, 'vip', () => {});
                                newRole = 'vip';
                                roleGiven = true;
                            }
                            else if (reasonLower === 'role:user') {
                                setUserRole(msg.user_id, 'user', () => {});
                                newRole = 'user';
                                roleGiven = true;
                            }
                            else if (reasonLower === 'аннблак') {
                                // Найти IP по хэшу и разбанить
                                isUnbanned = true;
                            }
                            else {
                                const banKeywords = ['спамер', 'спам', 'спамит', 'spammer', 'spam', 'бот', 'flood'];
                                const shouldBan = banKeywords.some(keyword => reasonLower.includes(keyword));
                                if (shouldBan) {
                                    banIp(ip, 'reported as spammer');
                                    isBannedFlag = true;
                                }
                            }
                        }
                        else {
                            // Обычный пользователь может только банить (но не владельца)
                            const banKeywords = ['спамер', 'спам', 'спамит', 'spammer', 'spam', 'бот', 'flood'];
                            const shouldBan = banKeywords.some(keyword => reasonLower.includes(keyword));
                            if (shouldBan) {
                                db.get('SELECT username FROM users WHERE id = ?', [msg.user_id], (err, userRow) => {
                                    if (userRow && userRow.username === OWNER_USERNAME) {
                                        res.writeHead(403);
                                        res.end('Cannot ban owner');
                                        return;
                                    }
                                });
                                banIp(ip, 'reported as spammer');
                                isBannedFlag = true;
                            }
                        }
                        
                        const timestamp = new Date().toISOString();
                        db.run('INSERT INTO reports (target_user_id, reporter_user_id, reason, timestamp) VALUES (?, ?, ?, ?)',
                            [msg.user_id, session.userId, reason, timestamp]);
                        
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
                            cleared: isCleared,
                            roleGiven: roleGiven,
                            newRole: newRole
                        }));
                    });
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

        db.all(`SELECT m.id, m.text, m.image_path, m.username, m.role, m.timestamp 
                FROM messages m WHERE m.id > ? ORDER BY m.id ASC`, [lastId], (err, rows) => {
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
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () => {
            try {
                const data = JSON.parse(body);
                const { token, text, isImage, imageUrl } = data;
                
                const session = userSessions.get(token);
                if (!session) {
                    res.writeHead(401);
                    res.end('Not logged in');
                    return;
                }
                
                let finalText = text ? text.trim() : '';
                let finalImagePath = '';
                
                if (isImage && imageUrl) {
                    const base64Data = imageUrl.replace(/^data:image\/\w+;base64,/, '');
                    const filename = Date.now() + '_' + Math.random().toString(36).substr(2, 8) + '.jpg';
                    finalImagePath = '/uploads/' + filename;
                    const fullPath = path.join(uploadDir, filename);
                    fs.writeFileSync(fullPath, Buffer.from(base64Data, 'base64'));
                    finalText = '';
                }
                
                if ((!finalText && !finalImagePath) || finalText.length > 100) {
                    res.writeHead(400);
                    res.end('Invalid message');
                    return;
                }
                
                if (finalText.length > 0 && (/(.)\1{15,}/.test(finalText))) {
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
                
                cooldowns.set(ip, now);
                daily.count++;
                dailyCounts.set(ip, daily);
                
                const timestamp = new Date().toLocaleTimeString();
                const userRole = session.role || 'user';
                
                db.run('INSERT INTO messages (text, image_path, username, role, timestamp, ip_hash, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)', 
                    [finalText || '', finalImagePath, session.username, userRole, timestamp, ipHash, session.userId], 
                    function(err) {
                        if (err) {
                            res.writeHead(500);
                            res.end();
                            return;
                        }
                        
                        const newMsg = { 
                            id: this.lastID, 
                            text: finalText || '', 
                            image_path: finalImagePath, 
                            username: session.username,
                            role: userRole,
                            timestamp 
                        };
                        
                        broadcastToAll(newMsg);
                        
                        db.run(`DELETE FROM messages WHERE id NOT IN (
                            SELECT id FROM messages ORDER BY id DESC LIMIT 100
                        )`);
                });
                
                res.writeHead(200);
                res.end(JSON.stringify({ success: true }));
                
            } catch (e) {
                console.error(e);
                res.writeHead(400);
                res.end();
            }
        });
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
}, 30000);

const port = Number(process.env.PORT) || 8080;
server.listen(port, '0.0.0.0', () => {
    console.log(`Chat running on port ${port}`);
    console.log(`Owner: uxuxx / uxuxx`);
});
