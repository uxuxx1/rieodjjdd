const http = require('http');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

// Файл базы данных будет создан автоматически в той же папке
const dbPath = path.join(__dirname, 'chat.db');
const db = new sqlite3.Database(dbPath);

let clients = [];

// Создание таблицы при первом запуске
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

    // Отдача главного интерфейса
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
    
    // Получение новых сообщений (Long Polling)
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
    
    // Обработка отправки нового сообщения
    else if (req.url === '/send' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => {
            try {
                const data = JSON.parse(body);
                const text = data.text ? data.text.trim() : '';

                // Строгая проверка: только текст от 1 до 100 символов
                if (text.length > 0 && text.length <= 100) {
                    const timestamp = new Date().toLocaleTimeString();

                    db.run('INSERT INTO messages (text, timestamp) VALUES (?, ?)', [text, timestamp], function(err) {
                        if (err) return;

                        const newMsg = { id: this.lastID, text, timestamp };

                        // Автоматическая очистка: удаляем всё, что не входит в последние 100 сообщений
                        db.run(`DELETE FROM messages WHERE id NOT IN (
                            SELECT id FROM messages ORDER BY id DESC LIMIT 100
                        )`);

                        // Моментальная рассылка всем, кто сейчас онлайн
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

const port = Number(process.env.PORT) || 8080;
server.listen(port, '0.0.0.0', () => {
    console.log(`chat engine active on port ${port}`);
});
