const http = require('http');
const fs = require('fs');
const path = require('path');

const colors = [
    '#ff0000', '#990000', '#ff7f00', '#994c00', '#ffff00', '#999900',
    '#00ff00', '#009900', '#0000ff', '#000099', '#4b0082', '#2e0051',
    '#8b00ff', '#550099', '#ffffff', '#000000'
];

const canvasSize = 500 * 500;
let matrix = new Uint8Array(canvasSize);
matrix.fill(14); // белый цвет по умолчанию

const server = http.createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    // если человек просто зашел на сайт (корень /), отдаем ему index.html
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
    
    else if (req.url === '/matrix' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
        res.end(Buffer.from(matrix.buffer));
    } 
    
    else if (req.url === '/draw' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', () => {
            const data = JSON.parse(body);
            const x = parseInt(data.x);
            const y = parseInt(data.y);
            const colorHex = data.color.toLowerCase();

            if (x >= 0 && x < 500 && y >= 0 && y < 500) {
                const colorIdx = colors.indexOf(colorHex);
                if (colorIdx !== -1) {
                    const position = y * 500 + x;
                    matrix[position] = colorIdx;
                }
            }
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true }));
        });
    } 
    
    else {
        res.writeHead(404);
        res.end();
    }
});

const port = process.env.PORT || 3000;
server.listen(port, () => {
    console.log(`grid engine active on port ${port}`);
});