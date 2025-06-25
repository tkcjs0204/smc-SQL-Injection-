const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// 미들웨어 설정
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(session({
    secret: 'sql-injection-lab-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// 정적 파일 제공
app.use(express.static('public'));

// SQLite 데이터베이스 초기화
const db = new sqlite3.Database('database.sqlite');
db.serialize(() => {
    // 사용자 테이블
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // 게시글 테이블
    db.run(`CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        content TEXT,
        author TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // 상품 테이블
    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        price REAL,
        description TEXT,
        category TEXT,
        stock INTEGER
    )`);
    
    // 주문 테이블
    db.run(`CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        product_id INTEGER,
        quantity INTEGER,
        total_price REAL,
        order_date DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // 샘플 데이터 삽입 (users)
    db.get('SELECT COUNT(*) as cnt FROM users', (err, row) => {
        if (!row || row.cnt === 0) {
            db.run(`INSERT INTO users (username, password, email, role) VALUES 
                ('admin', '${bcrypt.hashSync('admin123', 10)}', 'admin@sql-lab.com', 'admin'),
                ('user1', '${bcrypt.hashSync('password123', 10)}', 'user1@sql-lab.com', 'user'),
                ('john', '${bcrypt.hashSync('john123', 10)}', 'john@sql-lab.com', 'user'),
                ('alice', '${bcrypt.hashSync('alice123', 10)}', 'alice@sql-lab.com', 'user'),
                ('bob', '${bcrypt.hashSync('bob123', 10)}', 'bob@sql-lab.com', 'user')`);
        }
    });
    
    db.run(`INSERT INTO posts (title, content, author) VALUES 
        ('Welcome to SQL Injection Lab', 'This is a safe environment to learn about SQL Injection vulnerabilities.', 'admin'),
        ('SQL Injection Basics', 'Learn the fundamentals of SQL Injection attacks.', 'admin'),
        ('Advanced SQL Injection', 'Explore advanced techniques and payloads.', 'admin'),
        ('Defense Strategies', 'How to protect against SQL Injection attacks.', 'admin')`);
    
    db.run(`INSERT INTO products (name, price, description, category, stock) VALUES 
        ('Laptop', 999.99, 'High-performance laptop for developers', 'Electronics', 50),
        ('Smartphone', 699.99, 'Latest smartphone with advanced features', 'Electronics', 100),
        ('Headphones', 199.99, 'Wireless noise-canceling headphones', 'Electronics', 75),
        ('Book: SQL Security', 49.99, 'Comprehensive guide to SQL security', 'Books', 25),
        ('Online Course', 299.99, 'Complete SQL Injection course', 'Education', 1000)`);
    
    db.run(`INSERT INTO orders (user_id, product_id, quantity, total_price) VALUES 
        (1, 1, 1, 999.99),
        (2, 2, 2, 1399.98),
        (3, 3, 1, 199.99),
        (4, 4, 3, 149.97)`);

    // 워게임 level1용 users_level1 테이블 및 FLAG 생성 (최초 1회)
    db.run(`CREATE TABLE IF NOT EXISTS users_level1 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userid TEXT,
        userpassword TEXT
    )`);
    db.get('SELECT COUNT(*) as cnt FROM users_level1', (err, row) => {
        if (!row || row.cnt === 0) {
            db.run(`INSERT INTO users_level1 (userid, userpassword) VALUES ('admin', 'FLAG{1=1_is_2_eas7}')`);
        }
    });

    // 워게임 level2용 users_level2 테이블 및 FLAG 생성 (최초 1회)
    db.run(`CREATE TABLE IF NOT EXISTS users_level2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userid TEXT,
        userpassword TEXT
    )`);
    db.get('SELECT COUNT(*) as cnt FROM users_level2', (err, row) => {
        if (!row || row.cnt === 0) {
            db.run(`INSERT INTO users_level2 (userid, userpassword) VALUES ('guest', 'guest'), ('admin', 'FLAG{y0u_Are_g0od_At_in7ect1on}')`);
        }
    });

    // 워게임 level3용 users_level3 테이블 및 FLAG 생성 (최초 1회)
    db.run(`CREATE TABLE IF NOT EXISTS users_level3 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userid TEXT,
        userpassword TEXT
    )`);
    db.get('SELECT COUNT(*) as cnt FROM users_level3', (err, row) => {
        if (!row || row.cnt === 0) {
            db.run(`INSERT INTO users_level3 (userid, userpassword) VALUES ('guest', 'guest'), ('admin', 'FLAG{3mpT7_Adm1n}')`);
        }
    });
    // 워게임 level4용 users_level4 테이블 및 FLAG 생성 (최초 1회)
    db.run(`CREATE TABLE IF NOT EXISTS users_level4 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userid TEXT,
        userpassword TEXT
    )`);
    db.get('SELECT COUNT(*) as cnt FROM users_level4', (err, row) => {
        if (!row || row.cnt === 0) {
            db.run(`INSERT INTO users_level4 (userid, userpassword) VALUES ('guest', 'guest'), ('admin', 'FLAG{yumin_is_handsome}')`);
        }
    });


    // submissions 테이블 (워게임 문제 풀이 기록)
    db.run(`CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        level INTEGER,
        flag TEXT,
        solved_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

// 메인 페이지
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// SQL Injection 단계별 학습 페이지
app.get('/sql-injection-levels', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'sql-injection-levels.html'));
});

// SQL Injection 실습 페이지
app.get('/sql-practice', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'sql-practice.html'));
});

// SQL Injection 게임 페이지
app.get('/sql-game', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'sql-game.html'));
});

// Level 1: 기본 인증 우회 (취약점 포함)
app.post('/sql-level1/login', (req, res) => {
    const { username, password } = req.body;
    
    // 취약점: 사용자 입력을 직접 SQL에 삽입
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    db.all(sql, (err, rows) => {
        if (err) {
            res.json({ success: false, error: err.message, sql: sql });
        } else {
            if (rows.length > 0) {
                res.json({ 
                    success: true, 
                    message: '로그인 성공!',
                    user: rows[0],
                    sql: sql
                });
            } else {
                res.json({ 
                    success: false, 
                    message: '로그인 실패',
                    sql: sql
                });
            }
        }
    });
});

// Level 2: 데이터 추출 (취약점 포함)
app.post('/sql-level2/search', (req, res) => {
    const { username, password } = req.body;

    // 취약한 쿼리: 사용자 입력 직접 삽입
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    db.all(sql, (err, rows) => {
        if (err) {
            return res.json({ success: false, error: err.message, sql: sql });
        }

        const hasAdmin = rows.some(row => row.username === 'admin');

        if (hasAdmin) {
            return res.json({
                success: true,
                message: 'admin 계정에 로그인 성공!',
                sql
            });
        } else {
            return res.json({
                success: false,
                message: '로그인 실패',
                sql
            });
        }
    });
});

app.post('/sql-level3/search', (req, res) => {
    const { username } = req.body;

    // "admin" 문자열 필터링: 모든 admin을 공백으로 대체
    username = username.replace(/admin/gi, '');

    // 취약한 쿼리: 사용자 입력 직접 삽입 (비밀번호 제거됨)
    const sql = `SELECT * FROM users WHERE username = '${username}'`;

    db.all(sql, (err, rows) => {
        if (err) {
            return res.json({ success: false, error: err.message, sql: sql });
        }

        // 결과 중 admin 계정 존재 여부 확인
        const hasAdmin = rows.some(row => row.username === 'admin');

        if (hasAdmin) {
            return res.json({
                success: true,
                message: 'admin 계정에 로그인 성공!',
                sql
            });
        } else {
            return res.json({
                success: false,
                message: '로그인 실패',
                sql
            });
        }
    });
});


app.post('/sql-level4/search', (req, res) => {
    const { password } = req.body;

    // 취약한 쿼리: 사용자 입력 직접 삽입
    const sql = `SELECT * FROM users WHERE username = 'admin' AND password = '${password}'`;

    db.all(sql, (err, rows) => {
        if (err) {
            return res.json({ success: false, error: err.message, sql: sql });
        }

        const rightPasswd = rows.some(row => row.password === 'yumin_is_handsome');

        if (rightPasswd) {
            return res.json({
                success: true,
                message: 'admin 계정에 로그인 성공!',
                sql
            });
        } else {
            return res.json({
                success: false,
                message: '로그인 실패',
                sql
            });
        }
    });
});



// 실습용 사용자 검색 (취약점 포함)
app.get('/practice/search-users', (req, res) => {
    const query = req.query.q;
    
    // 취약점: 사용자 입력을 직접 SQL에 삽입
    const sql = `SELECT * FROM users WHERE username LIKE '%${query}%' OR email LIKE '%${query}%'`;
    
    db.all(sql, (err, rows) => {
        if (err) {
            res.json({ success: false, error: err.message, sql: sql });
        } else {
            res.json({ 
                success: true, 
                results: rows,
                sql: sql
            });
        }
    });
});

// 실습용 상품 검색 (취약점 포함)
app.get('/practice/search-products', (req, res) => {
    const query = req.query.q;
    
    // 취약점: 사용자 입력을 직접 SQL에 삽입
    const sql = `SELECT * FROM products WHERE name LIKE '%${query}%' OR description LIKE '%${query}%' OR category LIKE '%${query}%'`;
    
    db.all(sql, (err, rows) => {
        if (err) {
            res.json({ success: false, error: err.message, sql: sql });
        } else {
            res.json({ 
                success: true, 
                results: rows,
                sql: sql
            });
        }
    });
});

// 실습용 주문 검색 (취약점 포함)
app.get('/practice/search-orders', (req, res) => {
    const query = req.query.q;
    
    // 취약점: 사용자 입력을 직접 SQL에 삽입
    const sql = `SELECT o.*, u.username, p.name as product_name 
                 FROM orders o 
                 JOIN users u ON o.user_id = u.id 
                 JOIN products p ON o.product_id = p.id 
                 WHERE u.username LIKE '%${query}%' OR p.name LIKE '%${query}%'`;
    
    db.all(sql, (err, rows) => {
        if (err) {
            res.json({ success: false, error: err.message, sql: sql });
        } else {
            res.json({ 
                success: true, 
                results: rows,
                sql: sql
            });
        }
    });
});

// 게임용 로그인 (취약점 포함)
app.post('/game/login', (req, res) => {
    const { username, password } = req.body;
    
    // 취약점: 사용자 입력을 직접 SQL에 삽입
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    db.all(sql, (err, rows) => {
        if (err) {
            res.json({ success: false, error: err.message, sql: sql });
        } else {
            if (rows.length > 0) {
                res.json({ 
                    success: true, 
                    message: '로그인 성공!',
                    user: rows[0],
                    sql: sql
                });
            } else {
                res.json({ 
                    success: false, 
                    message: '로그인 실패',
                    sql: sql
                });
            }
        }
    });
});

// 게임용 데이터 추출 (취약점 포함)
app.get('/game/extract-data', (req, res) => {
    const query = req.query.q;
    
    // 취약점: 사용자 입력을 직접 SQL에 삽입
    const sql = `SELECT * FROM users WHERE username LIKE '%${query}%'`;
    
    db.all(sql, (err, rows) => {
        if (err) {
            res.json({ success: false, error: err.message, sql: sql });
        } else {
            res.json({ 
                success: true, 
                results: rows,
                sql: sql
            });
        }
    });
});

// 회원가입 API (안전하게 구현)
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    if (!username || !password || !email) {
        return res.json({ success: false, message: '모든 필드를 입력하세요.' });
    }
    // 중복 체크
    db.get('SELECT * FROM users WHERE username = ? OR email = ?', [username, email], async (err, user) => {
        if (err) {
            return res.json({ success: false, message: 'DB 오류', error: err.message });
        }
        if (user) {
            return res.json({ success: false, message: '이미 존재하는 사용자명 또는 이메일입니다.' });
        }
        // 비밀번호 해시
        const hash = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', [username, hash, email], function(err) {
            if (err) {
                return res.json({ success: false, message: '회원가입 실패', error: err.message });
            }
            return res.json({ success: true, message: '회원가입 성공', userId: this.lastID });
        });
    });
});

// 로그인 API (안전하게 구현)
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.json({ success: false, message: '모든 필드를 입력하세요.' });
    }
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            return res.json({ success: false, message: 'DB 오류', error: err.message });
        }
        if (!user) {
            return res.json({ success: false, message: '존재하지 않는 사용자입니다.' });
        }
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.json({ success: false, message: '비밀번호가 일치하지 않습니다.' });
        }
        // 로그인 성공: 세션에 사용자 정보 저장
        req.session.user = { id: user.id, username: user.username, email: user.email, role: user.role };
        return res.json({ success: true, message: '로그인 성공', user: req.session.user });
    });
});

// 로그인 상태 및 사용자 정보 반환
app.get('/api/me', (req, res) => {
    if (req.session.user) {
        res.json({ success: true, user: req.session.user });
    } else {
        res.json({ success: false });
    }
});

// 로그아웃
app.get('/api/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

// 샘플 푼 문제 목록 반환 (실제 구현 전 임시)
app.get('/api/solved', (req, res) => {
    if (!req.session.user) return res.json([]);
    // 샘플 데이터
    res.json([
        { problem_id: 1, title: 'SQL Injection 기초', correct: true, solved_at: '2024-06-19' },
        { problem_id: 2, title: 'SQL Injection 심화', correct: false, solved_at: '2024-06-19' }
    ]);
});

// 워게임 level1: 문제 설명 및 폼 (GET)
app.get('/wargame/level1', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'wargame-level1.html'));
});

// 워게임 level1: 로그인 처리 (POST, 취약)
app.post('/wargame/level1', (req, res) => {
    const { userid, userpassword } = req.body;
    // 취약한 쿼리 (Dreamhack 스타일)
    const sql = `SELECT * FROM users_level1 WHERE userid = '${userid}' AND userpassword = '${userpassword}'`;
    db.all(sql, (err, rows) => {
        if (err) {
            return res.send(`<pre>에러: ${err.message}</pre><hr/><pre>${sql}</pre>`);
        }
        if (rows.length > 0) {
            if (rows[0].userid === 'admin') {
                return res.send(`
                  <h2>hello admin! FLAG is ${rows[0].userpassword}</h2>
                  <hr/><pre>${sql}</pre>
                  <script>
                    fetch('/api/submit-wargame', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ level: 1, flag: '${rows[0].userpassword}' })
                    });
                  </script>
                `);
            }
            return res.send(`<script>alert('hello ${rows[0].userid}');history.go(-1);</script><hr/><pre>${sql}</pre>`);
        }
        return res.send(`<script>alert('wrong');history.go(-1);</script><hr/><pre>${sql}</pre>`);
    });
});

// 워게임 level2: 문제 설명 및 폼 (GET)
app.get('/wargame/level2', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'wargame-level2.html'));
});

// 워게임 level2: 로그인 처리 (POST, 블라인드 취약)
app.post('/wargame/level2', (req, res) => {
    const { userid, userpassword } = req.body;
    const sql = `SELECT * FROM users_level2 WHERE userid = '${userid}' AND userpassword = '${userpassword}'`;
    db.all(sql, (err, rows) => {
        if (err) {
            return res.send(`<pre>에러: ${err.message}</pre><hr/><pre>${sql}</pre>`);
        }
        if (rows.length > 0) {
            if (rows[0].userid === 'admin') {
                return res.send(`
                  <h2>hello admin! FLAG is ${rows[0].userpassword}</h2>
                  <hr/><pre>${sql}</pre>
                  <script>
                    fetch('/api/submit-wargame', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ level: 2, flag: '${rows[0].userpassword}' })
                    });
                  </script>
                `);
            }
            return res.send(`<h2>hello guest</h2><hr/><pre>${sql}</pre>`);
        }
        return res.send(`<h2>wrong</h2><hr/><pre>${sql}</pre>`);
    });
});

// 워게임 level3: 문제 설명 및 폼 (GET)
app.get('/wargame/level3', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'wargame-level3.html'));
});

// 워게임 level3: 로그인 처리 (POST, WAF 필터링)
app.post('/wargame/level3', (req, res) => {
    let { userid, userpassword } = req.body;
    // "admin" 문자열 필터링: 모든 admin을 공백으로 대체
    userid = userid.replace(/admin/gi, '');
    
    const sql = `SELECT * FROM users_level3 WHERE userid = '${userid}' AND userpassword = '${userpassword}'`;
    db.all(sql, (err, rows) => {
        if (err) {
            return res.send(`<pre>에러: ${err.message}</pre><hr/><pre>${sql}</pre>`);
        }
        if (rows.length > 0) {
            if (rows[0].userid === 'admin') {
                return res.send(`
                  <h2>hello admin! FLAG is ${rows[0].userpassword}</h2>
                  <hr/><pre>${sql}</pre>
                  <script>
                    fetch('/api/submit-wargame', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ level: 3, flag: '${rows[0].userpassword}' })
                    });
                  </script>
                `);
            }
            return res.send(`<h2>hello guest</h2><hr/><pre>${sql}</pre>`);
        }
        return res.send(`<h2>wrong</h2><hr/><pre>${sql}</pre>`);
    });
});

// 워게임 level4: 문제 설명 및 폼 (GET)
app.get('/wargame/level4', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'wargame-level4.html'));
});

// 워게임 level4: 로그인 처리 (POST, 블라인드 SQL 인젝션)
app.post('/wargame/level4', (req, res) => {
    const { userpassword } = req.body;
    const sql = `SELECT * FROM users_level4 WHERE userid = 'admin' AND userpassword = '${userpassword}'`;
    db.all(sql, (err, rows) => {
        if (err) {
            return res.send(`<pre>에러: ${err.message}</pre><hr/><pre>${sql}</pre>`);
        }
        // 블라인드 SQL Injection 조건: 결과가 있으면 "you're not real admin" 출력
        if (rows.length > 0 && rows[0].id) {
            if (rows[0].userid === 'admin' && rows[0].userpassword === 'FLAG{yumin_is_handsome}') {
                return res.send(`
                    <h2>hello admin! FLAG is ${rows[0].userpassword}</h2>
                    <hr/><pre>${sql}</pre>
                `);
            } else {
                return res.send(`
                    <h2>you're not real admin</h2>
                    <hr/><pre>${sql}</pre>
                `);
            }
        } else {
            return res.send(`
                <h2>Login failed</h2>
                <hr/><pre>${sql}</pre>
            `);
        }
    });
});

// 워게임 문제 풀이 기록 저장 API
app.post('/api/submit-wargame', (req, res) => {
    if (!req.session.user) return res.json({ success: false, message: '로그인 필요' });
    const { level, flag } = req.body;
    db.run('INSERT INTO submissions (user_id, level, flag) VALUES (?, ?, ?)', [req.session.user.id, level, flag], function(err) {
        if (err) return res.json({ success: false, message: 'DB 오류', error: err.message });
        res.json({ success: true });
    });
});

// GET /api/solved: 로그인한 유저의 워게임 풀이 기록 반환 (user.html에서 사용)
app.get('/api/solved', (req, res) => {
    if (!req.session.user) return res.json([]);
    db.all('SELECT level, flag, solved_at FROM submissions WHERE user_id = ? ORDER BY solved_at DESC', [req.session.user.id], (err, rows) => {
        if (err) return res.json([]);
        res.json(rows);
    });
});

// 서버 시작
app.listen(PORT, () => {
    console.log(`🚀 SQL Injection Lab 서버가 포트 ${PORT}에서 실행 중입니다!`);
    console.log(`📚 학습 사이트: http://localhost:${PORT}`);
    console.log(`🎯 단계별 학습: http://localhost:${PORT}/sql-injection-levels`);
    console.log(`🔬 실습 환경: http://localhost:${PORT}/sql-practice`);
    console.log(`🎮 게임 모드: http://localhost:${PORT}/sql-game`);
});