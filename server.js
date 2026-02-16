require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3000;

// Security
app.use(helmet({
    contentSecurityPolicy: false, // Biar Bootstrap jalan
}));

// Database
const db = new sqlite3.Database('./kmap.sqlite');
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE, password TEXT, fullname TEXT,
        role TEXT DEFAULT 'user', bio TEXT, phone TEXT,
        photo TEXT DEFAULT 'https://cdn-icons-png.flaticon.com/512/847/847969.png'
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, user_name TEXT,
        desa TEXT, kec TEXT, hama TEXT, status TEXT, lat REAL, lon REAL,
        foto TEXT, waktu TEXT, is_verified INTEGER DEFAULT 0
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, seller_name TEXT,
        seller_phone TEXT, product_name TEXT, price REAL, description TEXT,
        photo TEXT, created_at TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS proposals (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, user_name TEXT,
        type TEXT, amount TEXT, reason TEXT, status TEXT DEFAULT 'Pending', created_at TEXT
    )`);
    
    // Admin default
    const adminPass = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, password, fullname, role) 
            VALUES ('admin', '${adminPass}', 'Administrator', 'admin')`);
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.set('view engine', 'ejs');

app.use(session({
    secret: process.env.SESSION_SECRET || 'rahasia123',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, maxAge: 24*60*60*1000 }
}));

// Upload
const storage = multer.diskStorage({
    destination: './public/uploads/',
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

if (!fs.existsSync('./public/uploads')) fs.mkdirSync('./public/uploads', { recursive: true });

db.query = (sql, params = []) => new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
});

// Auth
const requireLogin = (req, res, next) => req.session.user ? next() : res.redirect('/login');
const requireAdmin = (req, res, next) => (req.session.user?.role === 'admin') ? next() : res.redirect('/');

// Routes
app.get('/', requireLogin, (req, res) => {
    db.get("SELECT * FROM users WHERE id = ?", [req.session.user.id], (err, row) => {
        if (row) req.session.user = row;
        res.render('landing', { user: req.session.user });
    });
});

app.get('/login', (req, res) => {
    if (req.session.user) return res.redirect('/');
    res.render('login', { message: null });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.user = user;
            res.redirect('/');
        } else {
            res.render('login', { message: 'Username atau Password salah!' });
        }
    });
});

app.get('/logout', (req, res) => { req.session.destroy(); res.redirect('/login'); });

app.get('/register', (req, res) => res.render('register', { message: null }));

app.post('/register', (req, res) => {
    const { fullname, username, password } = req.body;
    if (password.length < 6) return res.render('register', { message: 'Password minimal 6 karakter!' });
    
    const hash = bcrypt.hashSync(password, 10);
    const defaultPhoto = 'https://cdn-icons-png.flaticon.com/512/847/847969.png';
    
    db.run("INSERT INTO users (fullname, username, password, photo) VALUES (?,?,?,?)", 
        [fullname, username, hash, defaultPhoto], (err) => {
        if (err) res.render('register', { message: 'Username sudah digunakan!' });
        else res.render('login', { message: 'Registrasi Berhasil! Silakan Login.' });
    });
});

// Dashboard
app.get('/dashboard', requireLogin, async (req, res) => {
    const user = req.session.user;
    const reports = user.role === 'admin' 
        ? await db.query("SELECT * FROM reports ORDER BY id DESC")
        : await db.query("SELECT * FROM reports WHERE is_verified=1 OR user_id=? ORDER BY id DESC", [user.id]);
    
    const stats = {
        total: (await db.query("SELECT COUNT(*) as c FROM reports"))[0].c,
        bahaya: (await db.query("SELECT COUNT(*) as c FROM reports WHERE status='Bahaya'"))[0].c,
        waspada: (await db.query("SELECT COUNT(*) as c FROM reports WHERE status='Waspada'"))[0].c,
        aman: (await db.query("SELECT COUNT(*) as c FROM reports WHERE status='Aman'"))[0].c
    };
    
    const usersList = user.role === 'admin' ? await db.query("SELECT username, role FROM users") : [];
    const notification = req.session.notification || null;
    req.session.notification = null;
    
    res.render('dashboard', { user, reports, stats, usersList, notification });
});

app.post('/lapor', requireLogin, upload.single('foto'), (req, res) => {
    const { desa, kec, hama, status, lat, lon } = req.body;
    const foto = req.file ? `/uploads/${req.file.filename}` : '';
    const waktu = new Date().toLocaleString('id-ID');
    
    db.run(`INSERT INTO reports VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?)`,
        [req.session.user.id, req.session.user.fullname, desa, kec, hama, status, lat, lon, foto, waktu, 0],
        () => {
            req.session.notification = { type: 'success', message: 'Laporan berhasil dikirim!' };
            res.redirect('/dashboard');
        });
});

// Pasar
app.get('/pasar', requireLogin, async (req, res) => {
    const products = await db.query("SELECT * FROM products ORDER BY id DESC");
    res.render('pasar', { user: req.session.user, products });
});

app.post('/pasar/add', requireLogin, upload.single('product_photo'), (req, res) => {
    const { product_name, price, description, seller_phone } = req.body;
    const photo = req.file ? `/uploads/${req.file.filename}` : 'https://cdn-icons-png.flaticon.com/512/2921/2921822.png';
    const phone = seller_phone.replace(/^0/, '62');
    
    db.run(`INSERT INTO products VALUES (NULL,?,?,?,?,?,?,?,?)`,
        [req.session.user.id, req.session.user.fullname, phone, product_name, price, description, photo, 
         new Date().toLocaleString('id-ID')],
        () => res.redirect('/pasar'));
});

app.get('/pasar/delete/:id', requireLogin, async (req, res) => {
    const product = await db.query("SELECT * FROM products WHERE id = ?", [req.params.id]);
    if (product.length && (req.session.user.role === 'admin' || req.session.user.id === product[0].user_id)) {
        db.run("DELETE FROM products WHERE id = ?", [req.params.id]);
    }
    res.redirect('/pasar');
});

// Profil
app.get('/profil', requireLogin, (req, res) => {
    db.get("SELECT * FROM users WHERE id = ?", [req.session.user.id], (err, row) => {
        req.session.user = row;
        const notification = req.session.notification || null;
        req.session.notification = null;
        res.render('profil', { user: row, notification });
    });
});

app.post('/profil/update', requireLogin, upload.single('profile_photo'), (req, res) => {
    const { fullname, bio, phone } = req.body;
    const userId = req.session.user.id;
    
    if (req.file) {
        db.run("UPDATE users SET fullname=?, bio=?, phone=?, photo=? WHERE id=?", 
            [fullname, bio, phone, `/uploads/${req.file.filename}`, userId], () => {
                req.session.notification = { type: 'success', message: 'Profil berhasil diperbarui!' };
                res.redirect('/profil');
            });
    } else {
        db.run("UPDATE users SET fullname=?, bio=?, phone=? WHERE id=?", 
            [fullname, bio, phone, userId], () => {
                req.session.notification = { type: 'success', message: 'Profil berhasil diperbarui!' };
                res.redirect('/profil');
            });
    }
});

// Bantuan
app.get('/bantuan', requireLogin, async (req, res) => {
    const user = req.session.user;
    const proposals = user.role === 'admin' 
        ? await db.query("SELECT * FROM proposals ORDER BY id DESC")
        : await db.query("SELECT * FROM proposals WHERE user_id = ? ORDER BY id DESC", [user.id]);
    
    const notification = req.session.notification || null;
    req.session.notification = null;
    res.render('bantuan', { user, proposals, notification });
});

app.post('/bantuan/add', requireLogin, (req, res) => {
    const { type, amount, reason } = req.body;
    db.run(`INSERT INTO proposals VALUES (NULL,?,?,?,?,?,?,?)`,
        [req.session.user.id, req.session.user.fullname, type, amount, reason, 'Pending', 
         new Date().toLocaleString('id-ID')],
        () => {
            req.session.notification = { type: 'success', message: 'Proposal berhasil diajukan!' };
            res.redirect('/bantuan');
        });
});

// Admin
app.get('/admin/bantuan/approve/:id', requireAdmin, (req, res) => {
    db.run("UPDATE proposals SET status = 'Disetujui' WHERE id = ?", [req.params.id], () => {
        req.session.notification = { type: 'success', message: 'Proposal Disetujui' };
        res.redirect('/bantuan');
    });
});

app.get('/admin/bantuan/reject/:id', requireAdmin, (req, res) => {
    db.run("UPDATE proposals SET status = 'Ditolak' WHERE id = ?", [req.params.id], () => {
        req.session.notification = { type: 'error', message: 'Proposal Ditolak' };
        res.redirect('/bantuan');
    });
});

app.get('/admin/verify/:id', requireAdmin, (req, res) => { 
    db.run("UPDATE reports SET is_verified = 1 WHERE id = ?", [req.params.id], () => res.redirect('/dashboard')); 
});

app.get('/admin/delete-report/:id', requireAdmin, (req, res) => { 
    db.run("DELETE FROM reports WHERE id = ?", [req.params.id], () => res.redirect('/dashboard')); 
});

app.post('/admin/create-user', requireAdmin, (req, res) => {
    const { newFullname, newUsername, newPassword, newRole } = req.body;
    const hash = bcrypt.hashSync(newPassword, 10);
    db.run("INSERT INTO users (fullname, username, password, role) VALUES (?,?,?,?)", 
        [newFullname, newUsername, hash, newRole], () => res.redirect('/dashboard'));
});

app.post('/admin/reset-password', requireAdmin, (req, res) => {
    const { targetUsername, newPass } = req.body;
    const hash = bcrypt.hashSync(newPass, 10);
    db.run("UPDATE users SET password = ? WHERE username = ?", [hash, targetUsername], () => res.redirect('/dashboard'));
});

app.get('/admin/export-csv', requireAdmin, async (req, res) => {
    const reports = await db.query("SELECT * FROM reports");
    let csv = "ID,Waktu,Pelapor,Desa,Kecamatan,Hama,Status,Lat,Lon\n";
    reports.forEach(r => csv += `${r.id},"${r.waktu}","${r.user_name}","${r.desa}","${r.kec}","${r.hama}","${r.status}",${r.lat},${r.lon}\n`);
    res.header('Content-Type', 'text/csv'); 
    res.attachment('data-laporan.csv'); 
    res.send(csv);
});

app.get('/api/heatmap-data', async (req, res) => {
    const reports = await db.query("SELECT lat, lon, status FROM reports WHERE is_verified = 1");
    const heatmapData = reports.map(r => {
        let intensity = 0.2; 
        if (r.status === 'Bahaya') intensity = 1.0; 
        else if (r.status === 'Waspada') intensity = 0.6;
        return [r.lat, r.lon, intensity];
    });
    res.json(heatmapData);
});

app.listen(PORT, () => console.log(`🚀 Server jalan di http://localhost:${PORT}`));