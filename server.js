// =============================================
//   SERVER.JS - Backend Utama
//   Teknologi: Node.js + Express + LowDB (JSON)
// =============================================

import express from 'express';
import bcrypt  from 'bcryptjs';
import jwt     from 'jsonwebtoken';
import cors    from 'cors';
import path    from 'path';
import { fileURLToPath } from 'url';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app    = express();
const PORT   = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'rahasia_jwt_kamu_123';

const adapter = new JSONFile('db.json');
const defaultData = { users: [] };
const db = new Low(adapter, defaultData);
await db.read();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.resolve('public')));

app.get('/', (req, res) => {
  res.sendFile(path.resolve('public', 'index.html'));
});

console.log('✅ Database siap!');

// =============================================
//   HELPER - Cek token login
// =============================================
function cekToken(req, res) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) { res.status(401).json({ error: 'Kamu harus login dulu!' }); return null; }
  try {
    return jwt.verify(token, SECRET);
  } catch {
    res.status(403).json({ error: 'Token tidak valid atau sudah expired!' });
    return null;
  }
}

// =============================================
//   ROUTES
// =============================================

// POST /api/register
app.post('/api/register', async (req, res) => {
  const { nama, email, password } = req.body;
  if (!nama || !email || !password)
    return res.status(400).json({ error: 'Semua kolom harus diisi!' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password minimal 6 karakter!' });
  if (db.data.users.find(u => u.email === email))
    return res.status(409).json({ error: 'Email sudah terdaftar!' });

  const passwordTerenkripsi = await bcrypt.hash(password, 10);
  db.data.users.push({ id: Date.now(), nama, email, password: passwordTerenkripsi, createdAt: new Date().toISOString() });
  await db.write();
  res.status(201).json({ message: 'Registrasi berhasil! Silakan login.' });
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email dan password wajib diisi!' });

  const user = db.data.users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Email atau password salah!' });

  const cocok = await bcrypt.compare(password, user.password);
  if (!cocok) return res.status(401).json({ error: 'Email atau password salah!' });

  const token = jwt.sign({ id: user.id, nama: user.nama, email: user.email }, SECRET, { expiresIn: '1d' });
  res.json({ message: 'Login berhasil!', token, user: { id: user.id, nama: user.nama, email: user.email } });
});

// GET /api/profil
app.get('/api/profil', (req, res) => {
  const data = cekToken(req, res);
  if (!data) return;
  res.json({ message: 'Selamat datang!', user: data });
});

// PUT /api/edit-profil - Edit nama & email
app.put('/api/edit-profil', async (req, res) => {
  const sesi = cekToken(req, res);
  if (!sesi) return;

  const { nama, email } = req.body;
  if (!nama || !email)
    return res.status(400).json({ error: 'Nama dan email wajib diisi!' });

  const index = db.data.users.findIndex(u => u.id === sesi.id);
  if (index === -1) return res.status(404).json({ error: 'Akun tidak ditemukan!' });

  const emailDipakai = db.data.users.find(u => u.email === email && u.id !== sesi.id);
  if (emailDipakai)
    return res.status(409).json({ error: 'Email sudah dipakai akun lain!' });

  db.data.users[index].nama  = nama;
  db.data.users[index].email = email;
  await db.write();

  const tokenBaru = jwt.sign(
    { id: sesi.id, nama, email },
    SECRET,
    { expiresIn: '1d' }
  );

  res.json({
    message: 'Profil berhasil diupdate!',
    token: tokenBaru,
    user: { id: sesi.id, nama, email }
  });
});

// PUT /api/ganti-password - Ganti password
app.put('/api/ganti-password', async (req, res) => {
  const sesi = cekToken(req, res);
  if (!sesi) return;

  const { passwordLama, passwordBaru } = req.body;
  if (!passwordLama || !passwordBaru)
    return res.status(400).json({ error: 'Semua kolom wajib diisi!' });
  if (passwordBaru.length < 6)
    return res.status(400).json({ error: 'Password baru minimal 6 karakter!' });

  const index = db.data.users.findIndex(u => u.id === sesi.id);
  if (index === -1) return res.status(404).json({ error: 'Akun tidak ditemukan!' });

  const cocok = await bcrypt.compare(passwordLama, db.data.users[index].password);
  if (!cocok)
    return res.status(401).json({ error: 'Password lama salah!' });

  db.data.users[index].password = await bcrypt.hash(passwordBaru, 10);
  await db.write();

  res.json({ message: 'Password berhasil diganti! Silakan login ulang.' });
});

app.listen(PORT, () => {
  console.log(`🚀 Server berjalan di http://localhost:${PORT}`);
});
