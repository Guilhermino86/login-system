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

const adapter = new JSONFile(path.join('/tmp', 'db.json'));
const defaultData = { users: [], produk: [], transaksi: [] };
const db = new Low(adapter, defaultData);
await db.read();
if (!db.data.produk)    db.data.produk = [];
if (!db.data.transaksi) db.data.transaksi = [];
await db.write();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

console.log('✅ Database siap!');

// =============================================
//   HELPER
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
//   AUTH ROUTES
// =============================================

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

app.get('/api/profil', (req, res) => {
  const data = cekToken(req, res);
  if (!data) return;
  res.json({ message: 'Selamat datang!', user: data });
});

app.put('/api/edit-profil', async (req, res) => {
  const sesi = cekToken(req, res);
  if (!sesi) return;
  const { nama, email } = req.body;
  if (!nama || !email) return res.status(400).json({ error: 'Nama dan email wajib diisi!' });
  const index = db.data.users.findIndex(u => u.id === sesi.id);
  if (index === -1) return res.status(404).json({ error: 'Akun tidak ditemukan!' });
  const emailDipakai = db.data.users.find(u => u.email === email && u.id !== sesi.id);
  if (emailDipakai) return res.status(409).json({ error: 'Email sudah dipakai akun lain!' });
  db.data.users[index].nama  = nama;
  db.data.users[index].email = email;
  await db.write();
  const tokenBaru = jwt.sign({ id: sesi.id, nama, email }, SECRET, { expiresIn: '1d' });
  res.json({ message: 'Profil berhasil diupdate!', token: tokenBaru, user: { id: sesi.id, nama, email } });
});

app.put('/api/ganti-password', async (req, res) => {
  const sesi = cekToken(req, res);
  if (!sesi) return;
  const { passwordLama, passwordBaru } = req.body;
  if (!passwordLama || !passwordBaru) return res.status(400).json({ error: 'Semua kolom wajib diisi!' });
  if (passwordBaru.length < 6) return res.status(400).json({ error: 'Password baru minimal 6 karakter!' });
  const index = db.data.users.findIndex(u => u.id === sesi.id);
  if (index === -1) return res.status(404).json({ error: 'Akun tidak ditemukan!' });
  const cocok = await bcrypt.compare(passwordLama, db.data.users[index].password);
  if (!cocok) return res.status(401).json({ error: 'Password lama salah!' });
  db.data.users[index].password = await bcrypt.hash(passwordBaru, 10);
  await db.write();
  res.json({ message: 'Password berhasil diganti! Silakan login ulang.' });
});

// =============================================
//   PRODUK ROUTES
// =============================================

app.get('/api/produk', (req, res) => {
  const sesi = cekToken(req, res);
  if (!sesi) return;
  res.json(db.data.produk);
});

app.post('/api/produk', async (req, res) => {
  const sesi = cekToken(req, res);
  if (!sesi) return;
  const { nama, emoji, kategori, harga, stok } = req.body;
  if (!nama || harga === undefined || stok === undefined)
    return res.status(400).json({ error: 'Nama, harga, dan stok wajib diisi!' });
  const produk = { id: Date.now(), nama, emoji: emoji || '📦', kategori: kategori || '', harga: parseInt(harga), stok: parseInt(stok), createdAt: new Date().toISOString() };
  db.data.produk.push(produk);
  await db.write();
  res.status(201).json(produk);
});

app.put('/api/produk/:id', async (req, res) => {
  const sesi = cekToken(req, res);
  if (!sesi) return;
  const id = parseInt(req.params.id);
  const index = db.data.produk.findIndex(p => p.id === id);
  if (index === -1) return res.status(404).json({ error: 'Produk tidak ditemukan!' });
  const { nama, emoji, kategori, harga, stok } = req.body;
  db.data.produk[index] = { ...db.data.produk[index], nama, emoji, kategori, harga: parseInt(harga), stok: parseInt(stok) };
  await db.write();
  res.json(db.data.produk[index]);
});

app.delete('/api/produk/:id', async (req, res) => {
  const sesi = cekToken(req, res);
  if (!sesi) return;
  const id = parseInt(req.params.id);
  db.data.produk = db.data.produk.filter(p => p.id !== id);
  await db.write();
  res.json({ message: 'Produk dihapus!' });
});

// =============================================
//   TRANSAKSI ROUTES
// =============================================

app.post('/api/transaksi', async (req, res) => {
  const sesi = cekToken(req, res);
  if (!sesi) return;
  const { noTransaksi, items, subtotal, diskon, total, bayar, kembalian, kasir } = req.body;
  if (!items || !items.length) return res.status(400).json({ error: 'Items tidak boleh kosong!' });

  // Kurangi stok
  for (const item of items) {
    const idx = db.data.produk.findIndex(p => p.id === item.id);
    if (idx === -1) return res.status(404).json({ error: `Produk ${item.nama} tidak ditemukan!` });
    if (db.data.produk[idx].stok < item.qty) return res.status(400).json({ error: `Stok ${item.nama} tidak cukup!` });
    db.data.produk[idx].stok -= item.qty;
  }

  const trx = { id: Date.now(), noTransaksi, items, subtotal, diskon, total, bayar, kembalian, kasir, waktu: new Date().toISOString() };
  db.data.transaksi.push(trx);
  await db.write();
  res.status(201).json({ message: 'Transaksi berhasil!', transaksi: trx });
});

app.get('/api/transaksi', (req, res) => {
  const sesi = cekToken(req, res);
  if (!sesi) return;
  res.json(db.data.transaksi);
});

// =============================================
//   LAPORAN ROUTE
// =============================================

app.get('/api/laporan', (req, res) => {
  const sesi = cekToken(req, res);
  if (!sesi) return;

  const periode = req.query.periode || 'bulan';
  const now = new Date();
  let cutoff = new Date(0);

  if (periode === 'hari')   cutoff = new Date(now.toDateString());
  if (periode === 'minggu') cutoff = new Date(now - 7 * 86400000);
  if (periode === 'bulan')  cutoff = new Date(now - 30 * 86400000);

  const trxFiltered = db.data.transaksi.filter(t => new Date(t.waktu) >= cutoff);

  const totalPendapatan = trxFiltered.reduce((s, t) => s + t.total, 0);
  const jumlahTrx       = trxFiltered.length;
  const totalItem       = trxFiltered.reduce((s, t) => s + t.items.reduce((a, i) => a + i.qty, 0), 0);
  const rataRata        = jumlahTrx > 0 ? Math.round(totalPendapatan / jumlahTrx) : 0;

  // Harian
  const harianMap = {};
  trxFiltered.forEach(t => {
    const tgl = t.waktu.slice(0, 10);
    harianMap[tgl] = (harianMap[tgl] || 0) + t.total;
  });
  const harian = Object.entries(harianMap).sort().map(([tanggal, total]) => ({ tanggal, total }));

  // Terlaris
  const produkMap = {};
  trxFiltered.forEach(t => {
    t.items.forEach(i => {
      if (!produkMap[i.nama]) produkMap[i.nama] = { nama: i.nama, qty: 0, total: 0 };
      produkMap[i.nama].qty   += i.qty;
      produkMap[i.nama].total += i.harga * i.qty;
    });
  });
  const terlaris = Object.values(produkMap).sort((a, b) => b.qty - a.qty);

  res.json({ totalPendapatan, jumlahTrx, totalItem, rataRata, harian, terlaris });
});

app.listen(PORT, () => {
  console.log(`🚀 Server berjalan di http://localhost:${PORT}`);
});
