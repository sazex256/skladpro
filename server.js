const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const DB_PATH = path.join(__dirname, 'skladpro.db');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database(DB_PATH);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
  db.run(`CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT NOT NULL, category TEXT NOT NULL, quantity INTEGER DEFAULT 0, price REAL DEFAULT 0, cell TEXT, description TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))`);
  db.run(`CREATE TABLE IF NOT EXISTS activities (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, text TEXT NOT NULL, type TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id))`);
});

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Заполните все поля' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashed], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Email уже зарегистрирован' });
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      const token = jwt.sign({ id: this.lastID, name, email }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token, user: { id: this.lastID, name, email, created: new Date().toISOString() } });
      db.run('INSERT INTO activities (user_id, text, type) VALUES (?, ?, ?)', [this.lastID, 'Регистрация нового пользователя', 'add']);
    });
  } catch (e) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Неверный email или пароль' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Неверный email или пароль' });
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, created: user.created_at } });
  });
});

const authenticate = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Не авторизован' });
  try {
    const decoded = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    req.user = decoded;
    next();
  } catch { res.status(401).json({ error: 'Неверный токен' }); }
};

app.get('/api/products', authenticate, (req, res) => {
  db.all('SELECT * FROM products ORDER BY id DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Ошибка' });
    res.json(rows);
  });
});

app.post('/api/products', authenticate, (req, res) => {
  const { name, category, quantity, price, cell, description } = req.body;
  db.run('INSERT INTO products (user_id, name, category, quantity, price, cell, description) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [req.user.id, name, category, quantity || 0, price || 0, cell, description], function(err) {
      if (err) return res.status(500).json({ error: 'Ошибка' });
      const newProduct = { id: this.lastID, user_id: req.user.id, name, category, quantity: quantity || 0, price: price || 0, cell, description, created_at: new Date().toISOString() };
      res.json(newProduct);
      db.run('INSERT INTO activities (user_id, text, type) VALUES (?, ?, ?)', [req.user.id, `Добавлен товар: <strong>${name}</strong>`, 'add']);
    });
});

app.put('/api/products/:id', authenticate, (req, res) => {
  const { name, category, quantity, price, cell, description } = req.body;
  db.run('UPDATE products SET name=?, category=?, quantity=?, price=?, cell=?, description=? WHERE id=?',
    [name, category, quantity, price, cell, description, req.params.id], function(err) {
      if (err) return res.status(500).json({ error: 'Ошибка' });
      if (this.changes === 0) return res.status(404).json({ error: 'Не найдено' });
      res.json({ success: true });
      db.run('INSERT INTO activities (user_id, text, type) VALUES (?, ?, ?)', [req.user.id, `Обновлён товар: <strong>${name}</strong>`, 'edit']);
    });
});

app.delete('/api/products/:id', authenticate, (req, res) => {
  db.get('SELECT name FROM products WHERE id = ?', [req.params.id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Не найдено' });
    db.run('DELETE FROM products WHERE id = ?', [req.params.id], (err) => {
      if (err) return res.status(500).json({ error: 'Ошибка' });
      res.json({ success: true });
      db.run('INSERT INTO activities (user_id, text, type) VALUES (?, ?, ?)', [req.user.id, `Удалён товар: <strong>${row.name}</strong>`, 'delete']);
    });
  });
});

app.get('/api/activities', authenticate, (req, res) => {
  db.all('SELECT * FROM activities WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Ошибка' });
    res.json(rows.map(r => ({ ...r, time: r.created_at })));
  });
});

app.put('/api/profile', authenticate, (req, res) => {
  const { name, password } = req.body;
  if (!name) return res.status(400).json({ error: 'Имя обязательно' });
  if (password) {
    bcrypt.hash(password, 10).then(hashed => {
      db.run('UPDATE users SET name = ?, password = ? WHERE id = ?', [name, hashed, req.user.id], (err) => {
        if (err) return res.status(500).json({ error: 'Ошибка' });
        res.json({ success: true });
      });
    });
  } else {
    db.run('UPDATE users SET name = ? WHERE id = ?', [name, req.user.id], (err) => {
      if (err) return res.status(500).json({ error: 'Ошибка' });
      res.json({ success: true });
    });
  }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));