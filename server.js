const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// --- Middleware для проверки токена ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- АВТОРИЗАЦИЯ ---
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
      [username, hash]
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET);
    res.json({ token, user });
  } catch (err) {
    res.status(400).json({ error: 'Имя пользователя уже занято' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(400).json({ error: 'Пользователь не найден' });
    
    const user = result.rows[0];
    if (await bcrypt.compare(password, user.password_hash)) {
      const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET);
      res.json({ token, user: { id: user.id, username: user.username } });
    } else {
      res.status(400).json({ error: 'Неверный пароль' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// --- ПОСТЫ ---
app.get('/api/posts', async (req, res) => {
  try {
    // Сложный запрос: достаем посты, авторов, кол-во лайков и комментов
    const result = await pool.query(`
      SELECT p.*, u.username, 
        (SELECT COUNT(*) FROM likes WHERE post_id = p.id) as likes_count,
        (SELECT COUNT(*) FROM comments WHERE post_id = p.id) as comments_count
      FROM posts p
      JOIN users u ON p.user_id = u.id
      ORDER BY p.created_at DESC
    `);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/posts', authenticateToken, async (req, res) => {
  const { content, image_url } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO posts (user_id, content, image_url) VALUES ($1, $2, $3) RETURNING *',
      [req.user.id, content, image_url]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- ЛАЙКИ И КОММЕНТАРИИ ---
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
  const postId = req.params.id;
  try {
    // Пытаемся поставить лайк (если уже есть - выдаст ошибку unique constraint)
    await pool.query('INSERT INTO likes (user_id, post_id) VALUES ($1, $2)', [req.user.id, postId]);
    res.json({ success: true });
  } catch (err) {
    // Если ошибка уникальности - удаляем лайк (дизлайк)
    await pool.query('DELETE FROM likes WHERE user_id = $1 AND post_id = $2', [req.user.id, postId]);
    res.json({ success: true, action: 'unliked' });
  }
});

app.get('/api/posts/:id/comments', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*, u.username 
      FROM comments c JOIN users u ON c.user_id = u.id 
      WHERE c.post_id = $1 ORDER BY c.created_at ASC
    `, [req.params.id]);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'INSERT INTO comments (post_id, user_id, content) VALUES ($1, $2, $3) RETURNING *',
      [req.params.id, req.user.id, req.body.content]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('xnet Server Started'));