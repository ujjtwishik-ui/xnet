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
app.use(express.json({ limit: '50mb' })); // Увеличенный лимит для Base64 картинок
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static('public'));

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
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, bio, avatar',
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
      res.json({ token, user: { id: user.id, username: user.username, bio: user.bio, avatar: user.avatar } });
    } else {
      res.status(400).json({ error: 'Неверный пароль' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// --- РЕДАКТОР ПРОФИЛЯ ---
app.put('/api/profile', authenticateToken, async (req, res) => {
  const { username, bio, avatar } = req.body;
  try {
    if (username !== req.user.username) {
      const checkName = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
      if (checkName.rows.length > 0) return res.status(400).json({ error: 'Это имя уже занято' });
    }

    const result = await pool.query(
      'UPDATE users SET username = $1, bio = $2, avatar = $3 WHERE id = $4 RETURNING id, username, bio, avatar',
      [username, bio, avatar, req.user.id]
    );
    
    const updatedUser = result.rows[0];
    const newToken = jwt.sign({ id: updatedUser.id, username: updatedUser.username }, process.env.JWT_SECRET);
    res.json({ user: updatedUser, token: newToken });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка при обновлении профиля' });
  }
});

// --- ПОСТЫ ---
app.get('/api/posts', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT p.*, u.username, u.avatar, 
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

// УДАЛЕНИЕ ПОСТА (Админ или Владелец)
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const isAdmin = req.user.username.toLowerCase() === 'colorsoft';
    
    let query = 'DELETE FROM posts WHERE id = $1 RETURNING *';
    let params = [req.params.id];

    // Если не админ, то удаляем только если это его пост
    if (!isAdmin) {
      query = 'DELETE FROM posts WHERE id = $1 AND user_id = $2 RETURNING *';
      params = [req.params.id, req.user.id];
    }

    const result = await pool.query(query, params);
    if (result.rowCount === 0) return res.status(403).json({ error: 'Нет прав или пост не найден' });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- ЛАЙКИ И КОММЕНТАРИИ ---
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
  const postId = req.params.id;
  try {
    await pool.query('INSERT INTO likes (user_id, post_id) VALUES ($1, $2)', [req.user.id, postId]);
    res.json({ success: true, action: 'liked' });
  } catch (err) {
    await pool.query('DELETE FROM likes WHERE user_id = $1 AND post_id = $2', [req.user.id, postId]);
    res.json({ success: true, action: 'unliked' });
  }
});

app.get('/api/posts/:id/comments', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT c.*, u.username FROM comments c JOIN users u ON c.user_id = u.id 
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Сервер xnet успешно запущен на порту ${PORT}`);
});
