require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// ---------------------------------------------------------------------------
// Конфигурация1
// ---------------------------------------------------------------------------
const isProd = process.env.NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;
const BCRYPT_ROUNDS = 12;
const TOKEN_TTL = '7d';
const PAGE_SIZE = 20;

const { DATABASE_URL, JWT_SECRET } = process.env;
if (!DATABASE_URL) throw new Error('DATABASE_URL не задан (см. .env.example)');
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET должен быть задан и быть не короче 32 символов (см. .env.example)');
}

// DATABASE_SSL: off | relaxed | strict
//   strict  — проверять сертификат сервера (рекомендуется, если провайдер БД это поддерживает)
//   relaxed — шифровать, но не проверять сертификат (как было раньше)
const sslMode = process.env.DATABASE_SSL || (isProd ? 'relaxed' : 'off');
const ssl = sslMode === 'off' ? false : { rejectUnauthorized: sslMode === 'strict' };

const pool = new Pool({ connectionString: DATABASE_URL, ssl });
pool.on('error', (err) => console.error('Ошибка соединения с БД:', err.message));

const app = express();
app.disable('x-powered-by');
// За прокси (Render, Heroku, nginx) нужно, чтобы rate-limit видел реальный IP клиента.
if (process.env.TRUST_PROXY) app.set('trust proxy', Number(process.env.TRUST_PROXY) || process.env.TRUST_PROXY);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        // Картинки в постах — по ссылке с любого https-хоста
        imgSrc: ["'self'", 'https:', 'data:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
  })
);
app.use(express.json({ limit: '10kb' }));
app.use(express.static('public'));

// ---------------------------------------------------------------------------
// Утилиты
// ---------------------------------------------------------------------------
const apiLimiter = rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({
  windowMs: 15 * 60_000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Слишком много попыток, попробуйте позже' },
});
const writeLimiter = rateLimit({
  windowMs: 60_000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Слишком часто, подождите минуту' },
});

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const signToken = (user) =>
  jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { algorithm: 'HS256', expiresIn: TOKEN_TTL });

function readToken(req) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) return null;
  try {
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    return null;
  }
}

// Обязательная авторизация
function requireAuth(req, res, next) {
  const user = readToken(req);
  if (!user) return next(new HttpError(401, 'Требуется вход'));
  req.user = user;
  next();
}

// Необязательная: нужна ленте, чтобы показать «лайкнул ли я»
function optionalAuth(req, res, next) {
  req.user = readToken(req);
  next();
}

function parseId(value) {
  if (!/^\d{1,18}$/.test(String(value))) throw new HttpError(400, 'Некорректный id');
  return value;
}

function cleanText(value, field, max) {
  if (typeof value !== 'string') throw new HttpError(400, `Поле «${field}» обязательно`);
  const text = value.trim();
  if (!text) throw new HttpError(400, `Поле «${field}» не может быть пустым`);
  if (text.length > max) throw new HttpError(400, `Поле «${field}»: максимум ${max} символов`);
  return text;
}

function cleanImageUrl(value) {
  if (value == null || value === '') return null;
  if (typeof value !== 'string' || value.length > 2048) throw new HttpError(400, 'Некорректная ссылка на картинку');
  let url;
  try {
    url = new URL(value.trim());
  } catch {
    throw new HttpError(400, 'Некорректная ссылка на картинку');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new HttpError(400, 'Ссылка на картинку должна начинаться с http:// или https://');
  }
  return url.toString();
}

function validateCredentials({ username, password }) {
  if (typeof username !== 'string' || !/^[A-Za-z0-9_]{3,20}$/.test(username)) {
    throw new HttpError(400, 'Логин: 3–20 символов, только латиница, цифры и _');
  }
  // bcrypt обрезает всё после 72 байт, поэтому длинные пароли ограничиваем явно
  if (typeof password !== 'string' || password.length < 8 || Buffer.byteLength(password) > 72) {
    throw new HttpError(400, 'Пароль: от 8 символов (не больше 72 байт)');
  }
}

// ---------------------------------------------------------------------------
// Авторизация
// ---------------------------------------------------------------------------
app.use('/api', apiLimiter);

app.post('/api/register', authLimiter, async (req, res) => {
  validateCredentials(req.body || {});
  const { username, password } = req.body;

  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  try {
    const { rows } = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username',
      [username, hash]
    );
    res.status(201).json({ token: signToken(rows[0]), user: rows[0] });
  } catch (err) {
    if (err.code === '23505') throw new HttpError(409, 'Имя пользователя уже занято');
    throw err;
  }
});

// Хеш-пустышка: чтобы время ответа не выдавало, существует ли такой логин
const DUMMY_HASH = bcrypt.hashSync('dummy-password', BCRYPT_ROUNDS);

app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    throw new HttpError(400, 'Введите логин и пароль');
  }

  const { rows } = await pool.query(
    'SELECT id, username, password_hash FROM users WHERE lower(username) = lower($1)',
    [username]
  );
  const user = rows[0];
  const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok) throw new HttpError(401, 'Неверный логин или пароль');

  const publicUser = { id: user.id, username: user.username };
  res.json({ token: signToken(publicUser), user: publicUser });
});

// ---------------------------------------------------------------------------
// Посты
// ---------------------------------------------------------------------------
// Курсорная пагинация: GET /api/posts?before=<id последнего поста на странице>
app.get('/api/posts', optionalAuth, async (req, res) => {
  const before = req.query.before ? parseId(req.query.before) : null;
  const userId = req.user ? req.user.id : null;

  const { rows } = await pool.query(
    `SELECT p.id, p.content, p.image_url, p.created_at, u.username,
            (SELECT COUNT(*)::int FROM likes    WHERE post_id = p.id) AS likes_count,
            (SELECT COUNT(*)::int FROM comments WHERE post_id = p.id) AS comments_count,
            EXISTS (SELECT 1 FROM likes WHERE post_id = p.id AND user_id = $2) AS liked_by_me
       FROM posts p
       JOIN users u ON u.id = p.user_id
      WHERE ($1::bigint IS NULL OR p.id < $1::bigint)
      ORDER BY p.id DESC
      LIMIT $3`,
    [before, userId, PAGE_SIZE + 1]
  );

  const hasMore = rows.length > PAGE_SIZE;
  res.json({ posts: rows.slice(0, PAGE_SIZE), hasMore });
});

app.post('/api/posts', requireAuth, writeLimiter, async (req, res) => {
  const content = cleanText(req.body?.content, 'Текст', 2000);
  const imageUrl = cleanImageUrl(req.body?.image_url);

  try {
    const { rows } = await pool.query(
      `INSERT INTO posts (user_id, content, image_url) VALUES ($1, $2, $3)
       RETURNING id, content, image_url, created_at`,
      [req.user.id, content, imageUrl]
    );
    res.status(201).json({ ...rows[0], username: req.user.username, likes_count: 0, comments_count: 0, liked_by_me: false });
  } catch (err) {
    if (err.code === '23503') throw new HttpError(401, 'Пользователь не найден, войдите заново');
    throw err;
  }
});

// ---------------------------------------------------------------------------
// Лайки и комментарии
// ---------------------------------------------------------------------------
// Переключатель лайка. Возвращает актуальное состояние, чтобы клиент не гадал.
app.post('/api/posts/:id/like', requireAuth, writeLimiter, async (req, res) => {
  const postId = parseId(req.params.id);

  try {
    const removed = await pool.query('DELETE FROM likes WHERE user_id = $1 AND post_id = $2', [req.user.id, postId]);
    let liked = false;
    if (removed.rowCount === 0) {
      await pool.query(
        'INSERT INTO likes (user_id, post_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [req.user.id, postId]
      );
      liked = true;
    }
    const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM likes WHERE post_id = $1', [postId]);
    res.json({ liked, likes_count: rows[0].n });
  } catch (err) {
    if (err.code === '23503') throw new HttpError(404, 'Пост не найден');
    throw err;
  }
});

app.get('/api/posts/:id/comments', async (req, res) => {
  const postId = parseId(req.params.id);
  const { rows } = await pool.query(
    `SELECT c.id, c.content, c.created_at, u.username
       FROM comments c JOIN users u ON u.id = c.user_id
      WHERE c.post_id = $1
      ORDER BY c.id ASC
      LIMIT 200`,
    [postId]
  );
  res.json(rows);
});

app.post('/api/posts/:id/comments', requireAuth, writeLimiter, async (req, res) => {
  const postId = parseId(req.params.id);
  const content = cleanText(req.body?.content, 'Комментарий', 1000);

  try {
    const { rows } = await pool.query(
      `INSERT INTO comments (post_id, user_id, content) VALUES ($1, $2, $3)
       RETURNING id, content, created_at`,
      [postId, req.user.id, content]
    );
    res.status(201).json({ ...rows[0], username: req.user.username });
  } catch (err) {
    if (err.code === '23503') throw new HttpError(404, 'Пост не найден');
    throw err;
  }
});

// ---------------------------------------------------------------------------
// Служебное
// ---------------------------------------------------------------------------
app.get('/healthz', async (req, res) => {
  await pool.query('SELECT 1');
  res.json({ ok: true });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Не найдено' }));

// Единый обработчик ошибок: внутренности (тексты SQL-ошибок и т.п.) наружу не отдаём
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Некорректный JSON' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Слишком большой запрос' });
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  console.error(err);
  res.status(500).json({ error: 'Ошибка сервера' });
});

const server = app.listen(PORT, () => console.log(`xnet запущен на порту ${PORT}`));

function shutdown() {
  server.close(() => pool.end().then(() => process.exit(0)));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
