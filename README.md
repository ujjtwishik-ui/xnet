# xnet

Мини-соцсеть: регистрация, посты с картинками, лайки, комментарии.
Стек: Node.js, Express, PostgreSQL, JWT.

## Запуск

```bash
npm install
cp .env.example .env        # заполните DATABASE_URL и JWT_SECRET
npm run db:init             # создаёт таблицы (нужен установленный psql)
npm start                   # http://localhost:3000
```

Сгенерировать JWT_SECRET:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

## API

| Метод | Путь | Авторизация | Описание |
|-------|------|-------------|----------|
| POST | `/api/register` | — | `{username, password}` → `{token, user}` |
| POST | `/api/login` | — | `{username, password}` → `{token, user}` |
| GET | `/api/posts?before=<id>` | опц. | 20 постов, `{posts, hasMore}` |
| POST | `/api/posts` | да | `{content, image_url?}` |
| POST | `/api/posts/:id/like` | да | переключает лайк → `{liked, likes_count}` |
| GET | `/api/posts/:id/comments` | — | список комментариев |
| POST | `/api/posts/:id/comments` | да | `{content}` |
| GET | `/healthz` | — | проверка живости |
