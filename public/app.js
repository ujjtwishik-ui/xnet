'use strict';

// ---------------------------------------------------------------------------
// Состояние
// ---------------------------------------------------------------------------
function loadStored(key) {
  try {
    return JSON.parse(localStorage.getItem(key));
  } catch {
    return null;
  }
}

let token = loadStored('xnet_token');
let currentUser = loadStored('xnet_user');
let isRegisterMode = false;
let nextCursor = null;

const $ = (id) => document.getElementById(id);

// Создание DOM без innerHTML: любой пользовательский текст попадает в textContent,
// поэтому внедрить через него HTML/скрипт невозможно (защита от XSS).
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else node.setAttribute(key, value);
  }
  node.append(...children);
  return node;
}

let toastTimer;
function toast(message, isError = true) {
  const t = $('toast');
  t.textContent = message;
  t.classList.toggle('error', isError);
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3500);
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------
async function api(path, { method = 'GET', body } = {}) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;

  let res;
  try {
    res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  } catch {
    throw new Error('Нет связи с сервером');
  }
  const data = await res.json().catch(() => ({}));

  // Токен протух или недействителен — выходим, чтобы пользователь вошёл заново
  if (res.status === 401 && token) {
    logout(false);
    openModal();
  }
  if (!res.ok) throw new Error(data.error || 'Ошибка сервера');
  return data;
}

// ---------------------------------------------------------------------------
// Авторизация
// ---------------------------------------------------------------------------
function updateNavbar() {
  const area = $('authArea');
  area.replaceChildren();

  if (token && currentUser) {
    area.append(
      el('span', { class: 'nav-user', text: currentUser.username }),
      el('button', { class: 'btn', id: 'logoutBtn', text: 'Выйти' })
    );
    $('logoutBtn').addEventListener('click', () => logout());
  } else {
    area.append(el('button', { class: 'btn btn-primary', id: 'loginBtn', text: 'Войти' }));
    $('loginBtn').addEventListener('click', openModal);
  }
  $('createPostBox').hidden = !(token && currentUser);
}

function openModal() {
  $('authModal').hidden = false;
  $('authError').textContent = '';
  $('authUsername').focus();
}
function closeModal() {
  $('authModal').hidden = true;
  $('authPassword').value = '';
}

function setAuthMode(register) {
  isRegisterMode = register;
  $('modalTitle').textContent = register ? 'Регистрация' : 'Вход в xnet';
  $('authSubmit').textContent = register ? 'Создать аккаунт' : 'Войти';
  $('authToggle').textContent = register ? 'Уже есть аккаунт? Войти' : 'Нет аккаунта? Регистрация';
  $('authPassword').autocomplete = register ? 'new-password' : 'current-password';
  $('authError').textContent = '';
}

async function submitAuth(event) {
  event.preventDefault();
  const submit = $('authSubmit');
  submit.disabled = true;
  try {
    const data = await api(isRegisterMode ? '/api/register' : '/api/login', {
      method: 'POST',
      body: { username: $('authUsername').value.trim(), password: $('authPassword').value },
    });
    token = data.token;
    currentUser = data.user;
    try {
      localStorage.setItem('xnet_token', JSON.stringify(token));
      localStorage.setItem('xnet_user', JSON.stringify(currentUser));
    } catch { /* приватный режим: просто не запоминаем вход */ }
    closeModal();
    updateNavbar();
    loadFeed();
  } catch (e) {
    $('authError').textContent = e.message;
  } finally {
    submit.disabled = false;
  }
}

function logout(reload = true) {
  token = null;
  currentUser = null;
  try {
    localStorage.removeItem('xnet_token');
    localStorage.removeItem('xnet_user');
  } catch { /* ignore */ }
  updateNavbar();
  if (reload) loadFeed();
}

// ---------------------------------------------------------------------------
// Рендер постов
// ---------------------------------------------------------------------------
function renderLikeButton(btn, liked, count) {
  btn.classList.toggle('liked', liked);
  btn.setAttribute('aria-pressed', String(liked));
  btn.textContent = `${liked ? '❤️' : '🤍'} ${count}`;
}

function renderPost(post) {
  const likeBtn = el('button', { class: 'action-btn', type: 'button' });
  renderLikeButton(likeBtn, post.liked_by_me, post.likes_count);

  const commentsBtn = el('button', { class: 'action-btn', type: 'button' });
  const setCommentsCount = (n) => {
    commentsBtn.textContent = `💬 ${n}`;
    commentsBtn.dataset.count = n;
  };
  setCommentsCount(post.comments_count);

  const header = el(
    'div',
    { class: 'post-header' },
    el('span', { class: 'post-author', text: `@${post.username}` }),
    el('time', { datetime: post.created_at, text: new Date(post.created_at).toLocaleString('ru-RU') })
  );

  const article = el('article', { class: 'post' }, header);

  if (post.image_url) {
    const img = el('img', { class: 'post-img', alt: '', loading: 'lazy', referrerpolicy: 'no-referrer' });
    img.addEventListener('error', () => img.remove());
    img.src = post.image_url;
    article.append(img);
  }

  article.append(
    el('div', { class: 'post-content', text: post.content }),
    el('div', { class: 'post-footer' }, likeBtn, commentsBtn)
  );

  // --- лайк ---
  likeBtn.addEventListener('click', async () => {
    if (!token) return toast('Войдите, чтобы ставить лайки');
    likeBtn.disabled = true;
    try {
      const data = await api(`/api/posts/${post.id}/like`, { method: 'POST' });
      renderLikeButton(likeBtn, data.liked, data.likes_count);
    } catch (e) {
      toast(e.message);
    } finally {
      likeBtn.disabled = false;
    }
  });

  // --- комментарии (секция создаётся лениво, при первом открытии) ---
  let section = null;
  commentsBtn.addEventListener('click', async () => {
    if (section) {
      section.node.hidden = !section.node.hidden;
      return;
    }
    section = buildCommentsSection(post.id, setCommentsCount, () => Number(commentsBtn.dataset.count));
    article.append(section.node);
    await section.load();
  });

  return article;
}

function buildCommentsSection(postId, setCount, getCount) {
  const list = el('div', { class: 'comments-list' });
  const node = el('div', { class: 'comments-section' }, list);

  const appendComment = (c) =>
    list.append(el('div', { class: 'comment' }, el('span', { class: 'comment-author', text: `@${c.username}` }), c.content));

  if (token) {
    const input = el('input', { type: 'text', maxlength: '1000', placeholder: 'Написать комментарий...', required: '' });
    const button = el('button', { class: 'btn btn-primary', type: 'submit', text: 'Отправить' });
    const form = el('form', { class: 'comment-form' }, input, button);

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const content = input.value.trim();
      if (!content) return;
      button.disabled = true;
      try {
        const comment = await api(`/api/posts/${postId}/comments`, { method: 'POST', body: { content } });
        list.querySelector('.comment-hint')?.remove();
        appendComment(comment);
        setCount(getCount() + 1);
        input.value = '';
      } catch (err) {
        toast(err.message);
      } finally {
        button.disabled = false;
      }
    });
    node.append(form);
  } else {
    node.append(el('p', { class: 'comment-hint', text: 'Войдите, чтобы оставить комментарий.' }));
  }

  return {
    node,
    async load() {
      try {
        const comments = await api(`/api/posts/${postId}/comments`);
        if (comments.length === 0) list.append(el('p', { class: 'comment-hint', text: 'Комментариев пока нет.' }));
        comments.forEach(appendComment);
      } catch {
        list.append(el('p', { class: 'comment-hint', text: 'Не удалось загрузить комментарии.' }));
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Лента
// ---------------------------------------------------------------------------
async function loadFeed({ append = false } = {}) {
  const feed = $('feed');
  const more = $('loadMore');
  more.disabled = true;

  try {
    const query = append && nextCursor ? `?before=${nextCursor}` : '';
    const { posts, hasMore } = await api(`/api/posts${query}`);

    if (!append) feed.replaceChildren();
    if (!append && posts.length === 0) {
      feed.append(el('p', { class: 'empty', text: 'Постов пока нет. Будьте первым!' }));
    }
    feed.append(...posts.map(renderPost));

    nextCursor = posts.length ? posts[posts.length - 1].id : null;
    more.hidden = !hasMore;
  } catch (e) {
    if (!append) feed.replaceChildren(el('p', { class: 'empty', text: 'Ошибка загрузки ленты' }));
    toast(e.message);
  } finally {
    more.disabled = false;
  }
}

async function submitPost(event) {
  event.preventDefault();
  const content = $('postContent').value.trim();
  const image_url = $('postImage').value.trim();
  if (!content) return toast('Напишите текст поста');

  const button = event.submitter;
  button.disabled = true;
  try {
    const post = await api('/api/posts', { method: 'POST', body: { content, image_url } });
    $('postContent').value = '';
    $('postImage').value = '';
    $('feed').querySelector('.empty')?.remove();
    $('feed').prepend(renderPost(post));
  } catch (e) {
    toast(e.message);
  } finally {
    button.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// Инициализация
// ---------------------------------------------------------------------------
document.addEventListener('DOMContentLoaded', () => {
  $('createPostBox').addEventListener('submit', submitPost);
  $('authForm').addEventListener('submit', submitAuth);
  $('authToggle').addEventListener('click', () => setAuthMode(!isRegisterMode));
  $('loadMore').addEventListener('click', () => loadFeed({ append: true }));
  $('authModal').addEventListener('click', (e) => { if (e.target === $('authModal')) closeModal(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

  updateNavbar();
  loadFeed();
});
