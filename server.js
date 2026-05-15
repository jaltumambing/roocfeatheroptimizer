const express = require('express');
const path = require('path');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const fetch = require('node-fetch');

const app = express();
app.set('trust proxy', 1);
app.use(express.json());

// ── Database ──────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS session (
      sid VARCHAR NOT NULL COLLATE "default",
      sess JSON NOT NULL,
      expire TIMESTAMP(6) NOT NULL,
      CONSTRAINT session_pkey PRIMARY KEY (sid)
    );
    CREATE INDEX IF NOT EXISTS IDX_session_expire ON session(expire);

    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      discord_id VARCHAR(32) UNIQUE NOT NULL,
      username VARCHAR(100) NOT NULL,
      discriminator VARCHAR(10),
      avatar VARCHAR(200),
      ign VARCHAR(100),
      my_build JSONB,
      unslotted JSONB,
      char_profile JSONB,
      inv_grid JSONB,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS my_build JSONB;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS unslotted JSONB;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS char_profile JSONB;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS inv_grid JSONB;

    CREATE TABLE IF NOT EXISTS builds (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      name VARCHAR(100),
      ign VARCHAR(100),
      class VARCHAR(50) NOT NULL,
      types TEXT[] NOT NULL DEFAULT '{}',
      notes TEXT,
      statues JSONB NOT NULL,
      pool_inventory JSONB NOT NULL DEFAULT '{}',
      is_public BOOLEAN DEFAULT FALSE,
      thumbs_up INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS build_likes (
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      build_id INTEGER REFERENCES builds(id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (user_id, build_id)
    );

    CREATE TABLE IF NOT EXISTS build_comments (
      id SERIAL PRIMARY KEY,
      build_id INTEGER REFERENCES builds(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('DB initialized');
}

// ── Session ───────────────────────────────────────────────────────────────────
app.use(session({
  store: new PgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  },
}));

// ── Auth middleware ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  next();
}

// ── Discord OAuth ─────────────────────────────────────────────────────────────
const DISCORD_CLIENT_ID     = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI  = process.env.DISCORD_REDIRECT_URI;
const DISCORD_API           = 'https://discord.com/api/v10';

app.get('/auth/discord', (req, res) => {
  const params = new URLSearchParams({
    client_id:     DISCORD_CLIENT_ID,
    redirect_uri:  DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope:         'identify',
  });
  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

app.get('/auth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect('/?auth=cancelled');
  try {
    const tokenRes = await fetch(`${DISCORD_API}/oauth2/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type:    'authorization_code',
        code,
        redirect_uri:  DISCORD_REDIRECT_URI,
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return res.redirect('/?auth=error');

    const userRes = await fetch(`${DISCORD_API}/users/@me`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const discordUser = await userRes.json();
    if (!discordUser.id) return res.redirect('/?auth=error');

    const { rows } = await pool.query(`
      INSERT INTO users (discord_id, username, discriminator, avatar)
      VALUES ($1, $2, $3, $4)
      ON CONFLICT (discord_id) DO UPDATE SET
        username = EXCLUDED.username,
        discriminator = EXCLUDED.discriminator,
        avatar = EXCLUDED.avatar,
        updated_at = NOW()
      RETURNING *
    `, [discordUser.id, discordUser.username, discordUser.discriminator || '0', discordUser.avatar]);

    req.session.user = {
      id: rows[0].id, discord_id: rows[0].discord_id,
      username: rows[0].username, discriminator: rows[0].discriminator,
      avatar: rows[0].avatar, ign: rows[0].ign,
    };
    res.redirect('/?auth=success');
  } catch (err) {
    console.error('OAuth error:', err);
    res.redirect('/?auth=error');
  }
});

app.get('/auth/me', (req, res) => {
  if (req.session.user) res.json({ loggedIn: true, user: req.session.user });
  else res.json({ loggedIn: false });
});

app.post('/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

// Update IGN
app.post('/auth/ign', requireAuth, async (req, res) => {
  const { ign } = req.body;
  await pool.query('UPDATE users SET ign=$1 WHERE id=$2', [ign||null, req.session.user.id]);
  req.session.user.ign = ign || null;
  res.json({ ok: true });
});

// ── Profile Data (cloud sync) ─────────────────────────────────────────────────

// Get saved profile data (my_build, unslotted, char_profile, inv_grid)
app.get('/api/profile/data', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT my_build, unslotted, char_profile, inv_grid FROM users WHERE id=$1',
      [req.session.user.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({
      my_build:     rows[0].my_build     || null,
      unslotted:    rows[0].unslotted    || null,
      char_profile: rows[0].char_profile || null,
      inv_grid:     rows[0].inv_grid     || null,
    });
  } catch (err) {
    console.error('profile/data GET error:', err);
    res.status(500).json({ error: 'Failed to load profile data' });
  }
});

// Save profile data (my_build, unslotted, char_profile, inv_grid) — partial updates OK
app.post('/api/profile/data', requireAuth, async (req, res) => {
  try {
    const { my_build, unslotted, char_profile, inv_grid } = req.body;
    await pool.query(`
      UPDATE users SET
        my_build     = COALESCE($1::jsonb, my_build),
        unslotted    = COALESCE($2::jsonb, unslotted),
        char_profile = COALESCE($3::jsonb, char_profile),
        inv_grid     = COALESCE($4::jsonb, inv_grid),
        updated_at   = NOW()
      WHERE id=$5
    `, [
      my_build     != null ? JSON.stringify(my_build)     : null,
      unslotted    != null ? JSON.stringify(unslotted)    : null,
      char_profile != null ? JSON.stringify(char_profile) : null,
      inv_grid     != null ? JSON.stringify(inv_grid)     : null,
      req.session.user.id,
    ]);
    res.json({ ok: true });
  } catch (err) {
    console.error('profile/data POST error:', err);
    res.status(500).json({ error: 'Failed to save profile data' });
  }
});

// ── Builds API ────────────────────────────────────────────────────────────────

// Save a build
app.post('/api/builds', requireAuth, async (req, res) => {
  try {
    const { name, ign, class: cls, types, notes, statues, pool_inventory } = req.body;
    if (!cls || !types?.length || !statues) return res.status(400).json({ error: 'Missing required fields' });
    const { rows } = await pool.query(`
      INSERT INTO builds (user_id, name, ign, class, types, notes, statues, pool_inventory)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *
    `, [req.session.user.id, name||null, ign||null, cls, types, notes||null,
        JSON.stringify(statues), JSON.stringify(pool_inventory||{})]);
    res.json({ ok: true, build: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to save build' });
  }
});

// Get my builds
app.get('/api/builds/mine', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT b.*, u.username, u.avatar, u.discord_id,
        (SELECT COUNT(*) FROM build_likes WHERE build_id=b.id) AS like_count,
        (SELECT COUNT(*) FROM build_comments WHERE build_id=b.id) AS comment_count
      FROM builds b JOIN users u ON b.user_id=u.id
      WHERE b.user_id=$1 ORDER BY b.updated_at DESC
    `, [req.session.user.id]);
    res.json({ builds: rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch builds' });
  }
});

// Update a build (name, notes, make public/private)
app.patch('/api/builds/:id', requireAuth, async (req, res) => {
  try {
    const { name, notes, is_public, ign, class: cls, types } = req.body;
    const { rows } = await pool.query(`
      UPDATE builds SET
        name=COALESCE($1,name), notes=COALESCE($2,notes),
        is_public=CASE WHEN $3::boolean IS NOT NULL THEN $3::boolean ELSE is_public END,
        ign=COALESCE($4,ign),
        class=COALESCE($5,class), types=COALESCE($6,types),
        updated_at=NOW()
      WHERE id=$7 AND user_id=$8 RETURNING *
    `, [name, notes, is_public != null ? is_public : null, ign, cls, types, req.params.id, req.session.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'Build not found' });
    res.json({ ok: true, build: rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update build' });
  }
});

// Delete a build
app.delete('/api/builds/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM builds WHERE id=$1 AND user_id=$2', [req.params.id, req.session.user.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete build' });
  }
});

// Get community builds (public only)
app.get('/api/builds/community', async (req, res) => {
  try {
    const { class: cls, type, offset=0, limit=20 } = req.query;
    // Sanitise sort — only accept known values to prevent injection
    const sort = req.query.sort === 'recent' ? 'recent' : 'likes';
    const orderBy = sort === 'recent'
      ? 'b.created_at DESC'
      : '(SELECT COUNT(*) FROM build_likes WHERE build_id=b.id) DESC, b.created_at DESC';

    let where = ['b.is_public=true'];
    const params = [];
    if (cls) { params.push(cls); where.push(`b.class=$${params.length}`); }
    if (type) { params.push(type); where.push(`$${params.length}=ANY(b.types)`); }
    const limitIdx  = params.push(parseInt(limit));
    const offsetIdx = params.push(parseInt(offset));

    const { rows } = await pool.query(`
      SELECT b.*, u.username, u.avatar, u.discord_id,
        (SELECT COUNT(*) FROM build_likes WHERE build_id=b.id)::int AS like_count,
        (SELECT COUNT(*) FROM build_comments WHERE build_id=b.id)::int AS comment_count
      FROM builds b JOIN users u ON b.user_id=u.id
      WHERE ${where.join(' AND ')}
      ORDER BY ${orderBy}
      LIMIT $${limitIdx} OFFSET $${offsetIdx}
    `, params);
    res.json({ builds: rows });
  } catch (err) {
    console.error('community builds error:', err);
    res.status(500).json({ error: 'Failed to fetch community builds', detail: err.message });
  }
});

// Toggle like
app.post('/api/builds/:id/like', requireAuth, async (req, res) => {
  try {
    const existing = await pool.query('SELECT 1 FROM build_likes WHERE user_id=$1 AND build_id=$2',
      [req.session.user.id, req.params.id]);
    if (existing.rows.length) {
      await pool.query('DELETE FROM build_likes WHERE user_id=$1 AND build_id=$2',
        [req.session.user.id, req.params.id]);
      res.json({ liked: false });
    } else {
      await pool.query('INSERT INTO build_likes (user_id,build_id) VALUES ($1,$2)',
        [req.session.user.id, req.params.id]);
      res.json({ liked: true });
    }
  } catch (err) {
    res.status(500).json({ error: 'Failed to toggle like' });
  }
});

// Get comments for a build
app.get('/api/builds/:id/comments', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT c.*, u.username, u.avatar, u.discord_id, u.ign
      FROM build_comments c JOIN users u ON c.user_id=u.id
      WHERE c.build_id=$1 ORDER BY c.created_at ASC
    `, [req.params.id]);
    res.json({ comments: rows });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

// Post a comment
app.post('/api/builds/:id/comments', requireAuth, async (req, res) => {
  try {
    const { content } = req.body;
    if (!content?.trim()) return res.status(400).json({ error: 'Empty comment' });
    const { rows } = await pool.query(`
      INSERT INTO build_comments (build_id,user_id,content) VALUES ($1,$2,$3)
      RETURNING *, (SELECT username FROM users WHERE id=$2) as username,
                  (SELECT avatar FROM users WHERE id=$2) as avatar,
                  (SELECT discord_id FROM users WHERE id=$2) as discord_id
    `, [req.params.id, req.session.user.id, content.trim()]);
    res.json({ ok: true, comment: rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to post comment' });
  }
});

// ── Static files ──────────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', async () => {
  console.log(`ROOC Feather Optimizer running on port ${PORT}`);
  if (process.env.DATABASE_URL) await initDB();
  else console.warn('DATABASE_URL not set — skipping DB init');
});
