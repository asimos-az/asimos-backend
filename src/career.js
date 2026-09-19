import express from 'express';

const TABLE = 'career_articles';
const SUMMARY = 'id,slug,title,excerpt,category,cover_url,cover_style,reading_minutes,author,featured,status,published_at,updated_at';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const fail = (message) => { throw Object.assign(new Error(message), { status: 400 }); };

export function articleSlug(value) {
  return String(value || '').toLocaleLowerCase('az').replace(/[əğıöşçü]/g, c => ({ ə:'e', ğ:'g', ı:'i', ö:'o', ş:'s', ç:'c', ü:'u' }[c]))
    .normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 100).replace(/-$/, '');
}

export function validateArticle(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) fail('Məqalə məlumatları yanlışdır.');
  const text = (key, max, required = true) => {
    if (typeof input[key] !== 'string') { if (!required && input[key] == null) return ''; fail(`${key}: mətn daxil edin.`); }
    const value = input[key].trim();
    if ((required && !value) || value.length > max) fail(`${key}: 1–${max} simvol daxil edin.`);
    return value;
  };
  const title = text('title', 180);
  const slug = articleSlug(text('slug', 120, false) || title);
  if (!slug) fail('Keçid üçün latın hərfləri və ya rəqəmlər daxil edin.');
  const body = text('body', 50000);
  const cover_url = text('cover_url', 2048, false);
  if (cover_url) {
    try { const url = new URL(cover_url); if (url.protocol !== 'https:' || url.username || url.password) fail('Şəkil üçün HTTPS keçidi daxil edin.'); }
    catch { fail('Şəkil üçün HTTPS keçidi daxil edin.'); }
  }
  const status = input.status || 'draft';
  if (!['draft', 'published'].includes(status)) fail('Məqalə statusu yanlışdır.');
  const cover_style = input.cover_style || 'mint';
  if (!['mint', 'peach', 'blue', 'lilac'].includes(cover_style)) fail('Üz qabığı üslubu yanlışdır.');
  if (input.featured !== undefined && typeof input.featured !== 'boolean') fail('Seçilmiş məqalə dəyəri yanlışdır.');
  return { title, slug, body, excerpt: text('excerpt', 320), category: text('category', 60),
    author: text('author', 100, false) || 'Asimos redaksiyası', cover_url, cover_style, status,
    featured: input.featured === true, reading_minutes: Math.max(1, Math.ceil(body.split(/\s+/).length / 180)) };
}

export function createCareerRouter({ db, requireAdmin }) {
  const router = express.Router();
  router.use(['/career-articles', '/admin/career-articles'], (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  const handle = fn => async (req, res) => {
    try { await fn(req, res); }
    catch (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'Bu keçid artıq istifadə olunur. Başqa keçid seçin.' });
      if (error.status === 400) return res.status(400).json({ error: error.message });
      console.error('[career]', error.code || error.message);
      res.status(500).json({ error: 'Məqalələri emal etmək mümkün olmadı. Yenidən yoxlayın.' });
    }
  };
  const list = admin => handle(async (req, res) => {
    const page = Math.max(1, Math.min(10000, Math.trunc(Number(req.query.page)) || 1));
    const limit = Math.max(1, Math.min(50, Math.trunc(Number(req.query.limit)) || 12));
    let query = db.from(TABLE).select(SUMMARY, { count: 'exact' });
    if (!admin) query = query.eq('status', 'published');
    else if (['draft', 'published'].includes(req.query.status)) query = query.eq('status', req.query.status);
    if (req.query.category) query = query.eq('category', String(req.query.category).slice(0, 60));
    if (req.query.q) query = query.ilike('title', `%${String(req.query.q).slice(0, 100).replace(/[\\%_]/g, '\\$&')}%`);
    query = query.order('featured', { ascending: false }).order(admin ? 'updated_at' : 'published_at', { ascending: false }).order('id');
    const { data, count, error } = await query.range((page - 1) * limit, page * limit - 1);
    if (error) throw error;
    res.json({ items: data || [], total: count || 0, page, limit });
  });
  router.get('/career-articles', list(false));
  router.get('/career-articles/:slug', handle(async (req, res) => {
    const { data, error } = await db.from(TABLE).select('*').eq('slug', req.params.slug).eq('status', 'published').maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Məqalə tapılmadı.' });
    res.json(data);
  }));
  router.use('/admin/career-articles', requireAdmin);
  router.get('/admin/career-articles', list(true));
  router.get('/admin/career-articles/:id', handle(async (req, res) => {
    if (!UUID.test(req.params.id)) fail('Məqalə ID-si yanlışdır.');
    const { data, error } = await db.from(TABLE).select('*').eq('id', req.params.id).maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Məqalə tapılmadı.' });
    res.json(data);
  }));
  router.post('/admin/career-articles', handle(async (req, res) => {
    const article = validateArticle(req.body);
    const { data, error } = await db.from(TABLE).insert({ ...article, published_at: article.status === 'published' ? new Date().toISOString() : null }).select('*').single();
    if (error) throw error;
    res.status(201).json(data);
  }));
  router.put('/admin/career-articles/:id', handle(async (req, res) => {
    if (!UUID.test(req.params.id)) fail('Məqalə ID-si yanlışdır.');
    const article = validateArticle(req.body);
    const { data: current, error: lookupError } = await db.from(TABLE).select('published_at').eq('id', req.params.id).maybeSingle();
    if (lookupError) throw lookupError;
    if (!current) return res.status(404).json({ error: 'Məqalə tapılmadı.' });
    const { data, error } = await db.from(TABLE).update({ ...article, updated_at: new Date().toISOString(),
      published_at: current.published_at || (article.status === 'published' ? new Date().toISOString() : null) }).eq('id', req.params.id).select('*').maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Məqalə tapılmadı.' });
    res.json(data);
  }));
  router.delete('/admin/career-articles/:id', handle(async (req, res) => {
    if (!UUID.test(req.params.id)) fail('Məqalə ID-si yanlışdır.');
    const { data, error } = await db.from(TABLE).delete().eq('id', req.params.id).select('id').maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: 'Məqalə tapılmadı.' });
    res.status(204).end();
  }));
  return router;
}
