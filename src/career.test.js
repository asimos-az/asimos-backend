import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { createCareerRouter, validateArticle, articleSlug } from './career.js';
import { createMemoryDb } from '../tests/helpers/career-db.js';

const article = overrides => ({ title: 'Müsahibəyə necə hazırlaşmalı?', excerpt: 'Praktik məsləhətlər.', body: '## Hazırlıq\n\nŞirkəti araşdırın.', category: 'Müsahibə', ...overrides });

test('Azerbaijani slugs and automatically calculated reading time', () => {
  assert.equal(articleSlug('CV, iş və inkişaf: ƏĞIİÖŞÇÜ'), 'cv-is-ve-inkisaf-egiioscu');
  assert.equal(validateArticle(article()).slug, 'musahibeye-nece-hazirlasmali');
  assert.equal(validateArticle(article({ body: 'söz '.repeat(181) })).reading_minutes, 2);
  assert.equal(validateArticle(article({ is_admin: true, id: 'attacker', published_at: 'future' })).id, undefined);
});

test('reject invalid or unsafe content; drafts are the default', () => {
  assert.equal(validateArticle(article()).status, 'draft');
  for (const input of [article({ title: '' }), article({ body: '' }), article({ excerpt: 'x'.repeat(321) }), article({ cover_url: 'javascript:alert(1)' }), article({ cover_url: 'http://example.com/a.jpg' }), article({ cover_url: 'https://user:pass@example.com/a.jpg' }), article({ status: 'admin' }), article({ featured: 'false' }), article({ cover_style: 'evil' })]) {
    assert.throws(() => validateArticle(input), error => error.status === 400);
  }
});

test('article API: auth, drafts, publication, search, paging, edits, conflicts and deletion', async t => {
  const db = createMemoryDb();
  const app = express();
  app.use(express.json());
  app.use(createCareerRouter({ db, requireAdmin: (req, res, next) => req.headers.authorization === 'Bearer test-admin' ? next() : res.status(401).json({ error: 'Unauthorized' }) }));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = async (path, { admin = false, body, method = 'GET' } = {}) => {
    const res = await fetch(`${base}${path}`, { method, headers: { ...(admin ? { Authorization: 'Bearer test-admin' } : {}), 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    return { status: res.status, data: res.status === 204 ? null : await res.json(), cache: res.headers.get('cache-control') };
  };
  for (const method of ['GET', 'POST', 'PUT', 'DELETE']) {
    const result = await request(`/admin/career-articles${['PUT', 'DELETE'].includes(method) ? '/00000000-0000-0000-0000-000000000000' : ''}`, { method });
    assert.equal(result.status, 401);
  }
  const created = await request('/admin/career-articles', { admin: true, method: 'POST', body: article() });
  assert.equal(created.status, 201);
  assert.equal(created.data.published_at, null);
  const path = `/admin/career-articles/${created.data.id}`;
  assert.equal((await request(`/career-articles/${created.data.slug}`)).status, 404);
  assert.equal((await request('/career-articles')).data.total, 0);
  assert.equal((await request('/admin/career-articles', { admin: true })).data.total, 1);
  assert.equal((await request(path, { admin: true })).data.body, article().body);
  const published = await request(path, { admin: true, method: 'PUT', body: { ...created.data, status: 'published' } });
  assert.equal(published.status, 200);
  assert.ok(published.data.published_at);
  assert.equal((await request(`/career-articles/${created.data.slug}`)).status, 200);
  const publicList = await request('/career-articles');
  assert.equal(publicList.data.total, 1);
  assert.equal(publicList.data.items[0].body, undefined);
  assert.equal(publicList.cache, 'no-store');
  assert.equal((await request('/career-articles?q=olmayan')).data.total, 0);
  assert.equal((await request('/career-articles?q=M%C3%BCsahib%C9%99')).data.total, 1);
  assert.equal((await request('/career-articles?limit=5000')).data.limit, 50);
  assert.equal((await request('/career-articles?page=-2&limit=-3')).data.page, 1);
  assert.equal((await request('/career-articles?page=2&limit=1')).data.items.length, 0);
  const duplicate = await request('/admin/career-articles', { admin: true, method: 'POST', body: article() });
  assert.equal(duplicate.status, 409);
  const edited = await request(path, { admin: true, method: 'PUT', body: { ...published.data, title: 'Yeni başlıq', body: 'Yeni mətn.' } });
  assert.equal(edited.data.published_at, published.data.published_at);
  assert.equal((await request(`/career-articles/${created.data.slug}`)).data.body, 'Yeni mətn.');
  await request(path, { admin: true, method: 'PUT', body: { ...edited.data, status: 'draft' } });
  assert.equal((await request(`/career-articles/${created.data.slug}`)).status, 404);
  assert.equal((await request('/career-articles')).data.total, 0);
  assert.equal((await request(path, { admin: true, method: 'DELETE' })).status, 204);
  assert.equal((await request(path, { admin: true })).status, 404);
  assert.equal((await request(path, { admin: true, method: 'DELETE' })).status, 404);
  assert.equal((await request('/admin/career-articles/not-a-uuid', { admin: true })).status, 400);
});
