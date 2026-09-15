import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeContactNumber, createOtpSender } from './registration.js';

test('required contact and independent optional WhatsApp normalization', () => {
  for (const value of ['0501234567', '+994 50 123 45 67', '501234567', '994501234567']) assert.equal(normalizeContactNumber(value, true), '+994501234567');
  assert.equal(normalizeContactNumber(''), null);
  assert.equal(normalizeContactNumber(null), null);
  for (const value of ['', '+994', 'abc501234567', '123', '+9940501234567']) assert.throws(() => normalizeContactNumber(value, true), { status: 400 });
});

function fixture(overrides = {}) {
  const sent = [];
  const native = [];
  const generate = [];
  const sender = createOtpSender({
    admin: { auth: { admin: { generateLink: async (args) => { generate.push(args); return { data: { properties: { email_otp: '12345678' } } }; } } } },
    anon: { auth: { signInWithOtp: async args => { native.push(args); return {}; } } },
    mailer: { sendMail: async mail => { sent.push(mail); return { accepted: [mail.to], rejected: [] }; } },
    smtpConfigured: true, from: 'test@example.com', ...overrides,
  });
  return { sender, sent, native, generate };
}

test('SMTP sends a numeric OTP without exposing auth link or token to caller', async () => {
  const f = fixture();
  assert.equal(await f.sender('test@example.com', { phone: '+994501234567', whatsapp: null }, true), undefined);
  assert.match(f.sent[0].text, /12345678/);
  assert.equal(f.generate[0].type, 'magiclink');
  assert.equal(f.native.length, 0);
  await assert.rejects(f.sender('test@example.com'), { status: 429 });
});

test('resend is available after cooldown', async () => {
  let now = 1;
  const f = fixture({ now: () => now });
  await f.sender('test@example.com'); now += 60000;
  await f.sender('test@example.com');
  assert.equal(f.sent.length, 2);
});

test('missing backend SMTP uses configured Supabase delivery', async () => {
  const f = fixture({ smtpConfigured: false });
  await f.sender('test@example.com', undefined, false);
  assert.equal(f.native[0].options.shouldCreateUser, false);
  assert.equal(f.sent.length, 0);
});

test('delivery rejection reports failure, never a successful send', async () => {
  const f = fixture({ mailer: { sendMail: async () => ({ accepted: [], rejected: ['test@example.com'] }) } });
  await assert.rejects(f.sender('test@example.com'), { status: 502 });
});

test('provider rate limit remains actionable', async () => {
  const f = fixture({ smtpConfigured: false, anon: { auth: { signInWithOtp: async () => ({ error: { status: 429, code: 'over_email_send_rate_limit' } }) } } });
  await assert.rejects(f.sender('test@example.com'), { status: 429 });
});
