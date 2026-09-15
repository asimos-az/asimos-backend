export function normalizeContactNumber(value, required = false) {
  const compact = String(value ?? '').trim().replace(/[\s()-]/g, '');
  if (!compact && !required) return null;
  if (!/^(?:\+994|994|0)?[1-9]\d{8}$/.test(compact)) {
    throw Object.assign(new Error(required ? 'Düzgün əlaqə nömrəsi daxil edin' : 'Düzgün WhatsApp nömrəsi daxil edin'), { status: 400 });
  }
  return `+994${compact.slice(-9)}`;
}

// Both initial sends and resends share a cooldown. No codes or passwords are stored here.
export function createOtpSender({ admin, anon, mailer, smtpConfigured, from, now = Date.now }) {
  const attempts = new Map();
  return async function sendRegistrationOtp(email, metadata, shouldCreateUser = false) {
    const time = now();
    for (const [key, expires] of attempts) if (expires <= time) attempts.delete(key);
    if (attempts.has(email)) throw Object.assign(new Error('Yeni kod üçün 60 saniyə gözləyin.'), { status: 429 });
    attempts.set(email, time + 60000);
    if (!smtpConfigured) {
      const { error } = await anon.auth.signInWithOtp({ email, options: { shouldCreateUser, ...(metadata ? { data: metadata } : {}) } });
      if (error) {
        console.error('Registration OTP provider error', { code: error.code, status: error.status });
        throw Object.assign(new Error('Təsdiq kodu göndərilmədi. Bir qədər sonra yenidən cəhd edin.'), { status: error.status === 429 ? 429 : 502 });
      }
      return;
    }
    const { data, error } = await admin.auth.admin.generateLink({ type: 'magiclink', email, options: metadata ? { data: metadata } : {} });
    if (error || !/^\d{6,8}$/.test(data?.properties?.email_otp || '')) {
      console.error('Registration OTP generation failed', { code: error?.code });
      throw Object.assign(new Error('Təsdiq kodu yaradıla bilmədi. Yenidən cəhd edin.'), { status: 502 });
    }
    const code = data.properties.email_otp;
    try {
      const result = await mailer.sendMail({ from, to: email, subject: 'ASIMOS — E-poçt təsdiq kodunuz',
        text: `ASIMOS təsdiq kodunuz: ${code}\n\nBu kodu qeydiyyat səhifəsində daxil edin. Kodu heç kimlə paylaşmayın. Sorğunu siz etməmisinizsə, bu məktubu nəzərə almayın.`,
        html: `<div style="font-family:Arial,sans-serif;color:#17324d;max-width:480px;margin:auto;padding:32px"><h2 style="color:#079875">ASIMOS</h2><h3>E-poçtunuzu təsdiqləyin</h3><p>Qeydiyyatı tamamlamaq üçün bu kodu daxil edin:</p><div style="font-size:32px;font-weight:bold;letter-spacing:6px;padding:24px;background:#eaf8f3;border-radius:12px">${code}</div><p>Kodu heç kimlə paylaşmayın. Sorğunu siz etməmisinizsə, bu məktubu nəzərə almayın.</p></div>` });
      if (!result.accepted?.length || result.rejected?.length) throw new Error('Recipient rejected');
      console.info('Registration OTP accepted by SMTP', { messageId: result.messageId });
    } catch (error) {
      console.error('Registration OTP delivery failed', { code: error.code, responseCode: error.responseCode });
      throw Object.assign(new Error('E-poçt göndərilə bilmədi. Bir qədər sonra kodu yenidən istəyin.'), { status: 502 });
    }
  };
}
