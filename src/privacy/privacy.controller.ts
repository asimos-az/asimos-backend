import { Controller, Get, Header } from '@nestjs/common';

@Controller()
export class PrivacyController {
  @Get('privacy')
  @Header('Content-Type', 'text/html; charset=utf-8')
  privacy(): string {
    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Privacy Policy - Asimos WhatsApp Job Agent</title>
  <style>
    body{font-family:Arial,sans-serif;max-width:820px;margin:40px auto;padding:0 20px;line-height:1.6;color:#222}
    h1,h2{line-height:1.25} small{color:#666}
  </style>
</head>
<body>
<h1>Privacy Policy</h1>
<p><small>Last updated: September 30, 2026</small></p>
<p>Asimos WhatsApp Job Agent ("we", "our", or "the service") helps job seekers and employers interact through WhatsApp.</p>

<h2>Information we collect</h2>
<p>When you use the service, we may process your WhatsApp phone number, profile/display name, messages you send to the service, job-seeking preferences, CV information you choose to provide, employer and vacancy information, and location information that you voluntarily provide for location-based job matching.</p>

<h2>How we use information</h2>
<p>We use this information to operate the WhatsApp job service, create and manage job-seeker or employer profiles, match job seekers with vacancies, send requested job notifications, process support requests, prevent abuse, and maintain service security.</p>

<h2>WhatsApp and Meta</h2>
<p>The service uses the WhatsApp Business Platform provided by Meta. Information transmitted through WhatsApp may also be processed by Meta according to its own terms and privacy policies.</p>

<h2>Data sharing</h2>
<p>We do not sell personal information. Information is shared only when necessary to provide the service, comply with legal obligations, protect the service, or when you explicitly choose to share information with an employer or job seeker.</p>

<h2>Data retention and security</h2>
<p>We retain information only for as long as reasonably necessary for the purposes described above and apply reasonable technical and organizational safeguards to protect stored information.</p>

<h2>Your choices</h2>
<p>You may stop interacting with the service at any time. You may also request access to or deletion of personal information associated with your use of the service by contacting us.</p>

<h2>Contact</h2>
<p>For privacy questions or data requests, contact: <strong>asimos.org@gmail.com</strong></p>
</body>
</html>`;
  }
}
