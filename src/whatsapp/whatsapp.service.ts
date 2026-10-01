import { Injectable, Logger } from '@nestjs/common';

@Injectable()
export class WhatsAppService {
  private readonly logger = new Logger(WhatsAppService.name);

  async sendRoleSelection(to: string) {
    const token = process.env.WHATSAPP_ACCESS_TOKEN;
    const phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;

    if (!token || !phoneNumberId) {
      this.logger.error(
        `WhatsApp outbound env missing: token=${Boolean(token)} phoneNumberId=${Boolean(phoneNumberId)}`,
      );
      return null;
    }

    try {
      const response = await fetch(
        `https://graph.facebook.com/v24.0/${phoneNumberId}/messages`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            messaging_product: 'whatsapp',
            recipient_type: 'individual',
            to,
            type: 'interactive',
            interactive: {
              type: 'button',
              body: {
                text: '👋 Salam! Job Agent-ə xoş gəlmisiniz. Sizə necə kömək edək?',
              },
              action: {
                buttons: [
                  {
                    type: 'reply',
                    reply: { id: 'role_seeker', title: '🔎 İş axtarıram' },
                  },
                  {
                    type: 'reply',
                    reply: { id: 'role_employer', title: '🏢 İşçi axtarıram' },
                  },
                ],
              },
            },
          }),
        },
      );

      const data: any = await response.json().catch(() => ({}));

      if (!response.ok) {
        this.logger.error(
          `WhatsApp send failed status=${response.status} code=${data?.error?.code ?? 'unknown'} subcode=${data?.error?.error_subcode ?? 'unknown'} message=${data?.error?.message ?? JSON.stringify(data)}`,
        );
        return null;
      }

      this.logger.log(
        `WhatsApp outbound accepted to=${to} messageId=${data?.messages?.[0]?.id ?? 'unknown'}`,
      );
      return data;
    } catch (error) {
      this.logger.error(
        `WhatsApp send exception: ${error instanceof Error ? error.message : String(error)}`,
      );
      return null;
    }
  }
}
