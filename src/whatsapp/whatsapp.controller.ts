import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';

@Controller('whatsapp/webhook')
export class WhatsAppController {
  constructor(private readonly supabase: SupabaseService) {}

  @Get()
  verify(
    @Query('hub.mode') mode?: string,
    @Query('hub.verify_token') token?: string,
    @Query('hub.challenge') challenge?: string,
  ) {
    const verifyToken = process.env.WHATSAPP_VERIFY_TOKEN;
    if (mode === 'subscribe' && verifyToken && token === verifyToken) return challenge ?? '';
    return { status: 'verification_failed' };
  }

  @Post()
  async receive(@Body() payload: any) {
    const changes = payload?.entry?.flatMap((entry: any) => entry?.changes ?? []) ?? [];
    const messages = changes.flatMap((change: any) => change?.value?.messages ?? []);

    for (const message of messages) {
      const phone = message?.from;
      if (!phone) continue;

      const body =
        message?.text?.body ??
        message?.button?.text ??
        message?.interactive?.button_reply?.title ??
        message?.interactive?.list_reply?.title ??
        null;

      const { data: contact, error: contactError } = await this.supabase.db
        .from('job_agent_contacts')
        .upsert(
          {
            whatsapp_phone: phone,
            last_message_at: new Date().toISOString(),
            current_step: 'role_selection',
            onboarding_status: 'in_progress',
          },
          { onConflict: 'whatsapp_phone' },
        )
        .select('id')
        .single();

      if (contactError || !contact) continue;

      const { data: conversation } = await this.supabase.db
        .from('job_agent_conversations')
        .insert({
          contact_id: contact.id,
          state: 'active',
          last_message_at: new Date().toISOString(),
        })
        .select('id')
        .single();

      if (!conversation) continue;

      await this.supabase.db.from('job_agent_messages').upsert(
        {
          conversation_id: conversation.id,
          provider_message_id: message?.id ?? null,
          direction: 'inbound',
          message_type: message?.type ?? 'text',
          body,
          payload: message,
        },
        { onConflict: 'provider_message_id' },
      );
    }

    return { status: 'received' };
  }
}
