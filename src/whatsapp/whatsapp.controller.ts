import { Body, Controller, Get, Logger, Post, Query } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';
import { WhatsAppService } from './whatsapp.service';

@Controller('whatsapp/webhook')
export class WhatsAppController {
  private readonly logger = new Logger(WhatsAppController.name);

  constructor(
    private readonly supabase: SupabaseService,
    private readonly whatsapp: WhatsAppService,
  ) {}

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
    const statuses = changes.flatMap((change: any) => change?.value?.statuses ?? []);

    for (const status of statuses) {
      const errors = status?.errors ?? [];
      this.logger.log(
        `WhatsApp status id=${status?.id ?? 'unknown'} status=${status?.status ?? 'unknown'} recipient=${status?.recipient_id ?? 'unknown'} errors=${JSON.stringify(errors)}`,
      );
    }

    for (const message of messages) {
      const phone = message?.from;
      if (!phone) continue;

      const body =
        message?.text?.body ??
        message?.button?.text ??
        message?.interactive?.button_reply?.title ??
        message?.interactive?.list_reply?.title ??
        null;

      const { data: existingContact } = await this.supabase.db
        .from('job_agent_contacts')
        .select('id, role, current_step, onboarding_status')
        .eq('whatsapp_phone', phone)
        .maybeSingle();

      const isNewContact = !existingContact;

      const { data: contact, error: contactError } = await this.supabase.db
        .from('job_agent_contacts')
        .upsert(
          {
            whatsapp_phone: phone,
            last_message_at: new Date().toISOString(),
            ...(isNewContact
              ? { current_step: 'role_selection', onboarding_status: 'in_progress' }
              : {}),
          },
          { onConflict: 'whatsapp_phone' },
        )
        .select('id, role, current_step, onboarding_status')
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

      const { error: messageError } = await this.supabase.db
        .from('job_agent_messages')
        .upsert(
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

      if (messageError) continue;

      const buttonId =
        message?.interactive?.button_reply?.id ??
        message?.button?.payload ??
        null;

      if (buttonId === 'role_seeker') {
        await this.supabase.db
          .from('job_agent_contacts')
          .update({ role: 'seeker', current_step: 'seeker_job_title' })
          .eq('id', contact.id);
        continue;
      }

      if (buttonId === 'role_employer') {
        await this.supabase.db
          .from('job_agent_contacts')
          .update({ role: 'employer', current_step: 'employer_company_name' })
          .eq('id', contact.id);
        continue;
      }

      if (isNewContact || !contact.role || contact.current_step === 'role_selection') {
        await this.whatsapp.sendRoleSelection(phone);
      }
    }

    return { status: 'received' };
  }
}
