import { Module } from '@nestjs/common';
import { HealthController } from './health/health.controller';
import { SupabaseModule } from './supabase/supabase.module';
import { WhatsAppModule } from './whatsapp/whatsapp.module';
import { PrivacyController } from './privacy/privacy.controller';

@Module({
  imports: [SupabaseModule, WhatsAppModule],
  controllers: [HealthController, PrivacyController],
})
export class AppModule {}
