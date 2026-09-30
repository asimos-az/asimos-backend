import { Module } from '@nestjs/common';
import { WhatsAppController } from './whatsapp.controller';

@Module({ controllers: [WhatsAppController] })
export class WhatsAppModule {}
