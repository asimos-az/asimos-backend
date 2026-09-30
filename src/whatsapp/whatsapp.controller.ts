import { Body, Controller, Get, Post, Query } from '@nestjs/common';

@Controller('whatsapp/webhook')
export class WhatsAppController {
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
  receive(@Body() payload: unknown) {
    return { status: 'received' };
  }
}
