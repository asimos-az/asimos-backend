import { Controller, Get } from '@nestjs/common';
import { SupabaseService } from '../supabase/supabase.service';

@Controller('health')
export class HealthController {
  constructor(private readonly supabase: SupabaseService) {}

  @Get()
  async check() {
    const database = await this.supabase.ping();
    return { status: database ? 'ok' : 'degraded', service: 'job-agent-backend', database: database ? 'connected' : 'disconnected', timestamp: new Date().toISOString() };
  }
}
