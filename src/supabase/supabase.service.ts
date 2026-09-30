import { Injectable } from '@nestjs/common';
import { createClient, SupabaseClient } from '@supabase/supabase-js';

@Injectable()
export class SupabaseService {
  private readonly client: SupabaseClient | null;
  constructor() {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
    this.client = url && key ? createClient(url, key, { auth: { persistSession: false, autoRefreshToken: false } }) : null;
  }
  isConfigured(): boolean { return this.client !== null; }
  get db(): SupabaseClient { if (!this.client) throw new Error('Supabase is not configured'); return this.client; }
  async ping(): Promise<boolean> { if (!this.client) return false; const { error } = await this.client.from('jobs').select('id').limit(1); return !error; }
}
