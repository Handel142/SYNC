import { createClient } from '@supabase/supabase-js';
const url=import.meta.env.VITE_SUPABASE_URL?.trim();
const key=import.meta.env.VITE_SUPABASE_ANON_KEY?.trim();
export const configured=Boolean(url&&key&&!url.includes('YOUR-PROJECT')&&!key.includes('YOUR_PUBLIC'));
export const supabase=configured?createClient(url,key,{auth:{persistSession:true,autoRefreshToken:true,detectSessionInUrl:true}}):null;
