-- Anı Haritası: Supabase veritabanı kurulumu
-- Supabase panelinde SQL Editor > New query'ye yapıştırıp "Run" ile bir kez çalıştır.
-- Tekrar çalıştırmak güvenlidir: var olan tablolar ve veriler silinmez.
--
-- Tasarım:
--   * Tarayıcı tablolara doğrudan yazamaz. Yazma yalnızca submit_memory() ve report_memory()
--     fonksiyonlarıyla olur; bunlar girdiyi kontrol eder ve hız sınırı uygular.
--   * Herkes yalnızca "published" durumundaki anıları okuyabilir.
--   * Anıyla birlikte kişi bilgisi saklanmaz. Hız sınırı için IP adresinin tuzlu özeti
--     (hash) en fazla 24 saat tutulur, sonra silinir.

-- ---------- Tablolar ----------

create table if not exists public.memories (
  id          uuid primary key default gen_random_uuid(),
  date        date not null,
  lat         double precision not null,
  lng         double precision not null,
  city        text not null,
  place       text,
  text        text not null,
  mood        text,
  has_photo   boolean not null default false,
  status      text not null default 'published' check (status in ('pending', 'published', 'hidden')),
  reports     integer not null default 0,
  created_at  timestamptz not null default now()
);
create index if not exists memories_date_idx on public.memories (date);
create index if not exists memories_status_created_idx on public.memories (status, created_at desc);

-- Fotoğraflar ayrı tabloda: harita listesi hafif kalsın, fotoğraf yalnızca açılınca yüklensin.
create table if not exists public.memory_photos (
  id    uuid primary key references public.memories (id) on delete cascade,
  data  text not null
);

-- Hız sınırı ve şikâyet tekrarını önlemek için kısa ömürlü kayıtlar (IP'nin kendisi değil, özeti).
create table if not exists public.request_log (
  ip_hash     text not null,
  kind        text not null,
  target      uuid,
  created_at  timestamptz not null default now()
);
create index if not exists request_log_lookup_idx on public.request_log (ip_hash, kind, created_at);

-- Ayarlar: anıların onaysız yayına girip girmeyeceği ve kaç şikâyette gizleneceği.
create table if not exists public.settings (
  key    text primary key,
  value  text not null
);
insert into public.settings (key, value) values
  ('require_approval', 'false'),   -- 'true' yaparsan yeni anılar sen onaylayana kadar görünmez
  ('hide_after_reports', '3'),     -- bu kadar şikâyet alan anı otomatik gizlenir
  ('max_posts_per_hour', '5'),     -- bir IP saatte en fazla kaç anı bırakabilir
  ('ip_salt', md5(random()::text || clock_timestamp()::text)),
  ('turnstile_secret', '')         -- Cloudflare Turnstile gizli anahtarı; boşken bot kontrolü yapılmaz
on conflict (key) do nothing;

-- Turnstile doğrulaması için sunucudan Cloudflare'e istek atan eklenti.
create extension if not exists http with schema extensions;

-- ---------- Erişim kuralları (RLS) ----------

alter table public.memories      enable row level security;
alter table public.memory_photos enable row level security;
alter table public.request_log   enable row level security;
alter table public.settings      enable row level security;

drop policy if exists "yayindaki anilari herkes okur" on public.memories;
create policy "yayindaki anilari herkes okur" on public.memories
  for select to anon, authenticated using (status = 'published');

drop policy if exists "yayindaki anilarin fotografi okunur" on public.memory_photos;
create policy "yayindaki anilarin fotografi okunur" on public.memory_photos
  for select to anon, authenticated
  using (exists (select 1 from public.memories m where m.id = memory_photos.id and m.status = 'published'));

-- request_log ve settings için hiç politika yok: tarayıcı bunlara hiç erişemez.

revoke all on public.memories, public.memory_photos, public.request_log, public.settings from anon, authenticated;
grant select (id, date, lat, lng, city, place, text, mood, has_photo, status, created_at) on public.memories to anon, authenticated;
grant select on public.memory_photos to anon, authenticated;

-- ---------- Yardımcılar ----------

create or replace function public._client_ip_hash() returns text
language plpgsql stable security definer set search_path = public as $$
declare
  headers json := nullif(current_setting('request.headers', true), '')::json;
  ip text;
begin
  ip := coalesce(
    headers ->> 'cf-connecting-ip',
    split_part(coalesce(headers ->> 'x-forwarded-for', ''), ',', 1),
    'unknown'
  );
  return encode(sha256(convert_to(trim(ip) || (select value from settings where key = 'ip_salt'), 'utf8')), 'hex');
end $$;

create or replace function public._setting(k text) returns text
language sql stable security definer set search_path = public as $$
  select value from settings where key = k
$$;

-- ---------- Bot kontrolü (Cloudflare Turnstile) ----------

create or replace function public._verify_captcha(p_token text) returns void
language plpgsql volatile security definer set search_path = public, extensions as $$
declare
  v_secret text := coalesce(_setting('turnstile_secret'), '');
  v_res extensions.http_response;
  v_ok boolean;
begin
  if v_secret = '' then
    return; -- anahtar girilmemişse kontrol kapalı
  end if;
  if p_token is null or char_length(p_token) not between 10 and 4096 then
    raise exception 'Robot olmadığını doğrulayamadık. Kutucuğun tamamlanmasını bekleyip tekrar dene.' using errcode = 'P0001';
  end if;
  begin
    v_res := extensions.http_post(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      'secret=' || extensions.urlencode(v_secret) || '&response=' || extensions.urlencode(p_token),
      'application/x-www-form-urlencoded');
    v_ok := v_res.status = 200 and coalesce((v_res.content::json ->> 'success')::boolean, false);
  exception when others then
    raise exception 'Robot kontrolüne şu an ulaşılamıyor. Biraz sonra tekrar dene.' using errcode = 'P0001';
  end;
  if not v_ok then
    raise exception 'Robot olmadığını doğrulayamadık. Sayfayı yenileyip tekrar dene.' using errcode = 'P0001';
  end if;
end $$;

-- ---------- Anı bırakma ----------

-- Eski (captcha'sız) sürümü kaldır; yoksa kontrolü atlamak için kullanılabilirdi.
drop function if exists public.submit_memory(date, double precision, double precision, text, text, text, text, text);

create or replace function public.submit_memory(
  p_date date, p_lat double precision, p_lng double precision, p_city text,
  p_place text, p_text text, p_mood text, p_photo text, p_captcha text default null
) returns uuid
language plpgsql volatile security definer set search_path = public as $$
declare
  v_ip text := _client_ip_hash();
  v_id uuid;
  v_text text := btrim(coalesce(p_text, ''));
  v_place text := nullif(btrim(coalesce(p_place, '')), '');
  v_city text := btrim(coalesce(p_city, ''));
begin
  delete from request_log where created_at < now() - interval '24 hours';

  if (select count(*) from request_log
      where ip_hash = v_ip and kind = 'post' and created_at > now() - interval '1 hour')
     >= _setting('max_posts_per_hour')::int then
    raise exception 'Çok sık anı bıraktın. Biraz sonra tekrar dene.' using errcode = 'P0001';
  end if;

  perform _verify_captcha(p_captcha);

  if p_date is null or p_date > current_date or p_date < date '1940-01-01' then
    raise exception 'Tarih 1940 ile bugün arasında olmalı.' using errcode = 'P0001';
  end if;
  -- Türkiye ve KKTC'yi kapsayan geniş kutu; ayrıntılı sınır kontrolü sitede yapılıyor.
  if p_lat is null or p_lng is null or p_lat not between 34.5 and 42.5 or p_lng not between 25.5 and 45 then
    raise exception 'Yer Türkiye ya da KKTC sınırları içinde olmalı.' using errcode = 'P0001';
  end if;
  if char_length(v_city) not between 2 and 40 then
    raise exception 'İl bilgisi eksik.' using errcode = 'P0001';
  end if;
  if char_length(v_text) < 3 or char_length(v_text) > 1200 then
    raise exception 'Anı 3 ile 1200 karakter arasında olmalı.' using errcode = 'P0001';
  end if;
  if v_place is not null and char_length(v_place) > 120 then
    raise exception 'Yer tarifi en fazla 120 karakter olabilir.' using errcode = 'P0001';
  end if;
  if p_mood is not null and p_mood not in ('Özlem','Mutluluk','Hüzün','Öfke','Korku','Umut','Pişmanlık','Aşk') then
    raise exception 'Geçersiz his etiketi.' using errcode = 'P0001';
  end if;
  if p_photo is not null and (p_photo not like 'data:image/jpeg;base64,%' or char_length(p_photo) > 300000) then
    raise exception 'Fotoğraf geçersiz ya da çok büyük.' using errcode = 'P0001';
  end if;

  -- Kişiyi tanıtabilecek bilgileri yayından önce durdur: telefon, e-posta, TC kimlik numarası.
  if v_text || ' ' || coalesce(v_place, '') ~* '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'
     or regexp_replace(v_text || ' ' || coalesce(v_place, ''), '[\s().-]', '', 'g') ~ '(\+?90|0)?5\d{9}'
     or v_text ~ '(^|\D)[1-9]\d{10}(\D|$)' then
    raise exception 'Anında telefon, e-posta ya da kimlik numarası var gibi görünüyor. Anonimliğin için bunları çıkar.' using errcode = 'P0001';
  end if;

  insert into memories (date, lat, lng, city, place, text, mood, has_photo, status)
  values (p_date, round(p_lat::numeric, 4), round(p_lng::numeric, 4), v_city, v_place, v_text, p_mood,
          p_photo is not null,
          case when _setting('require_approval') = 'true' then 'pending' else 'published' end)
  returning id into v_id;

  if p_photo is not null then
    insert into memory_photos (id, data) values (v_id, p_photo);
  end if;

  insert into request_log (ip_hash, kind, target) values (v_ip, 'post', v_id);
  return v_id;
end $$;

-- ---------- Şikâyet ----------

create or replace function public.report_memory(p_id uuid) returns void
language plpgsql volatile security definer set search_path = public as $$
declare
  v_ip text := _client_ip_hash();
begin
  if exists (select 1 from request_log where ip_hash = v_ip and kind = 'report' and target = p_id) then
    return; -- aynı kişi aynı anıyı ikinci kez şikâyet edemez
  end if;
  if (select count(*) from request_log
      where ip_hash = v_ip and kind = 'report' and created_at > now() - interval '1 hour') >= 20 then
    raise exception 'Çok fazla şikâyet gönderdin. Biraz sonra tekrar dene.' using errcode = 'P0001';
  end if;
  update memories
     set reports = reports + 1,
         status = case when reports + 1 >= _setting('hide_after_reports')::int then 'hidden' else status end
   where id = p_id and status = 'published';
  insert into request_log (ip_hash, kind, target) values (v_ip, 'report', p_id);
end $$;

revoke all on function public._client_ip_hash(), public._setting(text), public._verify_captcha(text) from public, anon, authenticated;
revoke all on function public.submit_memory(date, double precision, double precision, text, text, text, text, text, text) from public;
revoke all on function public.report_memory(uuid) from public;
grant execute on function public.submit_memory(date, double precision, double precision, text, text, text, text, text, text) to anon, authenticated;
grant execute on function public.report_memory(uuid) to anon, authenticated;

-- ---------- Moderasyon ----------
-- Yönetici, Supabase Authentication'da e-posta + şifre ile açılmış bir kullanıcıdır.
-- Yetki için e-postası bu tabloda olmalı. Kurulumdan sonra bir kez çalıştır:
--   insert into public.admins (email) values ('senin@epostan.com');

create table if not exists public.admins (
  email text primary key check (email = lower(email))
);
alter table public.admins enable row level security;
revoke all on public.admins from anon, authenticated;

create or replace function public._is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce(auth.jwt() ->> 'role', '') = 'authenticated'
     and exists (select 1 from admins where email = lower(coalesce(auth.jwt() ->> 'email', '')))
$$;

create or replace function public._require_admin() returns void
language plpgsql stable security definer set search_path = public as $$
begin
  if not _is_admin() then
    raise exception 'Bu işlem için yönetici girişi gerekli.' using errcode = 'P0001';
  end if;
end $$;

create or replace function public.admin_check() returns boolean
language sql stable security definer set search_path = public as $$
  select _is_admin()
$$;

-- p_view: 'review' (onay bekleyen, şikâyet alan ya da gizlenen), 'published', 'hidden', 'pending', 'all'
create or replace function public.admin_memories(p_view text default 'review')
returns table (id uuid, date date, lat double precision, lng double precision, city text, place text,
               text text, mood text, has_photo boolean, status text, reports integer, created_at timestamptz)
language plpgsql stable security definer set search_path = public as $$
begin
  perform _require_admin();
  return query
    select m.id, m.date, m.lat, m.lng, m.city, m.place, m.text, m.mood, m.has_photo, m.status, m.reports, m.created_at
      from memories m
     where case p_view
             when 'review' then m.status <> 'published' or m.reports > 0
             when 'all' then true
             else m.status = p_view
           end
     order by (m.status = 'pending') desc, m.reports desc, m.created_at desc
     limit 500;
end $$;

create or replace function public.admin_photo(p_id uuid) returns text
language plpgsql stable security definer set search_path = public as $$
begin
  perform _require_admin();
  return (select data from memory_photos where id = p_id);
end $$;

-- Yayınlamak şikâyet sayacını sıfırlar; böylece tek yeni şikâyetle yeniden gizlenmez.
create or replace function public.admin_set_status(p_id uuid, p_status text) returns void
language plpgsql volatile security definer set search_path = public as $$
begin
  perform _require_admin();
  if p_status not in ('pending', 'published', 'hidden') then
    raise exception 'Geçersiz durum.' using errcode = 'P0001';
  end if;
  update memories
     set status = p_status,
         reports = case when p_status = 'published' then 0 else reports end
   where id = p_id;
end $$;

create or replace function public.admin_delete(p_id uuid) returns void
language plpgsql volatile security definer set search_path = public as $$
begin
  perform _require_admin();
  delete from memories where id = p_id;
end $$;

create or replace function public.admin_settings() returns json
language plpgsql stable security definer set search_path = public as $$
begin
  perform _require_admin();
  return (select json_object_agg(key, value) from settings where key not in ('ip_salt', 'turnstile_secret'));
end $$;

create or replace function public.admin_set_setting(p_key text, p_value text) returns void
language plpgsql volatile security definer set search_path = public as $$
begin
  perform _require_admin();
  if p_key = 'require_approval' and p_value in ('true', 'false')
     or p_key = 'hide_after_reports' and p_value ~ '^\d{1,3}$' and p_value::int >= 1
     or p_key = 'max_posts_per_hour' and p_value ~ '^\d{1,3}$' and p_value::int >= 1 then
    update settings set value = p_value where key = p_key;
  else
    raise exception 'Geçersiz ayar.' using errcode = 'P0001';
  end if;
end $$;

revoke all on function public._is_admin(), public._require_admin() from public, anon, authenticated;
revoke all on function public.admin_check(), public.admin_memories(text), public.admin_photo(uuid),
  public.admin_set_status(uuid, text), public.admin_delete(uuid), public.admin_settings(),
  public.admin_set_setting(text, text) from public, anon;
grant execute on function public.admin_check(), public.admin_memories(text), public.admin_photo(uuid),
  public.admin_set_status(uuid, text), public.admin_delete(uuid), public.admin_settings(),
  public.admin_set_setting(text, text) to authenticated;
