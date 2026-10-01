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
  ('ip_salt', md5(random()::text || clock_timestamp()::text))
on conflict (key) do nothing;

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

-- ---------- Anı bırakma ----------

create or replace function public.submit_memory(
  p_date date, p_lat double precision, p_lng double precision, p_city text,
  p_place text, p_text text, p_mood text, p_photo text
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

revoke all on function public._client_ip_hash(), public._setting(text) from public, anon, authenticated;
revoke all on function public.submit_memory(date, double precision, double precision, text, text, text, text, text) from public;
revoke all on function public.report_memory(uuid) from public;
grant execute on function public.submit_memory(date, double precision, double precision, text, text, text, text, text) to anon, authenticated;
grant execute on function public.report_memory(uuid) to anon, authenticated;
