# Anı Haritası

Canlı: https://aniharitasi.com

Türkiye ve KKTC içinde, takvimde bir güne gidip haritada bir noktaya geçmiş bir anıyı (yazı ve isteğe bağlı fotoğraf) **isimsiz** bırakma prototipi.

## Nasıl çalışır
- Tek dosya: `index.html`. Tarayıcıda açman yeterli, kurulum yok.
- Harita: OpenStreetMap + Leaflet. Üstteki kutudan yer ara (ör. "Kadıköy Starbucks") ya da yakınlaştırıp noktaya dokun.
- Takvim: bir gün seç, "Bu gün", "Her yıl bu gün" veya "Tümü" görünümüyle anıları gez.
- Anı: tarih, yer tarifi, metin (en fazla 1200 karakter), his etiketi, fotoğraf.
- Gizlilik: isim ya da hesap kaydedilmez; fotoğraf tarayıcıda küçültülür ve içindeki GPS/cihaz bilgisi silinir.

## Ortak veri (Supabase)
`index.html` içindeki `SUPABASE` ayarı boşsa anılar yalnızca ziyaretçinin kendi tarayıcısında saklanır. Herkesin anıyı görmesi için:
1. supabase.com'da proje aç (bölge: Frankfurt).
2. SQL Editor'da `supabase/schema.sql` dosyasının tamamını çalıştır.
3. Project Settings > API'deki **Project URL** ve **anon public** anahtarını `index.html` içindeki `SUPABASE` satırına yaz. `service_role` anahtarını asla koyma.

Tarayıcı tablolara doğrudan yazamaz; anılar `submit_memory`, şikâyetler `report_memory` fonksiyonundan geçer (girdi kontrolü, telefon/e-posta/TC no filtresi, IP özetiyle hız sınırı). Ayarlar `settings` tablosunda: `require_approval`, `hide_after_reports`, `max_posts_per_hour`.

## Moderasyon (`admin.html`)
1. Supabase'de Authentication > Users > Add user ile kendine e-posta + şifreli kullanıcı aç ("Auto confirm" işaretli).
2. SQL Editor'da `insert into public.admins (email) values ('senin@epostan.com');` çalıştır (küçük harfle).
3. `/admin.html` adresinden gir. Onay bekleyen, şikâyet alan ve gizlenen anıları yayınla, gizle ya da sil; ayarları buradan değiştir.

## Gerçek yayına çıkmadan önce
1. Ortak veri için sunucu (ör. Supabase / Firebase) ve fotoğraflar için depolama.
2. Moderasyon: şikâyet butonu, küfür/nefret filtresi, fotoğraflarda yüz/plaka bulanıklaştırma.
3. Kötüye kullanım koruması: hız sınırı, captcha; IP saklamadan.
4. KVKK metni ve kullanım koşulları.
5. OpenStreetMap karo ve Nominatim arama sunucuları yoğun trafik için değil; yayında MapTiler / Stadia / Carto gibi bir sağlayıcı kullanılmalı.
