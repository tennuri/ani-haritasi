# Anı Haritası

Türkiye içinde, takvimde bir güne gidip haritada bir noktaya geçmiş bir anıyı (yazı ve isteğe bağlı fotoğraf) **isimsiz** bırakma prototipi.

## Nasıl çalışır
- Tek dosya: `index.html`. Tarayıcıda açman yeterli, kurulum yok.
- Harita: OpenStreetMap + Leaflet. Üstteki kutudan yer ara (ör. "Kadıköy Starbucks") ya da yakınlaştırıp noktaya dokun.
- Takvim: bir gün seç, "Bu gün", "Her yıl bu gün" veya "Tümü" görünümüyle anıları gez.
- Anı: tarih, yer tarifi, metin (en fazla 1200 karakter), his etiketi, fotoğraf.
- Gizlilik: isim ya da hesap kaydedilmez; fotoğraf tarayıcıda küçültülür ve içindeki GPS/cihaz bilgisi silinir.

## Şu anki sınır
Bu prototipte anılar **yalnızca ziyaretçinin kendi tarayıcısında** (localStorage) saklanır; başkaları göremez. Herkesin birbirinin anısını görmesi için bir sunucu gerekir.

## Gerçek yayına çıkmadan önce
1. Ortak veri için sunucu (ör. Supabase / Firebase) ve fotoğraflar için depolama.
2. Moderasyon: şikâyet butonu, küfür/nefret filtresi, fotoğraflarda yüz/plaka bulanıklaştırma.
3. Kötüye kullanım koruması: hız sınırı, captcha; IP saklamadan.
4. KVKK metni ve kullanım koşulları.
5. OpenStreetMap karo ve Nominatim arama sunucuları yoğun trafik için değil; yayında MapTiler / Stadia / Carto gibi bir sağlayıcı kullanılmalı.
