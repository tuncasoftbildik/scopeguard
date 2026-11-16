# Sızma Testi Raporu

> İskelet. Köşeli parantezleri doldurun, alıntı kutularındaki notları silin. 1. ve 2. bölüm yönetim içindir ve tek başına okunabilmelidir: ikinci sayfada bırakan biri de pazartesi ne yapacağını bilmelidir.

| | |
| --- | --- |
| **Müşteri** | [ACME A.Ş.] |
| **Çalışma kimliği** | [ACME-2026-11] |
| **Test dönemi** | [20.11.2026 09:00 – 27.11.2026 18:00, UTC+03:00] |
| **Rapor sürümü** | [1.0, 02.12.2026] |
| **Hazırlayan** | [Ad soyad, iletişim] |
| **Gizlilik** | Gizli: yalnızca adı geçen müşteri yetkilileri içindir |

## 1. Yönetici özeti

**Genel risk: [Yüksek]**

[Üç ila beş cümle, teknik terim yok. Ne test edildi, en önemli sonuç ne, işe etkisi ne, ilk ne yapılmalı.]

| Önem derecesi | Adet | Test sırasında giderilen |
| --- | --- | --- |
| Kritik | [0] | |
| Yüksek | [2] | |
| Orta | [4] | |
| Düşük | [3] | |
| Bilgi | [5] | |

### İlk yapılacak üç iş

1. [İş, sorumlu, gerekçe. Her biri tek satır.]
2.
3.

### İyi çalışanlar

> Dürüst ve somut olun. Yalnızca kötü haber duyan müşteri bir süre sonra dinlemeyi bırakır.

- [Örnek: Yönetim arayüzlerine yalnızca VPN üzerinden erişilebiliyordu.]

## 2. Bulgular özet tablosu

| No | Bulgu | Önem | Varlık | Durum |
| --- | --- | --- | --- | --- |
| B-01 | [Sipariş numarası değiştirilerek başka müşterilerin sipariş bilgileri okunabiliyor] | Yüksek | app.example.com | Açık |
| B-02 | | | | |

## 3. Kapsam ve yetki

| | |
| --- | --- |
| **Test kuralları belgesi** | [Sürüm 1.0, 18.11.2026 tarihinde imzalandı] |
| **Kapsam içi** | [example.com ve alt alan adları; 203.0.113.0/28] |
| **Kapsam dışı** | [mail.example.com (üçüncü taraf); 203.0.113.9 (ödeme sistemi)] |
| **Yaklaşım** | [Ön bilgi yok / test hesapları verildi / kaynak kod verildi] |
| **Yetki kaydı** | `_scopeguard.[example.com]`, her araç çalıştırılmadan önce doğrulandı |
| **Sonucu etkileyen kısıtlar** | [Örnek: test yalnızca mesai dışında yapıldı; yük testi yapılmadı] |

> Neyin test **edilmediğini** ve nedenini yazın. Test edilmeyen alan, temiz alan demek değildir.

## 4. Yöntem

| Aşama | Yapılan |
| --- | --- |
| Keşif | [Yalnızca açık kaynaklar: DNS, sertifika kayıtları, yayımlanmış belgeler] |
| Haritalama | [Kapsam içi varlıklarda servis ve uygulama tespiti] |
| İnceleme | [Kimlik doğrulama, yetkilendirme, girdi işleme ve yapılandırmanın elle incelenmesi] |
| Doğrulama | [Her bulgu elle teyit edildi; etki, gereken en az işlemle gösterildi] |
| Raporlama | [Kritik bulgular aynı gün bildirildi; bu rapor] |

**Önem derecesi** CVSS v3.1 temel puanına göre verilmiştir. İş bağlamı riski açıkça değiştiriyorsa derece ayarlanmış ve gerekçesi bulguda yazılmıştır.

| Önem | CVSS | Beklenen işlem |
| --- | --- | --- |
| Kritik | 9,0–10,0 | Hemen giderilmeli ya da önlem alınmalı |
| Yüksek | 7,0–8,9 | [14] gün içinde giderilmeli |
| Orta | 4,0–6,9 | [60] gün içinde giderilmeli |
| Düşük | 0,1–3,9 | Olağan bakım sırasında giderilmeli |
| Bilgi | – | İyileştirme önerisi, doğrudan risk yok |

## 5. Bulgu ayrıntıları

> Her bulgu için bir bölüm. Önem sırasına göre dizin.

### B-01 [Sorunu ve yerini söyleyen kısa başlık]

| | |
| --- | --- |
| **Önem** | [Yüksek] |
| **CVSS v3.1** | [8,1] `[CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N]` |
| **Etkilenen varlık** | [https://app.example.com/orders/{id}] |
| **Kişisel veri içeriyor mu** | [Evet: ad, adres / Hayır] |
| **Durum** | [Açık / Giderildi, doğrulama bekliyor / Giderildi ve 10.12.2026'da doğrulandı] |

**Sorun.** [İki ila dört cümle, sade dille. Sistem ne yapıyor, ne yapmalıydı.]

**Etkisi.** [İşe yansıması, müşterinin diliyle: kim, kime, ne yapabilir; hangi ölçekte, ne kadar emekle.]

**Kanıt.** Müşterinin geliştiricisinin beş dakikada tekrarlayabileceği adımlar:

1. [A test kullanıcısıyla giriş yapılır.]
2. [A kullanıcısına ait `/orders/1042` açılır.]
3. [Numara `1043` yapılır. B kullanıcısının siparişi görüntülenir.]

[Ekran görüntüsü ya da kayıt alıntısı. Kişisel veriyi ve parolaları karartın; yalnızca sorunu kanıtlayacak kadarını gösterin.]

**Çözüm.** [Yapılacak somut değişiklik. "Sipariş döndürülmeden önce, siparişin oturum açan müşteriye ait olduğu sunucuda denetlenmeli."]

**Aynı kalıbın bulunabileceği yerler.** [Faturalar, adresler, destek kayıtları.]

**Kaynak.** [OWASP WSTG-ATHZ-04; CWE-639]

## 6. İyileştirme planı

| Öncelik | Yapılacak iş | Kapsadığı bulgular | Önerilen sorumlu | Emek |
| --- | --- | --- | --- | --- |
| 1 | [Nesne döndüren tüm uçlara sahiplik denetimi eklenmesi] | B-01, B-04 | [Arka uç ekibi] | [Gün] |
| 2 | | | | |

Giderilen bulguların doğrulama testi [düzeltmelerden sonraki 30 gün içinde, bir kez] bu çalışmaya dahildir.

## Ek A. Test kaydı

> Çalışmaya ait `scopeguard.log` dökümü: hangi araç, hangi hedefe, ne zaman (UTC) çalıştırıldı. Dosyayı ekleyin; ilk ve son satırı buraya yazın.

| İlk kayıt | Son kayıt | Çalıştırılan | Reddedilen |
| --- | --- | --- | --- |
| [2026-11-20T06:02:11Z] | [2026-11-27T14:48:40Z] | [312] | [7] |

## Ek B. Kullanılan araçlar

| Araç | Sürüm | Kullanım amacı |
| --- | --- | --- |
| | | |

## Ek C. Temizlik

| Kalem | Oluşturulma | Kaldırılma |
| --- | --- | --- |
| [Test hesabı pentest-a@example.com] | [20.11.2026] | [27.11.2026, müşteri teyit etti] |

Test eden tarafta tutulan tüm çalışma verisi [tarih] tarihinde silinecektir.
