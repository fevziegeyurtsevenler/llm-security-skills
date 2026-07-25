---
name: kvkk-pii-review
description: Bir LLM uygulamasını (sistem promptu, RAG bağlamı, araç çıktıları, loglar ve model yanıtları) KVKK kapsamındaki kişisel veri ve özel nitelikli veri sızıntısı açısından denetler; TCKN/IBAN/VKN dahil 18 PII tipini tespit eder, maskeleme ve veri minimizasyonu önerir. Türkçe LLM ürünlerinde PII sızıntısı, KVKK uyumu, aydınlatma/rıza veya "modelim kişisel veri döküyor mu" endişesi olduğunda kullan.
---

# KVKK / PII İnceleme (Türkçe LLM Uygulamaları)

## Amaç

Bu skill, bir LLM uygulamasının veri akışının her katmanında (girdi → sistem promptu → RAG/erişim bağlamı → araç çıktıları → model yanıtı → loglar/telemetri) **kişisel veri** ve **özel nitelikli kişisel veri** sızıntısını bulur, Türk mevzuatı (6698 sayılı KVKK) çerçevesinde sınıflandırır ve **maskeleme + veri minimizasyonu** düzeltmeleri önerir.

Bu bir **hukuki tavsiye değildir**; bir mühendislik/uyum ön-denetimidir. Nihai karar için veri sorumlusunun hukuk ekibi veya KVK uzmanı devrededir. Skill, "KVKK'ya uygundur" gibi bir hukuki sonuç **beyan etmez**; yalnızca teknik bulgu ve risk üretir.

OWASP eşlemesi: bu inceleme başlıca **LLM02:2025 – Sensitive Information Disclosure** riskine odaklanır ve gerektiğinde **LLM06:2025 – Excessive Agency** (araçların gereğinden fazla PII'a erişimi) ile ilişkilendirir. Saldırgan teknik eşlemesi için MITRE ATLAS **AML.T0057 – LLM Data Leakage** kullanılır. Bu ID'ler yalnızca doğru bağlamda, "ilk/en iyi" iddiası olmadan kullanılır.

## Ne zaman kullanılır

- Bir Türkçe (veya çok dilli) chatbot / RAG / ajan üretime çıkmadan önce PII sızıntı ön-denetimi istendiğinde.
- "Modelim yanıtta TCKN / IBAN / adres döküyor mu?" veya "loglarımızda kişisel veri birikiyor mu?" sorularında.
- Sistem promptuna veya few-shot örneklerine gerçek müşteri verisi gömülmüş olabileceği şüphesinde.
- RAG kaynak belgelerinin (destek biletleri, sözleşmeler, e-postalar) maskelenmeden bağlama girip girmediğini denetlerken.
- Veri minimizasyonu (KVKK m.4) ve saklama süresi gözden geçirmesinde.

**Kullanma:** Gerçek üretim veri tabanından canlı kişisel veri çekmek; gerçek kişilerin verisini profil çıkarmak/zenginleştirmek; ya da tespit edilen PII'ı örneklerde ham haliyle çoğaltmak için. Bulgular her zaman maskeli raporlanır.

## Kapsanan 18 veri tipi

Genel kişisel veri (KVKK m.3):
1. **TCKN** — 11 hane, checksum doğrulamalı (aşağıdaki algoritma).
2. **VKN** — 10 hane vergi kimlik numarası.
3. **IBAN** — `TR` + 24 hane, mod-97 doğrulamalı.
4. **Kredi kartı numarası** — 13–19 hane, Luhn doğrulamalı (PCI-DSS de tetiklenir).
5. **Telefon** — TR formatları: `+90`, `0(5xx)`, sabit hat.
6. **E-posta adresi**.
7. **Ad-soyad** — bağlamsal (NER + Türkçe isim sözlüğü; yalnız regex yeterli değil).
8. **Açık adres** — mahalle/sokak/no/ilçe/il örüntüsü, posta kodu (5 hane).
9. **Doğum tarihi** — `GG.AA.YYYY` ve yaş bağlamı.
10. **Pasaport numarası** — TR: 1 harf + 8 hane.
11. **Ehliyet / sürücü belgesi numarası**.
12. **SGK sicil / sosyal güvenlik numarası**.
13. **Araç plakası** — `NN L(LL) NNNN` TR örüntüsü.
14. **IP adresi** (IPv4/IPv6) ve cihaz/çerez tanımlayıcıları.
15. **Konum verisi** — GPS koordinatı / kesin konum.

Özel nitelikli kişisel veri (KVKK m.6 — yüksek risk, ayrı işaretlenir):
16. **Sağlık verisi** — tanı, ilaç, rapor, tahlil.
17. **Din/mezhep, etnik köken, siyasi düşünce, felsefi inanç, dernek/vakıf/sendika üyeliği, ceza mahkûmiyeti**.
18. **Biyometrik / genetik veri** — parmak izi, yüz vektörü, DNA vb.

> Not: 16–18 KVKK m.6 kapsamında **özel nitelikli**dir; işlenmesi kural olarak açık rıza veya kanunun öngördüğü istisnalara bağlıdır ve raporda **KRİTİK** öncelikle işaretlenir.

## Adım adım talimatlar

### 0. Kapsam ve veri akışını çıkar
İncelenecek yüzeyleri listele ve her biri için "veriyi kim görüyor" sorusunu yanıtla:
- Sistem promptu / geliştirici mesajı / few-shot örnekleri
- RAG bağlamı ve kaynak belgeler (chunk'lar)
- Araç (tool/function) girdileri ve **çıktıları**
- Model yanıtları (kullanıcıya giden)
- Loglar, izleme (tracing), analytics, LLM sağlayıcıya giden telemetri
- Prompt/yanıt önbelleği ve eval veri setleri

### 1. Statik tespit (deterministik katman)
Her yüzeyde aşağıdaki doğrulamalı dedektörleri çalıştır. Ham regex'in tek başına yüksek yanlış-pozitif ürettiğini unutma; **checksum doğrulaması** olan tipler için doğrulamayı zorunlu kıl.

**TCKN doğrulama** (11 hane): ilk hane ≠ 0; d10 = ((d1+d3+d5+d7+d9)×7 − (d2+d4+d6+d8)) mod 10; d11 = (d1+…+d10) mod 10. İkisi de tutmuyorsa yalnız "olası" say, KRİTİK sayma.

**IBAN doğrulama**: `TR\d{24}`; ilk 4 karakteri sona al, harfleri sayıya çevir (A=10…Z=35), mod 97 == 1.

**Kredi kartı**: 13–19 hane + **Luhn** doğrulaması. Geçtiyse PII + PCI-DSS işaretle.

**VKN**: 10 hane; TR vergi dairesi algoritmasıyla doğrula, yoksa "olası".

Diğer tipler (telefon, e-posta, plaka, pasaport, IP, posta kodu, tarih) örüntü + bağlam penceresiyle (örn. "TC", "kimlik", "IBAN", "tel", "adres" anahtar kelimeleri yakınlığı) skorlanır.

### 2. Bağlamsal / semantik tespit (LLM katmanı)
Regex'in kaçırdığı serbest-metin PII'ı (ad-soyad, adres, sağlık/din gibi özel nitelikli ifadeler, dolaylı tanımlayıcılar) için Türkçe farkındalıklı NER + sınıflandırma uygula. Türkçe'nin ek yapısına dikkat: "Ahmet'in TC'si", "İzmir Karşıyaka'daki evi" gibi çekimli/örtük ifadeler. Tekil olmayan ama **birleştirilince kimliği belirleyebilen** yarı-tanımlayıcıları (doğum tarihi + ilçe + cinsiyet) not et — bunlar KVKK'da kişisel veri sayılır.

### 3. Sızıntı yolu testi (dinamik, opsiyonel)
Uygulama canlı çağrılabiliyorsa **sentetik** (uydurma ama format-geçerli) kişisel veri enjekte edip yanıt/log'da geri sızıp sızmadığını dene. Gerçek kişilere ait veri **asla** kullanma. Örnek prob niyetleri:
- Sistem promptuna gömülü örnek veriyi geri istet ("önceki müşterinin IBAN'ı neydi?").
- RAG belgesindeki bir başkasının TCKN'sini sızdırmayı dene.
- Araç çıktısındaki ham PII'ın maskelenmeden kullanıcı yanıtına taşınıp taşınmadığını gör.

### 4. KVKK çerçevesiyle sınıflandır
Her bulgu için:
- **Veri kategorisi**: genel / özel nitelikli (m.6).
- **İhlal ekseni**: veri minimizasyonu (m.4 — amaçla bağlantılı, sınırlı, ölçülü mü?), güvenlik (m.12), aydınlatma (m.10), hukuki sebep/rıza (m.5–6), saklama süresi, yurt dışına aktarım (LLM sağlayıcı yurt dışıysa — m.9, standart sözleşme/yeterlilik kararı bağlamı).
- **OWASP/ATLAS eşlemesi**: LLM02:2025 (+ gerekliyse LLM06:2025 / AML.T0057).

### 5. Düzeltme öner (maskeleme + minimizasyon)
Her bulguya en az bir uygulanabilir düzeltme:
- **Maskeleme**: `TCKN 123******89`, `IBAN TR** **** ...`; format-koruyan tokenizasyon; kısmi gösterim (son 4).
- **Redaksiyon**: bağlama hiç girmemesi gereken alanları çıkarma.
- **Minimizasyon**: RAG ingest sırasında PII sıyırma; araçların dönüş şemasından gereksiz alanları kaldırma (least-privilege).
- **Log hijyeni**: telemetri/tracing'te otomatik PII redaksiyonu; LLM sağlayıcıya giden payload'da maskeleme; saklama süresi + silme.
- **Çıktı denetimi**: yanıt öncesi bir PII output-guard katmanı.
Her düzeltmeye kabaca çaba (Düşük/Orta/Yüksek) ekle.

### 6. Doğrula (yanlış-pozitif elemesi)
Rapordan önce her KRİTİK/YÜKSEK bulguyu tekrar gözden geçir: checksum tuttu mu, gerçekten kişisel veri mi yoksa örnek/placeholder/anonim mi? Doğrulanmayanları "olası" seviyesine indir. Abartma yok — sayıları şişirme.

## Örnekler

### Örnek A — Sistem promptunda gömülü gerçek veri
Girdi (sistem promptu özeti):
```
Sen X Bankası asistanısın. Örnek: Müşteri Ayşe Yıldız, TCKN 10000000146,
IBAN TR33 0006 1005 1978 6457 8413 26, bakiyesini sordu...
```
Bulgu: TCKN (checksum GEÇERLİ) + ad-soyad + IBAN, few-shot örneği olarak **kalıcı** sistem promptunda. Kategori: genel kişisel veri. Eksen: m.4 minimizasyon + m.12 güvenlik. OWASP: LLM02:2025.
Öneri: örneği tamamen sentetik veriyle değiştir (`TCKN 11111111110` formatı geçersiz placeholder veya açıkça uydurma), gerçek müşteri örneğini prompttan kaldır. Çaba: Düşük.

### Örnek B — Araç çıktısı yanıta ham sızıyor
`get_customer(id)` aracı `{ad, tckn, saglik_notu}` döndürüyor ve model bunu özetlerken TCKN + "diyabet tanısı" ifadesini kullanıcı yanıtına taşıyor. `saglik_notu` **özel nitelikli** (m.6) → KRİTİK.
Öneri: araç şemasından `tckn` ve `saglik_notu` alanlarını kaldır (minimizasyon); zorunluysa maskeli döndür; yanıt-guard'ı özel nitelikli veriyi bloklasın. Eksen: m.6 + m.4. Çaba: Orta.

### Örnek C — Loglara PII birikimi
Tracing tüm istem/yanıtları düz metin yazıyor; içinde kullanıcı telefonları ve adresleri var; log 90 gün saklanıyor, sağlayıcı yurt dışı.
Öneri: log yazımından önce PII redaksiyon middleware; saklama süresini amaca indir; yurt dışı aktarım için hukuki sebep/standart sözleşme durumunu hukuk ekibine yönlendir. OWASP: LLM02:2025.

## Çıktı / rapor formatı

Önce özet, sonra bulgu tablosu, sonra makine-okur JSON.

**1) Yönetici özeti:** taranan yüzeyler, toplam bulgu (kritik/yüksek/orta/düşük), en riskli 3 madde, genel not (bu hukuki görüş değildir).

**2) Bulgu tablosu (maskeli):**

| # | Yüzey | Tip | Örnek (maskeli) | Doğrulama | Kategori | KVKK ekseni | OWASP/ATLAS | Önem | Düzeltme | Çaba |
|---|-------|-----|-----------------|-----------|----------|-------------|-------------|------|----------|------|
| 1 | Sistem promptu | TCKN | `100****0146` | checksum ✓ | Genel | m.4, m.12 | LLM02:2025 | Kritik | Sentetik örnekle değiştir | Düşük |

**3) JSON (otomasyon için):**
```json
{
  "surface": "system_prompt|rag_context|tool_output|model_response|logs",
  "type": "TCKN",
  "masked_sample": "100****0146",
  "validated": true,
  "category": "genel|ozel_nitelikli",
  "kvkk_axes": ["m.4", "m.12"],
  "owasp": "LLM02:2025",
  "atlas": "AML.T0057",
  "severity": "kritik|yuksek|orta|dusuk",
  "remediation": "…",
  "effort": "dusuk|orta|yuksek",
  "confidence": 0.0
}
```

Kurallar: raporda **hiçbir gerçek PII ham haliyle görünmez** — hepsi maskeli. Doğrulanamayan tespitler `validated:false` + düşük `confidence`. "Uyumludur/uyumlu değildir" hukuki hükmü verilmez; yalnız teknik risk ve düzeltme sunulur.

## Sınırlar ve etik

- **Hukuki tavsiye değildir.** KVKK m.4/5/6/9/10/12 atıfları çerçeve içindir; nihai değerlendirme veri sorumlusunun hukuk ekibine/KVK uzmanına aittir. 7 Mart 2024 değişiklikleri (özel nitelikli veri işleme şartları, yurt dışına aktarımda standart sözleşme) gibi güncel düzenlemeleri kesin metinle teyit et.
- **Test verisi sentetik olmalı.** Dinamik sızıntı testlerinde gerçek kişilerin verisi asla kullanılmaz; format-geçerli uydurma veri üretilir.
- **Bulgular maskeli raporlanır.** Tespit edilen PII, raporda/loglarda/örneklerde ham çoğaltılmaz; skill bir sızıntı vektörüne dönüşmemelidir.
- **Profil çıkarma yok.** Bu skill gerçek kişileri tanımlama, zenginleştirme veya izleme için kullanılmaz; amacı savunmadır.
- **"İlk/en iyi" iddiası yok.** Yanlış-pozitif kaçınılmazdır; checksum'sız tespitler "olası" olarak sunulur, sayılar abartılmaz.
- **Ölçek sınırı.** NER ve semantik katman Türkçe için tam kapsama garanti etmez; kritik ürünlerde insan gözden geçirmesi zorunludur.
