# nashaat20h
Generated and deployed with APEXGODLY Coder

## خطوات التثبيت والتشغيل

### المتطلبات

- Python 3.10 أو أحدث
- Docker وDocker Compose (اختياريان للتشغيل بالحاويات)

### التثبيت محليًا

من مجلد المشروع، أنشئ بيئة افتراضية وفعّلها ثم ثبّت الحزم:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e .
```

في Windows فعّل البيئة الافتراضية باستخدام:

```powershell
.venv\Scripts\Activate.ps1
```

### الإعداد

مفاتيح الخدمات الخارجية اختيارية؛ تعمل الخدمات التي تتطلب مفتاحًا فقط عند ضبطه. انسخ ملف الإعداد النموذجي، ثم أضف المفاتيح التي تملكها إلى `.env`:

```bash
cp env.example .env
```

### تشغيل واجهة الويب

```bash
osintx serve
```

افتح `http://127.0.0.1:8000` في المتصفح. لإتاحة الخدمة على واجهات الشبكة الأخرى استخدم `osintx serve --host 0.0.0.0`.

### استخدام سطر الأوامر

```bash
osintx providers
osintx scan example.com --type domain
osintx scan user@example.com --type email --output report.json
```

للاطلاع على جميع الخيارات:

```bash
osintx --help
osintx scan --help
```

### التشغيل باستخدام Docker

أنشئ ملف `.env` كما هو موضح أعلاه، ثم شغّل:

```bash
docker compose up --build
```

افتح `http://127.0.0.1:8000`. لإيقاف الحاوية استخدم `Ctrl+C`، أو شغّل `docker compose down` في نافذة طرفية أخرى.
