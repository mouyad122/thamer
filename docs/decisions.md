# القرارات والتعارضات بين الوثيقة النظرية والبرومبت التنفيذي

طبقًا لتعليمات المستخدم: عند تعارض ملفات المشروع النظري مع البرومبت التنفيذي، الأولوية دائمًا
لعمل النظام الحقيقي وللمتطلبات الصريحة في البرومبت. هذا الملف يوثق كل تعارض والقرار المتخذ.

## 1. لغة/إطار التطبيق
- **الوثيقة النظرية:** Python 3 + Django + MySQL + BeautifulSoup/Requests + ReportLab.
- **البرومبت التنفيذي:** Next.js (App Router) + TypeScript + Tailwind + Prisma + Playwright.
- **القرار:** التنفيذ بـ Next.js/TypeScript كما هو صريح في البرومبت. الوثيقة النظرية تُستخدم فقط
  كمرجع للمفاهيم والمتطلبات (crawler, scanner, report engine, DB schema)، وليست إلزامًا تقنيًا.

## 2. الفحص النشط (Active Scanning / Payload Injection)
- **الوثيقة النظرية والعرض:** حقن Payloads فعلية لـ SQL Injection وXSS وCommand Injection ضمن
  حقول النماذج (Active Scanning هو جزء أساسي من الأهداف والمنهجية).
- **البرومبت التنفيذي:** يمنع منعًا باتًا استخدام Payloads هجومية؛ يقتصر الفحص على: فحوصات
  Passive (Headers, TLS, Cookies, CORS, HTML security misconfigurations) + OWASP ZAP **Baseline
  (Passive) Scan فقط**، بدون Active Scan حقيقي في النسخة الأساسية.
- **القرار:** الأولوية لأمان النظام وعدم تنفيذ هجمات فعلية على مواقع لا يملكها الفريق بالضرورة
  (لا يوجد نظام توثيق ملكية نطاق في هذا البرومبت المبسّط). تم تنفيذ فحوصات Passive فقط + ZAP
  Baseline. هذا التعارض موجود بطبيعته بين مشروع أكاديمي نظري افتراضي (Django/Active) ومشروع فعلي
  آمن قابل للتشغيل بدون إذن موثق لكل نطاق. تم توثيقه هنا صراحة كما طلب المستخدم بدل حذفه بصمت.

## 3. اكتشاف النماذج تحديدًا (Form-Specific Crawling)
- **الوثيقة:** التركيز الأساسي هو اكتشاف Forms وفحصها (Web Form Security Check).
- **البرومبت التنفيذي:** يطلب فحص الصفحة الرئيسية فقط (لا crawler كامل متعدد الصفحات)، ضمن بند
  "HTML Security Checks" الذي يشمل فحص النماذج على الصفحة المفحوصة (password over HTTP, mixed
  content, CSRF-relevant attributes) دون بناء crawler عام متعدد الصفحات.
- **القرار:** تنفيذ فحص النماذج (forms) الموجودة في الصفحة الرئيسية المفحوصة فقط، دون crawler
  متعدد المستويات، حفاظًا على البساطة المطلوبة صراحة في البرومبت ("مشروع جامعة بسيط... لا تنشئ
  صفحات أو معمارية غير ضرورية").

## 4. نظام المستخدمين والصلاحيات (Users / Admin / RBAC)
- **الوثيقة:** تذكر users table بأدوار (admin/user)، Use Case لتسجيل الدخول ولوحة Admin.
- **البرومبت التنفيذي:** يمنع صراحة: تسجيل دخول، حسابات، لوحة إدارة، فرق/مؤسسات.
- **القرار:** لا تسجيل دخول ولا لوحة إدارة إطلاقًا، تنفيذًا صريحًا للبرومبت. جدول `User` من الوثيقة
  حُذف بالكامل من تصميم قاعدة البيانات الفعلي.

## 5. قاعدة البيانات
- **الوثيقة:** MySQL بست جداول (users, scans, vulnerabilities, scan_settings, reports,
  vuln_references).
- **البرومبت التنفيذي:** PostgreSQL أو SQLite + Prisma، بثلاث جداول فقط (Scan, Finding, Report).
- **القرار:** SQLite + Prisma لتبسيط النشر والتطوير المحلي (لا حاجة لخادم DB منفصل في العرض
  الجامعي)، مع إمكانية التبديل لـ PostgreSQL عبر تغيير `DATABASE_URL` و`provider` في
  `schema.prisma` فقط عند النشر الفعلي على Vercel (SQLite لا يعمل على Vercel serverless بسبب عدم
  وجود filesystem دائم؛ هذا موثق في `docs/deployment.md`).

## 6. مخطط ER وجداول `scan_settings` / `vuln_references`
- **الوثيقة:** تفصل `scan_settings` و`vuln_references` كجداول مستقلة.
- **القرار:** تم دمج إعدادات الفحص داخل حقول `Scan` نفسها (لا حاجة لجدول منفصل لعدد محدود من
  الإعدادات)، ودُمجت المراجع الخارجية كحقل `remediation`/`owaspCategory`/`cweId` نصي داخل
  `Finding` بدل جدول علاقات منفصل، تبسيطًا كما يطلب البرومبت صراحة ("لا تنشئ جداول غير ضرورية").

## 7. تعارض جديد اكتُشف أثناء التنفيذ: SSRF Protection مقابل فحص Juice Shop محليًا
- **البرومبت التنفيذي يطلب الاثنين معًا:** (أ) منع صريح وقوي لأي هدف على شبكة داخلية/loopback
  (بما فيها `172.16.0.0/12` التي تقع فيها معظم شبكات Docker الافتراضية)، و(ب) القدرة الفعلية على
  فحص OWASP Juice Shop محليًا عبر docker-compose أثناء العرض أمام الدكتور.
- **التعارض:** حماية SSRF الصارمة كما هي مطلوبة تمنع بالضرورة الوصول لأي عنوان على شبكة Docker
  الداخلية (وهي شبكة خاصة ضمن المدى المحظور)، مما يمنع فعليًا فحص Juice Shop أو أي بيئة اختبار محلية.
- **القرار:** أضيف متغير بيئة اختياري `SCAN_ALLOW_PRIVATE_NETWORKS` (افتراضيًا `false`). عندما يكون
  `false` (الوضع الافتراضي والموصى به لأي نشر فعلي)، تبقى كل حمايات SSRF فعالة بالكامل كما هي
  موثقة في [lib/url-validation.ts](../lib/url-validation.ts). عندما يُضبط صراحة إلى `true` (فقط في
  بيئة `.env` المحلية أثناء العرض الجامعي)، يُسمح باستهداف الشبكات الخاصة/localhost لغرض فحص بيئات
  اختبار محلية مثل Juice Shop، مع بقاء حظر عناوين Cloud Metadata (`169.254.169.254`) فعالًا دائمًا
  بلا استثناء حتى في هذا الوضع. تم توثيق هذا بوضوح في `.env.example` وسيُشرح أيضًا في
  `docs/testing.md` و`docs/deployment.md` كـ"غير آمن إطلاقًا لأي نشر متاح على الإنترنت العام".

## 8. مجلد ملفات PDF النظرية غير موجود
- **الوضع:** البرومبت يفترض وجود `thamer project-docs/` بملفات PDF. لم يوجد هذا المجلد ولا أي PDF
  في مجلد المشروع وقت التنفيذ.
- **القرار:** تم استخدام `Web From Security Check.pptx` و`نسخة من Graduation project.docx`
  الموجودين فعليًا في مجلد المشروع كبديل، وتوثيق ذلك بوضوح في
  [docs/pdf-requirements.md](pdf-requirements.md) بدل التخمين أو الانتظار. لم يُحذف أي متطلب من
  هذين الملفين دون توثيق (انظر قسم "أجزاء تعذر استخراجها" في نفس الملف).

## 9. جولة تصحيح دقة التحليل والـScoring (بعد أول فحص حقيقي)
بعد أول فحص فعلي (github.com) ظهرت أخطاء تصنيف حقيقية أُصلحت دون إعادة بناء المعمارية:

- **CSP:** كان الفحص يبحث عن `unsafe-inline`/`unsafe-eval` داخل نص الـCSP كاملًا، فأنتج Finding
  خاطئة تقول إن الموقع يسمح بتنفيذ سكربت inline/eval بناءً على `unsafe-inline` الموجودة فقط داخل
  `style-src`. تم استبداله بمحلل CSP حقيقي لكل directive على حدة
  ([lib/checks/csp.ts](../lib/checks/csp.ts)) يفرّق بين `script-src` و`style-src` مع دعم وراثة
  `default-src`، ويعرض السياسة الكاملة فقط داخل قسم "Raw Evidence" القابل للتوسيع.
- **OWASP:** أُنشئ ملف مركزي واحد ([lib/owasp.ts](../lib/owasp.ts)) يحوّل كل تصنيف قديم (2021) إلى
  تسمية 2025. `Security Misconfiguration` و`Broken Access Control` مؤكدتان من المستخدم؛ باقي
  الفئات (Cryptographic Failures، إلخ) اعتُمدت على أفضل معرفة متاحة دون التحقق من مصدر حي
  (لا يوجد اتصال إنترنت في بيئة التنفيذ وقتها) — يُنصح بمراجعتها مقابل owasp.org/Top10/2025 قبل أي
  استخدام رسمي.
- **CWE:** أُزيل `CWE-1021` من كل مكان لا يتعلق بـClickjacking فعليًا (CSP, COOP, CORP)، وأُزيل
  `CWE-693` كقيمة افتراضية لأي Header مفقود. عند عدم وجود CWE دقيقة، القيمة الآن `undefined` وتُعرض
  كـ"Not mapped" بدل تخمين رقم خاطئ.
- **Cookies:** أُضيف تصنيف حساسية بالاسم فقط (`SENSITIVE_AUTH` مقابل `FUNCTIONAL`/`LIKELY_SENSITIVE`/
  `UNKNOWN` في [lib/checks/cookies.ts](../lib/checks/cookies.ts)). فقط الكوكيز المؤكدة كجلسة/مصادقة
  تُخصم من الدرجة؛ البقية تُسجَّل كملاحظة `REQUIRES_MANUAL_REVIEW` بدون أي خصم.
- **Headers دفاعية (COOP/CORP/Permissions-Policy):** أصبحت دائمًا `INFORMATIONAL`/`INFORMATIONAL_ONLY`
  (خصم = صفر)، مع فصل صريح بين تأكيد الملاحظة (الهيدر غائب فعلًا) وعدم إثبات قابلية الاستغلال، عبر
  حقل `exploitability: "NOT_DEMONSTRATED"` الجديد في `RawFinding`.
- **حالة الفحص الجزئي:** أُعيدت تسمية `PARTIALLY_COMPLETED` إلى `PARTIAL` في كل الطبقات (Prisma enum،
  الأنواع، الواجهة، الـPDF)، مع إضافة "Provisional Automated Security Score" و"Scan Coverage"
  كقيمة منفصلة تمامًا عن الدرجة (نسبة الفحوصات المكتملة فعليًا، وليست مبنية على عدد الـFindings).
- **سبب فشل ZAP الحقيقي:** لم يُعثر على أي Timeout ثابت بقيمة 225 ثانية في الكود (لا `225` نصية ولا
  ثابت زمني يساويها في `lib/worker-client.ts` أو غيره). الاحتمال الأرجح تقنيًا هو تراكم عدة مهلات
  تسلسلية حقيقية (كل فحص فرعي له timeout خاص به 5–10 ثوانٍ، بالإضافة إلى مهلة استدعاء ZAP القديمة
  BEFORE هذا الإصلاح والتي كانت تنتظر 120 ثانية كاملة قبل اعتبار الـworker غير قابل للوصول) — لم
  يكن هناك أي رمز يفسّر سبب الفشل، فقط `null`/"Not Tested" عام. تم استبداله بالكامل بنتيجة تنفيذ
  ZAP بنيوية حقيقية (`ZapExecutionResult` في [lib/types.ts](../lib/types.ts) و
  [lib/worker-client.ts](../lib/worker-client.ts)) تسجل السبب الدقيق
  (`ZAP_WORKER_NOT_CONFIGURED`/`ZAP_WORKER_UNREACHABLE`/`ZAP_START_FAILED`/`ZAP_TIMEOUT`/
  `ZAP_REPORT_MISSING`/`ZAP_INVALID_RESPONSE`) والتوقيتات الحقيقية، بدل رفع قيمة الـTimeout بلا فهم
  السبب الجذري.
