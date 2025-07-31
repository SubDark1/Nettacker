OWASP Nettacker Clone
بواسطة SayerLinux (SaudiSayer@gmail.com)

# طريقة التثبيت

1. قم بتثبيت Python 3.x على جهازك
2. قم بتنزيل أو استنساخ المستودع:
   ```
   git clone https://github.com/yourusername/nettacker.git
   cd nettacker
   ```
3. قم بتثبيت المتطلبات:
   ```
   pip install -r requirements.txt
   ```

# طريقة الاستخدام

الأداة تدعم العديد من وحدات الفحص المختلفة:

1. فحص المنافذ:
   ```
   python nettacker.py -H example.com -m port
   ```

2. فحص WordPress:
   ```
   python nettacker.py -H example.com -m wpscan
   ```

3. فحص الثغرات:
   ```
   python nettacker.py -H example.com -m vulnerability
   ```

4. فحص المجلدات:
   ```
   python nettacker.py -H example.com -m directory
   ```

5. فحص الخدمات:
   ```
   python nettacker.py -H example.com -m service
   ```

الخيارات المتاحة:
-H, --host        عنوان الهدف المراد فحصه
-m, --module      وحدة الفحص المراد استخدامها
-p, --ports       المنافذ المراد فحصها (افتراضياً: المنافذ الشائعة)
-t, --timeout     مهلة الاتصال (افتراضياً: 3 ثوانٍ)
-o, --output      مسار ملف النتائج (افتراضياً: results.txt)

ملاحظات:
- يتم حفظ نتائج الفحص تلقائياً في مجلد reports/
- تأكد من استخدام الأداة بشكل قانوني وأخلاقي
- لا تستخدم الأداة على أهداف غير مصرح لك بفحصها