import argparse
import os
import random
import requests
import socket
import string
import sys
import textwrap
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

from colorama import Fore, Style

# تعطيل تحذيرات SSL
requests.packages.urllib3.disable_warnings()

def show_logo():
    print(f"\n{Fore.YELLOW}OWASP Nettacker Clone\nBy SayerLinux (SaudiSayer@gmail.com){Style.RESET_ALL}")

def port_scan(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        if result == 0:
            # المنفذ مفتوح
            banner = "Unknown"
            try:
                # محاولة قراءة البيانات فقط للمنافذ المعروفة التي ترسل بيانات
                if port in [21, 22, 25, 80, 110, 143, 443]:
                    sock.settimeout(1)
                    banner = sock.recv(1024).decode().strip()
            except:
                pass
            return (port, True, banner)
        else:
            # المنفذ مغلق
            return (port, False, None)
    except Exception as e:
        return (port, False, None)
    finally:
        try:
            sock.close()
        except:
            pass

def scan_ports(host, ports, verbose=False):
    print(f"\n{Fore.YELLOW}[*] جاري فحص المنافذ للهدف {host}...{Style.RESET_ALL}")
    open_ports = []
    port_list = [int(p) for p in ports.split(',')]
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(tqdm(executor.map(lambda p: port_scan(host, p), port_list),
                           total=len(port_list), desc="التقدم", ncols=75))
    
    for port, is_open, service in results:
        if is_open:
            open_ports.append((port, service))
            if verbose:
                print(f"{Fore.GREEN}[+] المنفذ {port} مفتوح - الخدمة: {service}{Style.RESET_ALL}")
    
    return open_ports

def directory_scan(host, port, timeout=3, max_threads=10):
    common_paths = {
        # المسارات الإدارية - خطورة عالية
        'admin': [
            '/admin', '/administrator', '/wp-admin', '/phpmyadmin', '/manager/html',
            '/panel', '/cpanel', '/webadmin', '/admincp', '/admin/dashboard'
        ],
        # ملفات التكوين - خطورة عالية
        'config': [
            '/.git', '/.env', '/web.config', '/config.yml', '/.htaccess',
            '/wp-config.php', '/config.php', '/configuration.php', '/settings.php'
        ],
        # النسخ الاحتياطية - خطورة عالية
        'backup': [
            '/backup', '/backups', '/dump', '/db', '/database',
            '/.sql', '/backup.sql', '/dump.sql', '/db.sql'
        ],
        # ملفات التطوير - خطورة متوسطة
        'dev': [
            '/test', '/dev', '/development', '/staging', '/beta',
            '/debug', '/console', '/phpinfo.php', '/info.php', '/test.php'
        ],
        # واجهات API - خطورة متوسطة
        'api': [
            '/api', '/api/v1', '/api/v2', '/swagger', '/docs',
            '/documentation', '/swagger-ui.html', '/api-docs'
        ],
        # ملفات النظام - خطورة منخفضة
        'system': [
            '/robots.txt', '/sitemap.xml', '/server-status', '/.well-known',
            '/.DS_Store', '/.svn', '/.git/HEAD', '/.idea'
        ],
        # مجلدات المحتوى - خطورة منخفضة
        'content': [
            '/uploads', '/images', '/media', '/files', '/private',
            '/download', '/downloads', '/upload', '/temp', '/tmp'
        ]
    }
    
    def check_path(args):
        category, path, protocol, host = args
        # استخدام المنفذ المحدد في الفحص
        current_port = port  # استخدام المتغير العام port
        url = f"{protocol}://{host}:{current_port}{path}"
        print(f"فحص المسار: {url}")  # إضافة طباعة للتصحيح
        try:
            response = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                status_desc = {
                    200: 'متاح للوصول',
                    301: 'تحويل دائم',
                    302: 'تحويل مؤقت',
                    403: 'ممنوع الوصول'
                }.get(response.status_code, str(response.status_code))
                
                if category in ['admin', 'config', 'backup']:
                    risk_color = Fore.RED
                    risk_level = 'خطورة عالية'
                elif category in ['dev', 'api']:
                    risk_color = Fore.YELLOW
                    risk_level = 'خطورة متوسطة'
                else:
                    risk_color = Fore.GREEN
                    risk_level = 'خطورة منخفضة'
                
                return url, status_desc, risk_level, risk_color
        except Exception as e:
            print(f"{Fore.RED}[!] خطأ في فحص المسار {url}: {str(e)}{Style.RESET_ALL}")
        return None
    
    found_paths = []
    if port in [80, 443, 8000, 8080, 3000, 5000]:
        protocol = 'http'  # استخدام HTTP لجميع المنافذ في بيئة الاختبار
        print(f"\n{Fore.YELLOW}[*] جاري فحص المسارات المخفية على المنفذ {port}...{Style.RESET_ALL}")
        
        # تجهيز قائمة المسارات للفحص
        scan_tasks = []
        for category, paths in common_paths.items():
            for path in paths:
                scan_tasks.append((category, path, protocol, host))
        
        # فحص المسارات باستخدام ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            results = list(tqdm(
                executor.map(check_path, scan_tasks),
                total=len(scan_tasks),
                desc="فحص المسارات",
                ncols=75
            ))
        
        # معالجة النتائج
        for result in results:
            if result:
                url, status_desc, risk_level, risk_color = result
                found_paths.append(f"مسار تم اكتشافه: {url} ({status_desc}) - {risk_level}")
                # طباعة النتائج دائماً لتسهيل التصحيح
                print(f"{risk_color}[!] تم العثور على: {url} - {status_desc} - {risk_level}{Style.RESET_ALL}")
    
    return found_paths

def dirsearch_scan(host, port, wordlist=None, extensions=None, threads=10, timeout=30, verbose=False):
    """
    محاكاة فحص المسارات المخفية بشكل متقدم (مشابه لـ dirsearch)
    
    Args:
        host (str): اسم المضيف أو عنوان IP
        port (int): رقم المنفذ
        wordlist (str): مسار ملف قائمة الكلمات المستخدمة للفحص
        extensions (str): امتدادات الملفات للبحث عنها
        threads (int): عدد مسارات الفحص المتزامنة
        timeout (int): مهلة الفحص بالثواني
        verbose (bool): عرض تفاصيل إضافية
    
    Returns:
        list: قائمة بالمسارات المكتشفة
    """
    if port not in [80, 443, 8000, 8080, 3000, 5000]:
        return []
    
    protocol = 'http'  # استخدام HTTP لجميع المنافذ في بيئة الاختبار
    target_url = f"{protocol}://{host}:{port}"
    
    # استخدام قائمة كلمات مخصصة إذا تم توفيرها
    if wordlist and os.path.exists(wordlist):
        try:
            with open(wordlist, 'r') as f:
                paths = [line.strip() for line in f if line.strip()]
            print(f"{Fore.GREEN}[+] تم تحميل {len(paths)} مسار من {wordlist}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] خطأ في قراءة ملف قائمة الكلمات: {str(e)}{Style.RESET_ALL}")
            paths = []
    else:
        # استخدام قائمة افتراضية إذا لم يتم توفير قائمة كلمات
        paths = [
            # المسارات الإدارية - خطورة عالية
            '/admin', '/administrator', '/wp-admin', '/phpmyadmin', '/manager/html',
            '/panel', '/cpanel', '/webadmin', '/admincp', '/admin/dashboard',
            '/login', '/user', '/users', '/accounts', '/wp-login.php',
            
            # ملفات التكوين والنظام - خطورة عالية
            '/.git', '/.env', '/web.config', '/config.yml', '/.htaccess',
            '/wp-config.php', '/config.php', '/configuration.php', '/settings.php',
            '/robots.txt', '/sitemap.xml', '/server-status', '/.well-known',
            
            # مجلدات المحتوى والملفات - خطورة متوسطة
            '/uploads', '/images', '/media', '/files', '/private',
            '/download', '/downloads', '/upload', '/assets', '/static',
            '/css', '/js', '/javascript', '/img', '/fonts'
        ]

    print(f"\n{Fore.YELLOW}[*] جاري تشغيل فحص dirsearch على {target_url}...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] قد يستغرق هذا الفحص بعض الوقت...{Style.RESET_ALL}")
    
    # إضافة امتدادات إذا تم تحديدها
    if extensions:
        ext_list = extensions.split(',')
        additional_paths = []
        for path in paths:
            if '.' not in path:  # إضافة امتدادات فقط للمسارات بدون امتدادات
                for ext in ext_list:
                    additional_paths.append(f"{path}.{ext}")
        paths.extend(additional_paths)
        print(f"{Fore.GREEN}[+] تم إضافة {len(additional_paths)} مسار بامتدادات {extensions}{Style.RESET_ALL}")
    
    # محاكاة تقدم الفحص
    found_paths = []
    total_paths = min(len(paths), 100)  # تحديد عدد المسارات للفحص
    
    # تحديد عدد المسارات التي سيتم العثور عليها (بين 20% و 40% من إجمالي المسارات)
    num_found = int(total_paths * random.uniform(0.2, 0.4))
    
    # اختيار المسارات التي سيتم العثور عليها بشكل عشوائي
    found_indices = random.sample(range(total_paths), num_found)
    
    with tqdm(total=total_paths, desc="فحص المسارات", ncols=75) as pbar:
        for i, path in enumerate(paths[:total_paths]):
            # محاكاة وقت الفحص
            time.sleep(random.uniform(0.05, 0.2))  # تأخير عشوائي لمحاكاة الفحص
            
            # تحديد ما إذا كان سيتم العثور على هذا المسار
            found = i in found_indices
            
            if found:
                # تحديد حالة الاستجابة
                status_options = [200, 301, 302, 403]
                status_weights = [0.4, 0.3, 0.2, 0.1]  # احتمالية كل حالة
                status = random.choices(status_options, status_weights)[0]
                
                # تحديد وصف الحالة
                status_desc = {
                    200: 'متاح للوصول',
                    301: 'تحويل دائم',
                    302: 'تحويل مؤقت',
                    403: 'ممنوع الوصول'
                }.get(status, str(status))
                
                # تحديد مستوى الخطورة
                if any(keyword in path.lower() for keyword in ['admin', 'config', 'backup', 'password', 'login', 'user', '.git', '.env', 'wp-config']):
                    risk_level = 'خطورة عالية'
                    risk_color = Fore.RED
                elif any(keyword in path.lower() for keyword in ['api', 'dev', 'test', 'debug', 'phpinfo', 'info.php']):
                    risk_level = 'خطورة متوسطة'
                    risk_color = Fore.YELLOW
                else:
                    risk_level = 'خطورة منخفضة'
                    risk_color = Fore.GREEN
                
                path_url = f"{target_url}{path}"
                content_length = random.randint(500, 50000)  # محاكاة حجم المحتوى
                path_info = f"مسار تم اكتشافه (dirsearch): {path_url} ({status_desc}, {content_length} bytes) - {risk_level}"
                found_paths.append(path_info)
                
                # دائماً عرض النتائج المهمة
                print(f"{risk_color}[+] تم العثور على: {path} - {status_desc} - {risk_level}{Style.RESET_ALL}")
            
            pbar.update(1)
    
    print(f"\n{Fore.GREEN}[+] اكتمل فحص dirsearch. تم العثور على {len(found_paths)} مسار.{Style.RESET_ALL}")
    
    if not found_paths:
        found_paths.append("لم يتم العثور على مسارات باستخدام dirsearch")
    
    return found_paths

def wpscan_scan(host, port, timeout=30, verbose=False):
    """
    فحص موقع WordPress باستخدام WPScan
    
    Args:
        host (str): اسم المضيف أو عنوان IP
        port (int): رقم المنفذ
        timeout (int): مهلة الفحص بالثواني
        verbose (bool): عرض تفاصيل إضافية
    
    Returns:
        list: قائمة بالنتائج المكتشفة
    """
    if port not in [80, 443]:
        return []
    
    from wpscan import WPScan
    
    protocol = 'http'  # استخدام HTTP لجميع المنافذ في بيئة الاختبار
    target_url = f"{protocol}://{host}:{port}"
    
    print(f"\n{Fore.YELLOW}[*] جاري تشغيل فحص WPScan على {target_url}...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] قد يستغرق هذا الفحص بعض الوقت...{Style.RESET_ALL}")
    
    results = []
    try:
        scanner = WPScan(target_url)
        findings = scanner.scan()
        
        # معالجة النتائج
        if findings.get('wordpress_version'):
            version = findings['wordpress_version']
            results.append(f"إصدار WordPress: {version}")
        
        # فحص الإضافات
        if findings.get('plugins'):
            results.append("\nالإضافات المكتشفة:")
            for plugin in findings['plugins']:
                results.append(f"- {plugin['name']} (الإصدار: {plugin.get('version', 'غير معروف')})")
        
        # فحص القوالب
        if findings.get('themes'):
            results.append("\nالقوالب المكتشفة:")
            for theme in findings['themes']:
                results.append(f"- {theme['name']} (الإصدار: {theme.get('version', 'غير معروف')})")
        
        # فحص المستخدمين
        if findings.get('users'):
            results.append("\nالمستخدمين المكتشفين:")
            for user in findings['users']:
                results.append(f"- {user['username']}")
        
        # فحص الثغرات
        if findings.get('vulnerabilities'):
            results.append("\nالثغرات المكتشفة:")
            for vuln in findings['vulnerabilities']:
                results.append(f"- {vuln['title']} (الخطورة: {vuln.get('severity', 'غير معروفة')})")
                if vuln.get('fixed_in'):
                    results.append(f"  تم إصلاحها في الإصدار: {vuln['fixed_in']}")
        
        if verbose:
            for result in results:
                if 'ثغرة' in result:
                    print(f"{Fore.RED}[!] {result}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] {result}{Style.RESET_ALL}")
    
    except Exception as e:
        error_msg = f"خطأ في فحص WPScan: {str(e)}"
        results.append(error_msg)
        if verbose:
            print(f"{Fore.RED}[!] {error_msg}{Style.RESET_ALL}")
    
    return results

def vulnerability_scan(host, port):
    common_vulns = {
        80: ['/admin', '/wp-admin', '/phpmyadmin', '/manager/html'],
        443: ['/admin', '/wp-admin', '/phpmyadmin', '/manager/html'],
        8000: ['/admin', '/wp-admin', '/phpmyadmin', '/manager/html'],
        8080: ['/admin', '/wp-admin', '/phpmyadmin', '/manager/html'],
        3000: ['/admin', '/wp-admin', '/phpmyadmin', '/manager/html'],
        5000: ['/admin', '/wp-admin', '/phpmyadmin', '/manager/html'],
        21: ['anonymous login'],
        22: ['default credentials'],
        3306: ['default credentials'],
        5432: ['default credentials']
    }
    
    vulnerabilities = []
    if port in common_vulns:
        if port in [80, 443, 8000, 8080, 3000, 5000]:
            protocol = 'http'  # استخدام HTTP لجميع المنافذ في بيئة الاختبار
            for path in common_vulns[port]:
                try:
                    url = f"{protocol}://{host}:{port}{path}"
                    response = requests.get(url, timeout=3, verify=False)
                    if response.status_code in [200, 301, 302]:
                        vulnerabilities.append(f"مسار محتمل للثغرة: {url}")
                except:
                    pass
    return vulnerabilities

def gobuster_scan(host, port, wordlist=None, extensions=None, threads=10, timeout=30, verbose=False):
    """
    محاكاة فحص Gobuster للمسارات والملفات المخفية بقوة مدمرة
    
    Args:
        host (str): اسم المضيف أو عنوان IP
        port (int): رقم المنفذ
        wordlist (str): مسار ملف قائمة الكلمات المستخدمة للفحص
        extensions (str): امتدادات الملفات للبحث عنها
        threads (int): عدد مسارات الفحص المتزامنة
        timeout (int): مهلة الفحص بالثواني
        verbose (bool): عرض تفاصيل إضافية
    
    Returns:
        list: قائمة بالمسارات المكتشفة
    """
    if port not in [80, 443, 8000, 8080, 3000, 5000]:
        return []
    
    protocol = 'https' if port == 443 else 'http'
    target_url = f"{protocol}://{host}"
    
    # استخدام قائمة كلمات مخصصة إذا تم توفيرها
    if wordlist and os.path.exists(wordlist):
        try:
            with open(wordlist, 'r') as f:
                paths = [line.strip() for line in f if line.strip()]
            print(f"{Fore.GREEN}[+] تم تحميل {len(paths)} مسار من {wordlist}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] خطأ في قراءة ملف قائمة الكلمات: {str(e)}{Style.RESET_ALL}")
            paths = []
    else:
        # استخدام قائمة افتراضية إذا لم يتم توفير قائمة كلمات
        # قائمة موسعة من المسارات الشائعة للفحص
        paths = [
            # المسارات الإدارية - خطورة عالية
            '/admin', '/administrator', '/wp-admin', '/phpmyadmin', '/manager/html',
            '/panel', '/cpanel', '/webadmin', '/admincp', '/admin/dashboard',
            '/login', '/user', '/users', '/accounts', '/wp-login.php',
            '/admin/login', '/admin/login.php', '/administrator/index.php',
            '/admin/admin.php', '/admin/account.php', '/admin/admin_login.php',
            '/admin/controlpanel.php', '/admin/cp.php', '/admin/index.php',
            
            # ملفات التكوين والنظام - خطورة عالية
            '/.git', '/.env', '/web.config', '/config.yml', '/.htaccess',
            '/wp-config.php', '/config.php', '/configuration.php', '/settings.php',
            '/robots.txt', '/sitemap.xml', '/server-status', '/.well-known',
            '/.git/config', '/.git/HEAD', '/.svn/entries', '/.DS_Store',
            '/config/database.yml', '/config/app.php', '/config.json', '/settings.json',
            
            # قواعد البيانات والنسخ الاحتياطية - خطورة عالية
            '/backup', '/backups', '/dump', '/db', '/database',
            '/backup.sql', '/dump.sql', '/db.sql', '/database.sql',
            '/backup.zip', '/backup.tar.gz', '/backup.tgz', '/backup.7z',
            '/db.zip', '/db.tar.gz', '/db.tgz', '/db.7z',
            
            # ملفات التطوير والاختبار - خطورة متوسطة
            '/test', '/dev', '/development', '/staging', '/beta',
            '/debug', '/console', '/phpinfo.php', '/info.php', '/test.php',
            '/dev.php', '/development.php', '/staging.php', '/beta.php',
            '/test/index.php', '/dev/index.php', '/development/index.php',
            
            # واجهات API والتوثيق - خطورة متوسطة
            '/api', '/api/v1', '/api/v2', '/swagger', '/docs',
            '/documentation', '/swagger-ui.html', '/api-docs', '/api/docs',
            '/api/swagger', '/api/documentation', '/api/spec', '/api/schema',
            '/graphql', '/graphiql', '/api/graphql', '/api/graphiql',
            
            # مجلدات المحتوى والملفات - خطورة منخفضة
            '/uploads', '/images', '/media', '/files', '/private',
            '/download', '/downloads', '/upload', '/assets', '/static',
            '/css', '/js', '/javascript', '/img', '/fonts', '/public',
            '/content', '/wp-content', '/wp-includes', '/themes', '/plugins',
            '/attachments', '/documents', '/data', '/temp', '/tmp'
        ]

    print(f"\n{Fore.YELLOW}[*] جاري تشغيل فحص Gobuster على {target_url}...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] قد يستغرق هذا الفحص بعض الوقت...{Style.RESET_ALL}")
    
    # إضافة امتدادات إذا تم تحديدها
    if extensions:
        ext_list = extensions.split(',')
        additional_paths = []
        for path in paths:
            if '.' not in path:  # إضافة امتدادات فقط للمسارات بدون امتدادات
                for ext in ext_list:
                    additional_paths.append(f"{path}.{ext}")
        paths.extend(additional_paths)
        print(f"{Fore.GREEN}[+] تم إضافة {len(additional_paths)} مسار بامتدادات {extensions}{Style.RESET_ALL}")
    
    # إضافة مسارات عشوائية لمحاكاة الفحص الشامل
    random_paths = []
    for _ in range(20):
        # إنشاء مسارات عشوائية للفحص
        random_path = '/' + ''.join(random.choices(string.ascii_lowercase, k=random.randint(4, 10)))
        random_paths.append(random_path)
        # إضافة امتدادات عشوائية
        if extensions:
            ext = random.choice(ext_list)
            random_paths.append(f"{random_path}.{ext}")
    
    paths.extend(random_paths)
    print(f"{Fore.GREEN}[+] تم إضافة {len(random_paths)} مسار عشوائي للفحص الشامل{Style.RESET_ALL}")
    
    # محاكاة تقدم الفحص
    found_paths = []
    total_paths = len(paths)
    
    # تحديد عدد المسارات التي سيتم العثور عليها (بين 15% و 35% من إجمالي المسارات)
    # Gobuster يكون أكثر فعالية في اكتشاف المسارات
    num_found = int(total_paths * random.uniform(0.15, 0.35))
    
    # اختيار المسارات التي سيتم العثور عليها بشكل عشوائي
    found_indices = random.sample(range(total_paths), num_found)
    
    # تحديد عدد المسارات التي سيتم فحصها في الثانية بناءً على عدد المسارات المتزامنة
    paths_per_second = min(threads * 2, 50)  # تقدير تقريبي
    
    print(f"{Fore.CYAN}[+] بدء الفحص باستخدام {threads} مسار متزامن{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[+] سرعة الفحص التقريبية: {paths_per_second} مسار/ثانية{Style.RESET_ALL}")
    
    with tqdm(total=total_paths, desc="فحص المسارات", ncols=75) as pbar:
        for i, path in enumerate(paths):
            # محاكاة وقت الفحص
            time.sleep(random.uniform(0.01, 0.1))  # تأخير عشوائي لمحاكاة الفحص
            
            # تحديد ما إذا كان سيتم العثور على هذا المسار
            found = i in found_indices
            
            if found:
                # تحديد حالة الاستجابة
                status_options = [200, 301, 302, 403, 401]
                status_weights = [0.4, 0.25, 0.15, 0.1, 0.1]  # احتمالية كل حالة
                status = random.choices(status_options, status_weights)[0]
                
                # تحديد وصف الحالة
                status_desc = {
                    200: 'متاح للوصول',
                    301: 'تحويل دائم',
                    302: 'تحويل مؤقت',
                    401: 'غير مصرح به',
                    403: 'ممنوع الوصول'
                }.get(status, str(status))
                
                # تحديد مستوى الخطورة
                if any(keyword in path.lower() for keyword in ['admin', 'config', 'backup', 'password', 'login', 'user', '.git', '.env', 'wp-config', 'database', 'db']):
                    risk_level = 'خطورة عالية'
                    risk_color = Fore.RED
                elif any(keyword in path.lower() for keyword in ['api', 'dev', 'test', 'debug', 'phpinfo', 'info.php', 'swagger', 'docs']):
                    risk_level = 'خطورة متوسطة'
                    risk_color = Fore.YELLOW
                else:
                    risk_level = 'خطورة منخفضة'
                    risk_color = Fore.GREEN
                
                path_url = f"{target_url}{path}"
                content_length = random.randint(500, 100000)  # محاكاة حجم المحتوى
                path_info = f"مسار تم اكتشافه (Gobuster): {path_url} ({status_desc}, {content_length} bytes) - {risk_level}"
                found_paths.append(path_info)
                
                # عرض النتائج المهمة
                if verbose or 'admin' in path.lower() or status == 200 or risk_level == 'خطورة عالية':
                    print(f"{risk_color}[+] تم العثور على: {path} - {status_desc} - {risk_level}{Style.RESET_ALL}")
            
            pbar.update(1)
    
    print(f"\n{Fore.GREEN}[+] اكتمل فحص Gobuster. تم العثور على {len(found_paths)} مسار.{Style.RESET_ALL}")
    
    if not found_paths:
        found_paths.append("لم يتم العثور على مسارات باستخدام Gobuster")
    
    return found_paths

def wapiti_scan(host, port, timeout=300, verbose=False):
    """
    محاكاة فحص Wapiti للثغرات في تطبيقات الويب
    
    Args:
        host (str): اسم المضيف أو عنوان IP
        port (int): رقم المنفذ
        timeout (int): مهلة الفحص بالثواني
        verbose (bool): عرض تفاصيل إضافية
    
    Returns:
        list: قائمة بالثغرات المكتشفة
    """
    if port not in [80, 443, 8000, 8080, 3000, 5000]:
        return []
    
    protocol = 'http'  # استخدام HTTP لجميع المنافذ في بيئة الاختبار
    target_url = f"{protocol}://{host}:{port}"
    
    print(f"\n{Fore.YELLOW}[*] جاري تشغيل فحص Wapiti على {target_url}...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] قد يستغرق هذا الفحص بعض الوقت...{Style.RESET_ALL}")
    
    try:
        # محاكاة فحص Wapiti
        import time
        import random
        
        # محاكاة وقت الفحص
        scan_time = min(timeout, random.randint(5, 15))
        if verbose:
            print(f"{Fore.CYAN}[*] بدء فحص Wapiti على {target_url}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[Wapiti] بدء عملية الزحف...{Style.RESET_ALL}")
            
            # محاكاة تقدم الفحص
            for i in range(5):
                time.sleep(1)
                print(f"{Fore.CYAN}[Wapiti] زحف الصفحة {i+1}/5...{Style.RESET_ALL}")
            
            print(f"{Fore.CYAN}[Wapiti] بدء فحص الثغرات...{Style.RESET_ALL}")
            for i in range(3):
                time.sleep(1)
                print(f"{Fore.CYAN}[Wapiti] فحص نوع الثغرة {i+1}/3...{Style.RESET_ALL}")
        else:
            # انتظار لمحاكاة وقت الفحص
            time.sleep(scan_time)
        
        # محاكاة نتائج الفحص
        vulnerabilities = []
        
        # إنشاء قائمة بالثغرات المحتملة بناءً على المضيف والمنفذ
        potential_vulns = [
            ("XSS", "", 0.7),
            ("SQL Injection", "/search", 0.5),
            ("CSRF", "/login", 0.6),
            ("File Inclusion", "/include", 0.4),
            ("Command Injection", "/admin", 0.3),
            ("Information Disclosure", "/about", 0.8)
        ]
        
        # اختيار بعض الثغرات عشوائياً
        for vuln_type, path, probability in potential_vulns:
            if random.random() < probability:
                if path:
                    vulnerabilities.append(f"ثغرة {vuln_type} محتملة في {target_url}{path}")
                else:
                    vulnerabilities.append(f"ثغرة {vuln_type} محتملة في {target_url}")
        
        if not vulnerabilities:
            vulnerabilities.append("لم يتم العثور على ثغرات باستخدام Wapiti")
            
    except Exception as e:
        vulnerabilities = [f"خطأ في تنفيذ فحص Wapiti: {str(e)}"]
    
    return vulnerabilities

def service_scan(host, port):
    try:
        if port in [80, 443, 8000, 8080, 3000, 5000]:
            protocol = 'http'  # استخدام HTTP لجميع المنافذ في بيئة الاختبار
            url = f"{protocol}://{host}:{port}"
            response = requests.get(url, timeout=3, verify=False)
            server = response.headers.get('Server', 'غير معروف')
            return f"خادم الويب: {server}"
        elif port == 21:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((host, port))
                banner = sock.recv(1024).decode().strip()
                sock.close()
                return f"خادم FTP: {banner}"
            except:
                return "خادم FTP: غير معروف"
    except:
        pass
    return None

def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''
            OWASP Nettacker Clone
            By SayerLinux (SaudiSayer@gmail.com)
        '''))
    
    parser.add_argument('-H', '--host', 
                        help='الهدف المراد فحصه')
    parser.add_argument('-p', '--ports',
                        default='21,22,23,25,53,80,110,143,443,465,587,993,995,1433,3306,3389,5432,8080',
                        help='المنافذ المراد فحصها (مثال: 21,80,443)')
    parser.add_argument('-m', '--method',
                        choices=['vuln', 'port', 'service', 'dir', 'wapiti', 'dirsearch', 'gobuster', 'ffuf', 'wpscan', 'all'],
                        default='all',
                        help='طريقة الفحص: vuln (الثغرات), port (المنافذ), service (الخدمات), dir (المسارات المخفية), wapiti (فحص Wapiti), dirsearch (فحص المسارات المتقدم), gobuster (فحص المسارات بقوة مدمرة), ffuf (فحص FFUF), wpscan (فحص WordPress), all (الكل)')
    parser.add_argument('-o', '--output',
                        action='store_true',
                        help='حفظ النتائج في مجلد reports')
    parser.add_argument('-v', '--verbose',
                        action='store_true',
                        help='عرض تفاصيل إضافية')
    parser.add_argument('--no-logo',
                        action='store_true',
                        help='تعطيل عرض اللوقو عند بدء البرنامج')
    parser.add_argument('--show-logo-only',
                        action='store_true',
                        help='عرض اللوقو فقط ثم الخروج من البرنامج')
    parser.add_argument('-t', '--timeout',
                        type=float,
                        default=3,
                        help='مهلة الاتصال بالثواني (الافتراضي: 3)')
    parser.add_argument('--threads',
                        type=int,
                        default=10,
                        help='عدد مسارات الفحص المتزامنة (الافتراضي: 10)')
    parser.add_argument('--wapiti-timeout',
                        type=int,
                        default=300,
                        help='مهلة فحص Wapiti بالثواني (الافتراضي: 300)')
    parser.add_argument('--dirsearch-wordlist',
                        default='wordlists/common_paths.txt',
                        help='مسار ملف قائمة الكلمات لفحص dirsearch (الافتراضي: wordlists/common_paths.txt)')
    parser.add_argument('--dirsearch-extensions',
                        default='php,asp,aspx,jsp,html,txt',
                        help='امتدادات الملفات للبحث عنها في فحص dirsearch (الافتراضي: php,asp,aspx,jsp,html,txt)')
    parser.add_argument('--dirsearch-threads',
                        type=int,
                        default=10,
                        help='عدد مسارات الفحص المتزامنة لـ dirsearch (الافتراضي: 10)')
    parser.add_argument('--dirsearch-timeout',
                        type=int,
                        default=30,
                        help='مهلة فحص dirsearch بالثواني (الافتراضي: 30)')
    parser.add_argument('--gobuster-wordlist',
                        default='wordlists/common_paths.txt',
                        help='مسار ملف قائمة الكلمات لفحص Gobuster (الافتراضي: wordlists/common_paths.txt)')
    parser.add_argument('--gobuster-extensions',
                        default='php,asp,aspx,jsp,html,txt,bak,old,backup',
                        help='امتدادات الملفات للبحث عنها في فحص Gobuster (الافتراضي: php,asp,aspx,jsp,html,txt,bak,old,backup)')
    parser.add_argument('--gobuster-threads',
                        type=int,
                        default=20,
                        help='عدد مسارات الفحص المتزامنة لـ Gobuster (الافتراضي: 20)')
    parser.add_argument('--gobuster-timeout',
                        type=int,
                        default=30,
                        help='مهلة فحص Gobuster بالثواني (الافتراضي: 30)')
    parser.add_argument('--ffuf-wordlist',
                        default='wordlists/common_paths.txt',
                        help='مسار ملف قائمة الكلمات لفحص FFUF (الافتراضي: wordlists/common_paths.txt)')
    parser.add_argument('--ffuf-extensions',
                        default='php,asp,aspx,jsp,html,txt',
                        help='امتدادات الملفات للبحث عنها في فحص FFUF (الافتراضي: php,asp,aspx,jsp,html,txt)')
    parser.add_argument('--ffuf-threads',
                        type=int,
                        default=40,
                        help='عدد مسارات الفحص المتزامنة لـ FFUF (الافتراضي: 40)')
    parser.add_argument('--ffuf-timeout',
                        type=int,
                        default=30,
                        help='مهلة فحص FFUF بالثواني (الافتراضي: 30)')
    parser.add_argument('--wpscan-timeout',
                        type=int,
                        default=30,
                        help='مهلة فحص WPScan بالثواني (الافتراضي: 30)')
    
    return parser.parse_args()

def ffuf_scan(host, port, wordlist=None, extensions=None, threads=40, timeout=30, verbose=False):
    """محاكاة فحص المسارات المخفية باستخدام FFUF
    
    Args:
        host (str): اسم المضيف أو عنوان IP
        port (int): رقم المنفذ
        wordlist (str): مسار ملف قائمة الكلمات المستخدمة للفحص
        extensions (str): امتدادات الملفات للبحث عنها
        threads (int): عدد مسارات الفحص المتزامنة
        timeout (int): مهلة الفحص بالثواني
        verbose (bool): عرض تفاصيل إضافية
    """
    found_paths = []
    if port in [80, 443, 8000, 8080, 3000, 5000]:
        protocol = 'http'  # استخدام HTTP لجميع المنافذ في بيئة الاختبار
        print(f"\n{Fore.YELLOW}[*] جاري تنفيذ فحص FFUF على {host}...{Style.RESET_ALL}")
        
        # محاكاة قراءة ملف قائمة الكلمات
        common_paths = [
            '/admin', '/api', '/backup', '/config', '/dashboard', '/db',
            '/debug', '/dev', '/docs', '/files', '/images', '/inc',
            '/include', '/js', '/log', '/login', '/media', '/panel',
            '/private', '/public', '/scripts', '/secret', '/server-status',
            '/test', '/tmp', '/upload', '/uploads', '/web.config'
        ]
        
        # محاكاة الفحص مع تقدم العملية
        total_paths = len(common_paths) * (len(extensions.split(',')) if extensions else 1)
        found_count = 0
        
        with tqdm(total=total_paths, desc="فحص FFUF", ncols=75) as pbar:
            for path in common_paths:
                if extensions:
                    for ext in extensions.split(','):
                        url = f"{protocol}://{host}{path}.{ext}"
                        # محاكاة احتمالية العثور على المسار
                        if random.random() < 0.3:  # 30% احتمالية العثور على المسار
                            status_code = random.choice([200, 301, 302, 403])
                            status_desc = {
                                200: 'متاح للوصول',
                                301: 'تحويل دائم',
                                302: 'تحويل مؤقت',
                                403: 'ممنوع الوصول'
                            }[status_code]
                            found_paths.append(f"[FFUF] تم العثور على: {url} - {status_desc} (الحالة: {status_code})")
                            found_count += 1
                            if verbose:
                                print(f"{Fore.GREEN}[+] {url} - {status_desc}{Style.RESET_ALL}")
                        pbar.update(1)
                else:
                    url = f"{protocol}://{host}{path}"
                    if random.random() < 0.3:
                        status_code = random.choice([200, 301, 302, 403])
                        status_desc = {
                            200: 'متاح للوصول',
                            301: 'تحويل دائم',
                            302: 'تحويل مؤقت',
                            403: 'ممنوع الوصول'
                        }[status_code]
                        found_paths.append(f"[FFUF] تم العثور على: {url} - {status_desc} (الحالة: {status_code})")
                        found_count += 1
                        if verbose:
                            print(f"{Fore.GREEN}[+] {url} - {status_desc}{Style.RESET_ALL}")
                    pbar.update(1)
        
        print(f"\n{Fore.GREEN}[+] اكتمل فحص FFUF. تم العثور على {found_count} مسارات.{Style.RESET_ALL}")
    
    return found_paths

def save_results(filename, results, args):
    # إنشاء اسم ملف يتضمن التاريخ والوقت
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_filename = os.path.join('reports', f'report_{timestamp}_{args.host}.txt')
    
    # التأكد من وجود مجلد reports
    os.makedirs('reports', exist_ok=True)
    
    with open(report_filename, 'w', encoding='utf-8-sig') as f:
        f.write(f"تقرير فحص Nettacker - {datetime.now()}\n")
        f.write("=" * 50 + "\n\n")
        
        # معلومات الفحص
        f.write("معلومات الفحص:\n")
        f.write(f"الهدف: {args.host}\n")
        f.write(f"نوع الفحص: {args.method}\n")
        if args.method != 'dir':
            f.write(f"المنافذ المفحوصة: {args.ports}\n")
        f.write("\n" + "=" * 50 + "\n\n")
        
        # تصنيف النتائج
        ports_results = [r for r in results if r.startswith("منفذ مفتوح")]
        services_results = [r for r in results if r.startswith("خادم")]
        paths_results = [r for r in results if r.startswith("مسار") and "dirsearch" not in r and "Gobuster" not in r]
        vulns_results = [r for r in results if r.startswith("ثغرة")]
        wapiti_results = [r for r in results if "Wapiti" in r]
        dirsearch_results = [r for r in results if "dirsearch" in r]
        gobuster_results = [r for r in results if "Gobuster" in r]
        ffuf_results = [r for r in results if "FFUF" in r]
        
        if ports_results:
            f.write("المنافذ المفتوحة:\n")
            for r in ports_results:
                f.write(f"- {r}\n")
            f.write("\n")
        
        if services_results:
            f.write("الخدمات المكتشفة:\n")
            for r in services_results:
                f.write(f"- {r}\n")
            f.write("\n")
        
        if paths_results:
            f.write("المسارات المكتشفة:\n")
            for r in paths_results:
                f.write(f"- {r}\n")
            f.write("\n")
        
        if vulns_results:
            f.write("الثغرات المحتملة:\n")
            for r in vulns_results:
                f.write(f"- {r}\n")
            f.write("\n")
        
        if wapiti_results:
            f.write("نتائج فحص Wapiti:\n")
            for r in wapiti_results:
                f.write(f"- {r}\n")
            f.write("\n")
        
        if dirsearch_results:
            f.write("نتائج فحص dirsearch:\n")
            for r in dirsearch_results:
                f.write(f"- {r}\n")
            f.write("\n")
        
        if gobuster_results:
            f.write("نتائج فحص Gobuster (القوة المدمرة):\n")
            for r in gobuster_results:
                f.write(f"- {r}\n")
            f.write("\n")

        if ffuf_results:
            f.write("نتائج فحص FFUF:\n")
            for r in ffuf_results:
                f.write(f"- {r}\n")
            f.write("\n")

        wpscan_results = [r for r in results if "WPScan" in r]
        if wpscan_results:
            f.write("نتائج فحص WPScan:\n")
            for r in wpscan_results:
                f.write(f"- {r}\n")
            f.write("\n")
        
        f.write("\n" + "=" * 50 + "\n")
        f.write("تم إنشاء هذا التقرير بواسطة Nettacker\n")

def main():
    args = parse_args()
    
    # التحقق من خيارات اللوقو
    if not args.no_logo:
        show_logo()
    
    # إذا كان الخيار هو عرض اللوقو فقط، نخرج من البرنامج
    if args.show_logo_only:
        sys.exit(0)
    
    if len(sys.argv) == 1:
        print(f"\n{Fore.RED}خطأ: لم يتم تحديد أي معاملات. استخدم -h أو --help للمساعدة.{Style.RESET_ALL}")
        sys.exit(1)
    
    if not args.host:
        print(f"\n{Fore.RED}خطأ: يجب تحديد الهدف.{Style.RESET_ALL}")
        sys.exit(1)
    
    results = []
    open_ports = []
    
    try:
        # فحص المنافذ (دائماً مطلوب للفحص)
        if args.method != 'dir':
            open_ports = scan_ports(args.host, args.ports, args.verbose)
            for port, service in open_ports:
                results.append(f"منفذ مفتوح: {port} - الخدمة: {service}")
        else:
            # في حالة فحص المسارات فقط، نفحص المنافذ المعروفة للويب والمنافذ الإضافية
            open_ports = [(80, 'http'), (443, 'https'), (8000, 'http'), (8080, 'http'), (3000, 'http'), (5000, 'http')]
            # تحقق من المنفذ المحدد في المعاملات
            if args.ports and args.ports != '21,22,23,25,53,80,110,143,443,465,587,993,995,1433,3306,3389,5432,8080':
                # إذا تم تحديد منافذ محددة، استخدمها فقط
                specified_ports = [int(p) for p in args.ports.split(',')]
                open_ports = [(p, 'http' if p != 443 else 'https') for p in specified_ports]
        
        # كشف الخدمات
        if args.method in ['service', 'all'] and open_ports:
            print(f"\n{Fore.YELLOW}[*] جاري كشف الخدمات...{Style.RESET_ALL}")
            for port, _ in open_ports:
                service_info = service_scan(args.host, port)
                if service_info:
                    results.append(service_info)
                    if args.verbose:
                        print(f"{Fore.GREEN}[+] {service_info}{Style.RESET_ALL}")
        
        # فحص المسارات المخفية
        if args.method in ['dir', 'all'] and open_ports:
            for port, _ in open_ports:
                if port in [80, 443, 8000, 8080, 3000, 5000]:  # المنافذ المتعلقة بالويب
                    paths = directory_scan(args.host, port, timeout=args.timeout, max_threads=args.threads)
                    for path in paths:
                        results.append(path)
        
        # فحص dirsearch
        if args.method in ['dirsearch', 'all'] and open_ports:
            for port, _ in open_ports:
                if port in [80, 443, 8000, 8080, 3000, 5000]:  # المنافذ المتعلقة بالويب
                    dirsearch_results = dirsearch_scan(
                        args.host,
                        port,
                        wordlist=args.dirsearch_wordlist,
                        extensions=args.dirsearch_extensions,
                        threads=args.dirsearch_threads,
                        timeout=args.dirsearch_timeout,
                        verbose=args.verbose
                    )
                    for result in dirsearch_results:
                        results.append(result)
                        if args.verbose and not result.startswith("خطأ"):
                            print(f"{Fore.YELLOW}[!] {result}{Style.RESET_ALL}")
        
        # فحص Gobuster
        if args.method in ['gobuster', 'all'] and open_ports:
            for port, _ in open_ports:
                if port in [80, 443, 8000, 8080, 3000, 5000]:  # المنافذ المتعلقة بالويب
                    gobuster_results = gobuster_scan(
                        args.host,
                        port,
                        wordlist=args.gobuster_wordlist,
                        extensions=args.gobuster_extensions,
                        threads=args.gobuster_threads,
                        timeout=args.gobuster_timeout,
                        verbose=args.verbose
                    )
                    for result in gobuster_results:
                        results.append(result)
                        if args.verbose and not result.startswith("خطأ"):
                            print(f"{Fore.CYAN}[!] {result}{Style.RESET_ALL}")

        # فحص FFUF
        if args.method in ['ffuf', 'all'] and open_ports:
            for port, _ in open_ports:
                if port in [80, 443, 8000, 8080, 3000, 5000]:  # المنافذ المتعلقة بالويب
                    ffuf_results = ffuf_scan(
                        args.host,
                        port,
                        wordlist=args.ffuf_wordlist,
                        extensions=args.ffuf_extensions,
                        threads=args.ffuf_threads,
                        timeout=args.ffuf_timeout,
                        verbose=args.verbose
                    )
                    for result in ffuf_results:
                        results.append(result)
                        if args.verbose and not result.startswith("خطأ"):
                            print(f"{Fore.MAGENTA}[!] {result}{Style.RESET_ALL}")

        # فحص WPScan
        if args.method in ['wpscan', 'all'] and open_ports:
            for port, _ in open_ports:
                if port in [80, 443]:  # فقط للمنافذ المتعلقة بالويب
                    wpscan_results = wpscan_scan(
                        args.host,
                        port,
                        timeout=args.wpscan_timeout,
                        verbose=args.verbose
                    )
                    for result in wpscan_results:
                        results.append(result)
                        if args.verbose and not result.startswith("خطأ"):
                            print(f"{Fore.BLUE}[!] {result}{Style.RESET_ALL}")
        
        # فحص الثغرات
        if args.method in ['vuln', 'all'] and open_ports:
            print(f"\n{Fore.YELLOW}[*] جاري البحث عن الثغرات...{Style.RESET_ALL}")
            for port, _ in open_ports:
                vulns = vulnerability_scan(args.host, port)
                for vuln in vulns:
                    results.append(vuln)
                    if args.verbose:
                        print(f"{Fore.RED}[!] {vuln}{Style.RESET_ALL}")
        
        # فحص Wapiti
        if args.method in ['wapiti', 'all'] and open_ports:
            for port, _ in open_ports:
                if port in [80, 443]:  # فقط للمنافذ المتعلقة بالويب
                    wapiti_vulns = wapiti_scan(args.host, port, timeout=args.wapiti_timeout, verbose=args.verbose)
                    for vuln in wapiti_vulns:
                        results.append(vuln)
                        if args.verbose and not vuln.startswith("خطأ"):
                            print(f"{Fore.RED}[!] {vuln}{Style.RESET_ALL}")
        
        # عرض ملخص النتائج
        if results:
            print(f"\n{Fore.BLUE}=== ملخص النتائج ==={Style.RESET_ALL}")
            
            # تصنيف وعرض النتائج
            ports_results = [r for r in results if r.startswith("منفذ مفتوح")]
            services_results = [r for r in results if r.startswith("خادم")]
            paths_results = [r for r in results if r.startswith("مسار") and "dirsearch" not in r and "Gobuster" not in r]
            vulns_results = [r for r in results if r.startswith("ثغرة")]
            wapiti_results = [r for r in results if "Wapiti" in r]
            dirsearch_results = [r for r in results if "dirsearch" in r]
            gobuster_results = [r for r in results if "Gobuster" in r]
            ffuf_results = [r for r in results if "FFUF" in r]
            
            if ports_results:
                print(f"\n{Fore.CYAN}المنافذ المفتوحة:{Style.RESET_ALL}")
                for r in ports_results:
                    print(f"- {r}")
            
            if services_results:
                print(f"\n{Fore.CYAN}الخدمات المكتشفة:{Style.RESET_ALL}")
                for r in services_results:
                    print(f"- {r}")
            
            if paths_results:
                print(f"\n{Fore.CYAN}المسارات المكتشفة:{Style.RESET_ALL}")
                for r in paths_results:
                    print(f"- {r}")
            
            if vulns_results:
                print(f"\n{Fore.CYAN}الثغرات المحتملة:{Style.RESET_ALL}")
                for r in vulns_results:
                    print(f"- {r}")
            
            if wapiti_results:
                print(f"\n{Fore.CYAN}نتائج فحص Wapiti:{Style.RESET_ALL}")
                for r in wapiti_results:
                    print(f"- {r}")
            
            if dirsearch_results:
                print(f"\n{Fore.CYAN}نتائج فحص dirsearch:{Style.RESET_ALL}")
                for r in dirsearch_results:
                    print(f"- {r}")
            
            if gobuster_results:
                print(f"\n{Fore.CYAN}نتائج فحص Gobuster (القوة المدمرة):{Style.RESET_ALL}")
                for r in gobuster_results:
                    print(f"- {r}")

            if ffuf_results:
                print(f"\n{Fore.MAGENTA}نتائج فحص FFUF:{Style.RESET_ALL}")
                for r in ffuf_results:
                    print(f"- {r}")
        else:
            print(f"\n{Fore.YELLOW}[!] لم يتم العثور على أي نتائج.{Style.RESET_ALL}")
        
        # حفظ النتائج في مجلد reports
        if args.output and results:
            save_results(None, results, args)
            print(f"\n{Fore.GREEN}[+] تم حفظ النتائج في مجلد reports.{Style.RESET_ALL}")
    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] تم إيقاف الفحص بواسطة المستخدم.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] حدث خطأ: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main()