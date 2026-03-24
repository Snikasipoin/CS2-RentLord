import asyncio
import sqlite3
import logging
import os
import re
import time
import imaplib
from datetime import datetime, timedelta
from email import message_from_bytes
from email.header import decode_header

from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken

from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command, StateFilter
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.context import FSMContext

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  РќР°СЃС‚СЂРѕР№РєРё Рё С€РёС„СЂРѕРІР°РЅРёРµ
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

load_dotenv()

TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID_RAW = os.getenv("ADMIN_ID") or ""
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

def _parse_admin_ids(raw: str) -> list[int]:
    # РџРѕРґРґРµСЂР¶РєР° С„РѕСЂРјР°С‚Р°:
    #   ADMIN_ID=123456789
    #   ADMIN_ID=123456789,987654321,555666777
    #   ADMIN_ID=123456789 987654321 (С‡РµСЂРµР· РїСЂРѕР±РµР»С‹ С‚РѕР¶Рµ)
    parts = (
        raw.replace(";", ",")
            .replace("\n", " ")
            .replace("\r", " ")
            .replace("\t", " ")
            .split(",")
    )
    ids: list[int] = []
    for part in parts:
        for token in part.split():
            token = token.strip()
            if not token:
                continue
            if not token.isdigit():
                raise SystemExit(f"вќЊ ADMIN_ID СЃРѕРґРµСЂР¶РёС‚ РЅРµС‡РёСЃР»РѕРІРѕР№ РёРґРµРЅС‚РёС„РёРєР°С‚РѕСЂ: {token!r}")
            ids.append(int(token))
    return ids

ADMIN_IDS = _parse_admin_ids(ADMIN_ID_RAW)

if not all([TOKEN, ADMIN_IDS, ENCRYPTION_KEY]):
    raise SystemExit("вќЊ Р’ .env РґРѕР»Р¶РЅС‹ Р±С‹С‚СЊ BOT_TOKEN, ADMIN_ID (РјРѕР¶РЅРѕ РЅРµСЃРєРѕР»СЊРєРѕ С‡РµСЂРµР· Р·Р°РїСЏС‚СѓСЋ), ENCRYPTION_KEY")

def _normalize_fernet_key(key: str) -> bytes:
    """
    Fernet key РґРѕР»Р¶РЅР° Р±С‹С‚СЊ base64url СЃС‚СЂРѕРєРѕР№ (РѕР±С‹С‡РЅРѕ 44 СЃРёРјРІРѕР»Р°, Р·Р°РєР°РЅС‡РёРІР°РµС‚СЃСЏ РЅР° '=')
    РРЅРѕРіРґР° РІ .env РєР»СЋС‡ РєРѕРїРёСЂСѓСЋС‚ Р±РµР· padding РёР»Рё СЃ РїСЂРѕР±РµР»Р°РјРё/РєР°РІС‹С‡РєР°РјРё.
    """
    k = (key or "").strip()

    # РЈР±РµСЂС‘Рј РІРѕР·РјРѕР¶РЅС‹Рµ РѕР±СЂР°РјР»СЏСЋС‰РёРµ РєР°РІС‹С‡РєРё
    if (k.startswith('"') and k.endswith('"')) or (k.startswith("'") and k.endswith("'")):
        k = k[1:-1]

    # РЈР±РµСЂС‘Рј РїСЂРѕР±РµР»С‹/РїРµСЂРµРЅРѕСЃС‹ СЃС‚СЂРѕРє РІРЅСѓС‚СЂРё
    k = "".join(k.split())

    # Р”РѕР±Р°РІРёРј padding base64url, РµСЃР»Рё РЅРµ РєСЂР°С‚РЅРѕ 4
    rem = len(k) % 4
    if rem:
        k = k + ("=" * (4 - rem))

    return k.encode()

try:
    cipher = Fernet(_normalize_fernet_key(ENCRYPTION_KEY))
except Exception as e:
    raise SystemExit(
        "вќЊ ENCRYPTION_KEY РЅРµ СЏРІР»СЏРµС‚СЃСЏ РєРѕСЂСЂРµРєС‚РЅС‹Рј Fernet-РєР»СЋС‡РѕРј. "
        "РџСЂРѕРІРµСЂСЊС‚Рµ РїРµСЂРµРјРµРЅРЅСѓСЋ РѕРєСЂСѓР¶РµРЅРёСЏ/С„Р°Р№Р» .env (РєР»СЋС‡ Fernet.generate_key())."
    ) from e

def encrypt(text: str | None) -> str | None:
    if text is None: return None
    return cipher.encrypt(text.encode()).decode()

def decrypt(encrypted: str | None) -> str | None:
    if encrypted is None: return None
    try:
        return cipher.decrypt(encrypted.encode()).decode()
    except InvalidToken:
        return "[РѕС€РёР±РєР° СЂР°СЃС€РёС„СЂРѕРІРєРё вЂ” СЃС‚Р°СЂС‹Р№ С„РѕСЂРјР°С‚]"

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  Р‘Р°Р·Р° РґР°РЅРЅС‹С…
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

conn = sqlite3.connect("accounts.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS accounts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    steam_login     TEXT UNIQUE NOT NULL,
    steam_password  TEXT,
    email           TEXT,
    email_password  TEXT,
    faceit_email    TEXT,
    faceit_password TEXT,
    status          TEXT DEFAULT 'free',
    rent_end        TEXT
)
""")
conn.commit()

def migrate_encryption():
    cursor.execute("SELECT id, steam_password, email_password, faceit_password FROM accounts")
    updated = False
    for row in cursor.fetchall():
        aid, sp, ep, fp = row
        if sp and not sp.startswith("gAAAA"):
            cursor.execute("UPDATE accounts SET steam_password=? WHERE id=?", (encrypt(sp), aid))
            updated = True
        if ep and not ep.startswith("gAAAA"):
            cursor.execute("UPDATE accounts SET email_password=? WHERE id=?", (encrypt(ep), aid))
            updated = True
        if fp and not fp.startswith("gAAAA"):
            cursor.execute("UPDATE accounts SET faceit_password=? WHERE id=?", (encrypt(fp), aid))
            updated = True
    if updated:
        conn.commit()
    logging.info("РњРёРіСЂР°С†РёСЏ С€РёС„СЂРѕРІР°РЅРёСЏ Р·Р°РІРµСЂС€РµРЅР°")

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  РЎРѕСЃС‚РѕСЏРЅРёСЏ FSM
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

class AddAccount(StatesGroup):
    steam_login     = State()
    steam_password  = State()
    email           = State()
    email_password  = State()
    faceit_choice   = State()
    faceit_email    = State()
    faceit_password = State()
    confirm         = State()

class RentAccount(StatesGroup):
    select_account = State()
    select_time    = State()
    waiting_code_action = State()

class ExtendAccount(StatesGroup):
    select_account = State()
    select_time    = State()

class FreeAccount(StatesGroup):
    select_account = State()

class AccountDetails(StatesGroup):
    select_account = State()

class DeleteAccount(StatesGroup):
    select_account = State()
    confirm = State()

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  Р‘РѕС‚ Рё РєР»Р°РІРёР°С‚СѓСЂС‹
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

bot = Bot(token=TOKEN, timeout=120)
dp = Dispatcher()

cancel_kb = ReplyKeyboardMarkup(
    keyboard=[[KeyboardButton(text="РћС‚РјРµРЅР°")]],
    resize_keyboard=True
)

main_menu = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="рџ“Љ РЎС‚Р°С‚СѓСЃ"),     KeyboardButton(text="рџ“¦ РђРєРєР°СѓРЅС‚С‹")],
        [KeyboardButton(text="вћ• Р”РѕР±Р°РІРёС‚СЊ"),    KeyboardButton(text="рџ—‘ РЈРґР°Р»РёС‚СЊ")],
        [KeyboardButton(text="рџЋ® РЎРґР°С‚СЊ"),       KeyboardButton(text="вњ… РћСЃРІРѕР±РѕРґРёС‚СЊ")],
        [KeyboardButton(text="вЏ± РџСЂРѕРґР»РёС‚СЊ")]
    ],
    resize_keyboard=True
)

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  Р’СЃРїРѕРјРѕРіР°С‚РµР»СЊРЅС‹Рµ С„СѓРЅРєС†РёРё
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

def clean_invalid_dates():
    try:
        cursor.execute("""
            UPDATE accounts
               SET status = 'free',
                   rent_end = NULL
             WHERE status = 'busy'
               AND (rent_end IS NULL OR rent_end = '' OR rent_end <= datetime('now'))
        """)
        conn.commit()
    except Exception as e:
        logging.error(f"clean_invalid_dates error: {e}")

def _detect_imap_hosts(email_address: str) -> list[tuple[str, int]]:
    email_address = (email_address or "").lower().strip()
    if email_address.endswith("@gmail.com"):
        return [("imap.gmail.com", 993)]
    if email_address.endswith("@proton.me") or email_address.endswith("@protonmail.com") or email_address.endswith("@pm.me"):
        return [("imap.proton.me", 993), ("imap.protonmail.com", 993)]
    return []

def _normalize_imap_host(host: str | None) -> str | None:
    host = (host or "").strip().lower()
    if not host:
        return None
    if host.startswith("imap://"):
        host = host[7:]
    if host.startswith("imaps://"):
        host = host[8:]
    return host.strip("/")

def _build_imap_hosts(email_address: str) -> list[tuple[str, int]]:
    candidates: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()

    def add_candidate(host: str | None, port: int = 993):
        normalized_host = _normalize_imap_host(host)
        if not normalized_host:
            return
        item = (normalized_host, port)
        if item not in seen:
            seen.add(item)
            candidates.append(item)

    for host, port in _detect_imap_hosts(email_address):
        add_candidate(host, port)

    if "@" in (email_address or ""):
        domain = email_address.rsplit("@", 1)[1].strip().lower()
        for guessed_host in (f"imap.{domain}", f"mail.{domain}", domain):
            add_candidate(guessed_host, 993)

    return candidates

def _decode_mime_words(value: str | None) -> str:
    if not value:
        return ""

    parts: list[str] = []
    for part, encoding in decode_header(value):
        if isinstance(part, bytes):
            try:
                parts.append(part.decode(encoding or "utf-8", errors="replace"))
            except Exception:
                parts.append(part.decode("utf-8", errors="replace"))
        else:
            parts.append(str(part))
    return "".join(parts)

def _extract_text_from_email_bytes(raw: bytes) -> tuple[str, str, str]:
    msg = message_from_bytes(raw)
    subject = _decode_mime_words(msg.get("Subject"))
    from_ = _decode_mime_words(msg.get("From"))

    parts_text: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = (part.get_content_type() or "").lower()
            if ctype not in ("text/plain", "text/html"):
                continue
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except Exception:
                text = payload.decode("utf-8", errors="replace")
            if ctype == "text/html":
                text = re.sub(r"<[^>]+>", " ", text)
            parts_text.append(text)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            try:
                parts_text.append(payload.decode(charset, errors="replace"))
            except Exception:
                parts_text.append(payload.decode("utf-8", errors="replace"))

    return subject, from_, "\n".join(parts_text).strip()

def _search_unseen_message_ids(imap: imaplib.IMAP4_SSL, senders: tuple[str, ...]) -> list[bytes]:
    found: list[bytes] = []
    seen: set[bytes] = set()

    for sender in senders:
        typ, data = imap.uid("search", None, f'(UNSEEN FROM "{sender}")')
        if typ != "OK" or not data:
            continue
        for uid in (data[0] or b"").split():
            if uid not in seen:
                seen.add(uid)
                found.append(uid)

    return found

def _get_email_code_sync(
    email_address: str,
    email_password: str,
    senders: tuple[str, ...],
    pattern: str,
    timeout_s: int = 120,
    interval_s: int = 5,
) -> str | None:
    hosts = _build_imap_hosts(email_address)
    if not hosts:
        raise RuntimeError(f"Unknown IMAP host for email: {email_address}")

    deadline = time.monotonic() + timeout_s
    last_error: Exception | None = None

    for host, port in hosts:
        imap = None
        try:
            imap = imaplib.IMAP4_SSL(host, port)
            imap.login(email_address, email_password)
            imap.select("INBOX")

            baseline = set(_search_unseen_message_ids(imap, senders))
            while time.monotonic() < deadline:
                current_ids = _search_unseen_message_ids(imap, senders)
                new_ids = [uid for uid in current_ids if uid not in baseline]

                for uid in reversed(new_ids):
                    typ, msg_data = imap.uid("fetch", uid.decode(), "(RFC822)")
                    if typ != "OK" or not msg_data:
                        continue

                    raw = None
                    for part in msg_data:
                        if isinstance(part, tuple) and len(part) >= 2:
                            raw = part[1]
                            break
                    if not raw:
                        continue

                    subject, from_, body_text = _extract_text_from_email_bytes(raw)
                    haystack = f"{subject}\n{from_}\n{body_text}".upper()
                    match = re.search(pattern, haystack)
                    if match:
                        try:
                            imap.uid("store", uid.decode(), "+FLAGS", "\\Seen")
                        except Exception:
                            pass
                        return match.group(1)

                baseline.update(current_ids)
                time.sleep(interval_s)

            return None
        except Exception as e:
            last_error = e
        finally:
            if imap is not None:
                try:
                    imap.logout()
                except Exception:
                    pass

    raise RuntimeError(f"IMAP error: {last_error}")

async def get_steam_guard_code(email: str, password: str) -> str | None:
    return await asyncio.to_thread(
        _get_email_code_sync,
        email,
        password,
        ("noreply@steampowered.com", "no-reply@steampowered.com"),
        r"\b([A-Z0-9]{5})\b",
        120,
        5,
    )

async def check_steam_code(account_id: int) -> str | None:
    cursor.execute(
        """
        SELECT email, email_password
          FROM accounts
         WHERE id = ?
        """,
        (account_id,)
    )
    row = cursor.fetchone()
    if not row:
        raise RuntimeError("Account not found")

    email, email_password_enc = row
    email_password = decrypt(email_password_enc)
    if not email or not email_password or email_password.startswith("[РѕС€РёР±РєР°"):
        raise RuntimeError("Email check failed")

    return await get_steam_guard_code(email, email_password)

async def check_faceit_code(account_id: int) -> str | None:
    cursor.execute(
        """
        SELECT email, email_password
          FROM accounts
         WHERE id = ?
        """,
        (account_id,)
    )
    row = cursor.fetchone()
    if not row:
        raise RuntimeError("Account not found")

    email, email_password_enc = row
    email_password = decrypt(email_password_enc)
    if not email or not email_password or email_password.startswith("[РѕС€РёР±РєР°"):
        raise RuntimeError("Email check failed")

    return await asyncio.to_thread(
        _get_email_code_sync,
        email,
        email_password,
        ("notifications@faceit.com",),
        r"\b(\d{6})\b",
        120,
        5,
    )

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  РћС‚РјРµРЅР° Р»СЋР±РѕРіРѕ СЃРѕСЃС‚РѕСЏРЅРёСЏ
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

@dp.message(F(equals=["РѕС‚РјРµРЅР°", "cancel"], ignore_case=True))
@dp.message(Command("cancel"))
async def cancel_any_state(message: types.Message, state: FSMContext):
    if await state.get_state() is None:
        return await message.answer("РќРµС‡РµРіРѕ РѕС‚РјРµРЅСЏС‚СЊ.", reply_markup=main_menu)

    await state.clear()
    await message.answer("Р”РµР№СЃС‚РІРёРµ РѕС‚РјРµРЅРµРЅРѕ.", reply_markup=main_menu)

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  /start
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    if message.from_user.id not in ADMIN_IDS:
        return
    clean_invalid_dates()
    await message.answer("Р”РѕР±СЂРѕ РїРѕР¶Р°Р»РѕРІР°С‚СЊ РІ РїР°РЅРµР»СЊ Р°СЂРµРЅРґС‹", reply_markup=main_menu)

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  Р”РѕР±Р°РІР»РµРЅРёРµ Р°РєРєР°СѓРЅС‚Р° вЂ” РїРѕР»РЅС‹Р№ С†РёРєР»
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

@dp.message(F.text == "вћ• Р”РѕР±Р°РІРёС‚СЊ")
async def add_start(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS: return
    await state.set_state(AddAccount.steam_login)
    await message.answer("Р›РѕРіРёРЅ Steam:", reply_markup=cancel_kb)

@dp.message(StateFilter(AddAccount.steam_login))
async def add_login(message: types.Message, state: FSMContext):
    await state.update_data(steam_login=message.text.strip())
    await state.set_state(AddAccount.steam_password)
    await message.answer("РџР°СЂРѕР»СЊ Steam:", reply_markup=cancel_kb)

@dp.message(StateFilter(AddAccount.steam_password))
async def add_steam_pw(message: types.Message, state: FSMContext):
    await state.update_data(steam_password=message.text.strip())
    await state.set_state(AddAccount.email)
    await message.answer("Email:", reply_markup=cancel_kb)

@dp.message(StateFilter(AddAccount.email))
async def add_email(message: types.Message, state: FSMContext):
    await state.update_data(email=message.text.strip())
    await state.set_state(AddAccount.email_password)
    await message.answer("РџР°СЂРѕР»СЊ email:", reply_markup=cancel_kb)

@dp.message(StateFilter(AddAccount.email_password))
async def add_email_pw(message: types.Message, state: FSMContext):
    await state.update_data(email_password=message.text.strip())
    await state.set_state(AddAccount.faceit_choice)
    await message.answer("Р•СЃС‚СЊ Faceit? (РґР° / РЅРµС‚)", reply_markup=cancel_kb)

@dp.message(StateFilter(AddAccount.faceit_choice))
async def add_faceit_choice(message: types.Message, state: FSMContext):
    txt = message.text.lower().strip()
    if txt == "РґР°":
        await state.set_state(AddAccount.faceit_email)
        await message.answer("Email Faceit:", reply_markup=cancel_kb)
    elif txt == "РЅРµС‚":
        await state.update_data(faceit_email=None, faceit_password=None)
        await show_confirm_add(message, state)
    else:
        await message.answer("РћС‚РІРµС‚СЊС‚Рµ В«РґР°В» РёР»Рё В«РЅРµС‚В».", reply_markup=cancel_kb)

@dp.message(StateFilter(AddAccount.faceit_email))
async def add_faceit_email(message: types.Message, state: FSMContext):
    await state.update_data(faceit_email=message.text.strip())
    await state.set_state(AddAccount.faceit_password)
    await message.answer("РџР°СЂРѕР»СЊ Faceit:", reply_markup=cancel_kb)

@dp.message(StateFilter(AddAccount.faceit_password))
async def add_faceit_pw(message: types.Message, state: FSMContext):
    await state.update_data(faceit_password=message.text.strip())
    await show_confirm_add(message, state)

async def show_confirm_add(message: types.Message, state: FSMContext):
    d = await state.get_data()
    text = (
        f"РџРѕРґС‚РІРµСЂРґРёС‚Рµ РґРѕР±Р°РІР»РµРЅРёРµ:\n\n"
        f"Steam: {d['steam_login']} : ********\n"
        f"Email: {d['email']} : ********\n"
        f"Faceit: {d.get('faceit_email') or 'РќРµС‚'}"
    )
    kb = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="РџРѕРґС‚РІРµСЂРґРёС‚СЊ")],
            [KeyboardButton(text="РћС‚РјРµРЅР°")]
        ],
        resize_keyboard=True
    )
    await state.set_state(AddAccount.confirm)
    await message.answer(text, reply_markup=kb)

@dp.message(StateFilter(AddAccount.confirm))
async def add_confirm(message: types.Message, state: FSMContext):
    if (message.text or "").strip().lower() != "РїРѕРґС‚РІРµСЂРґРёС‚СЊ":
        await state.clear()
        return await message.answer("Р”РѕР±Р°РІР»РµРЅРёРµ РѕС‚РјРµРЅРµРЅРѕ.", reply_markup=main_menu)

    d = await state.get_data()
    login = d["steam_login"]

    cursor.execute("SELECT 1 FROM accounts WHERE steam_login = ?", (login,))
    if cursor.fetchone():
        await state.clear()
        return await message.answer("РўР°РєРѕР№ Р»РѕРіРёРЅ СѓР¶Рµ СЃСѓС‰РµСЃС‚РІСѓРµС‚!", reply_markup=main_menu)

    try:
        cursor.execute("""
            INSERT INTO accounts (
                steam_login, steam_password, email, email_password,
                faceit_email, faceit_password, status
            ) VALUES (?, ?, ?, ?, ?, ?, 'free')
        """, (
            login,
            encrypt(d["steam_password"]),
            d["email"],
            encrypt(d["email_password"]),
            d.get("faceit_email"),
            encrypt(d.get("faceit_password"))
        ))
        conn.commit()
        await message.answer("РђРєРєР°СѓРЅС‚ СѓСЃРїРµС€РЅРѕ РґРѕР±Р°РІР»РµРЅ!", reply_markup=main_menu)
    except sqlite3.IntegrityError:
        conn.rollback()
        await message.answer("РћС€РёР±РєР°: С‚Р°РєРѕР№ Р»РѕРіРёРЅ СѓР¶Рµ СЃСѓС‰РµСЃС‚РІСѓРµС‚.", reply_markup=main_menu)
    except Exception as e:
        conn.rollback()
        logging.error(f"add_confirm error: {e}")
        await message.answer("РћС€РёР±РєР° СЃРѕС…СЂР°РЅРµРЅРёСЏ. РџРѕРїСЂРѕР±СѓР№С‚Рµ РїРѕР·Р¶Рµ.", reply_markup=main_menu)

    await state.clear()

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  РџСЂРѕСЃРјРѕС‚СЂ СЃРїРёСЃРєР°
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

@dp.message(F.text == "рџ“¦ РђРєРєР°СѓРЅС‚С‹")
async def show_accounts(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS: return
    clean_invalid_dates()

    cursor.execute("SELECT id, steam_login, status, rent_end FROM accounts ORDER BY steam_login")
    rows = cursor.fetchall()

    if not rows:
        return await message.answer("РђРєРєР°СѓРЅС‚РѕРІ РЅРµС‚", reply_markup=main_menu)

    lines = []
    rows_data = []
    for aid, login, st, end in rows:
        rows_data.append({"id": aid, "login": login, "status": st, "end": end})
        if st == "free":
            lines.append(f"рџџў {login}")
        else:
            try:
                dt = datetime.fromisoformat(end)
                mins = max(0, int((dt - datetime.now()).total_seconds() / 60))
                lines.append(f"рџ”ґ {login} вЂ” {mins} РјРёРЅ")
            except:
                lines.append(f"рџџў {login} (РѕС€РёР±РєР° РґР°С‚С‹)")

    kb = ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=acc["login"])] for acc in rows_data] + [[KeyboardButton(text="РћС‚РјРµРЅР°")]],
        resize_keyboard=True
    )
    await state.set_state(AccountDetails.select_account)
    await state.update_data(accounts=rows_data)
    await message.answer(
        (("\n".join(lines) or "РџСѓСЃС‚Рѕ") + "\n\nР’С‹Р±РµСЂРёС‚Рµ Р°РєРєР°СѓРЅС‚ РґР»СЏ РїСЂРѕСЃРјРѕС‚СЂР° РґР°РЅРЅС‹С…:"),
        reply_markup=kb,
    )


@dp.message(StateFilter(AccountDetails.select_account))
async def show_account_details(message: types.Message, state: FSMContext):
    login = (message.text or "").strip()
    data = await state.get_data()
    rows = data.get("accounts", [])

    chosen = next((r for r in rows if r.get("login") == login), None)
    if chosen is None:
        await state.clear()
        return await message.answer("РђРєРєР°СѓРЅС‚ РЅРµ РЅР°Р№РґРµРЅ.", reply_markup=main_menu)

    aid = chosen["id"]

    cursor.execute(
        """
        SELECT steam_login, steam_password, email, email_password, faceit_email, faceit_password, status, rent_end
          FROM accounts
         WHERE id = ?
        """,
        (aid,),
    )
    row = cursor.fetchone()
    if not row:
        await state.clear()
        return await message.answer("РћС€РёР±РєР°: Р°РєРєР°СѓРЅС‚ РЅРµ РЅР°Р№РґРµРЅ РІ Р±Р°Р·Рµ.", reply_markup=main_menu)

    s_login, s_pw_enc, email, e_pw_enc, f_email, f_pw_enc, st, rent_end = row
    s_pw = decrypt(s_pw_enc)
    e_pw = decrypt(e_pw_enc)
    f_pw = decrypt(f_pw_enc) if f_pw_enc is not None else None

    details_lines = [
        f"Р”Р°РЅРЅС‹Рµ Р°РєРєР°СѓРЅС‚Р°: {s_login}",
        f"РЎС‚Р°С‚СѓСЃ: {st}",
        "",
        "Steam:",
        f"  Р›РѕРіРёРЅ: {s_login}",
        f"  РџР°СЂРѕР»СЊ: {s_pw}",
        "",
        "Email:",
        f"  РђРґСЂРµСЃ: {email or '-'}",
        f"  РџР°СЂРѕР»СЊ: {e_pw or '-'}",
    ]

    if f_email:
        details_lines.extend([
            "",
            "Faceit:",
            f"  Email: {f_email}",
            f"  РџР°СЂРѕР»СЊ: {f_pw or '-'}",
        ])

    # РџР°СЂР° СЃС‚СЂРѕРє РїСЂРѕ Р°СЂРµРЅРґСѓ вЂ” СѓРґРѕР±РЅРѕ, РЅРѕ РЅРµ РѕР±СЏР·Р°С‚РµР»СЊРЅРѕ
    if st == "busy" and rent_end:
        try:
            dt = datetime.fromisoformat(rent_end)
            mins = max(0, int((dt - datetime.now()).total_seconds() / 60))
            details_lines.extend(["", f"Р”Рѕ РєРѕРЅС†Р° Р°СЂРµРЅРґС‹: ~{mins} РјРёРЅ"])
        except Exception:
            pass

    await state.clear()
    await message.answer("\n".join(details_lines), reply_markup=main_menu)

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  РЈРґР°Р»РµРЅРёРµ Р°РєРєР°СѓРЅС‚Р°
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

@dp.message(F.text == "рџ—‘ РЈРґР°Р»РёС‚СЊ")
async def delete_start(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS: return
    clean_invalid_dates()

    cursor.execute("SELECT id, steam_login, status FROM accounts ORDER BY steam_login")
    rows = cursor.fetchall()
    if not rows:
        return await message.answer("РќРµС‚ Р°РєРєР°СѓРЅС‚РѕРІ РґР»СЏ СѓРґР°Р»РµРЅРёСЏ", reply_markup=main_menu)

    kb = ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=login)] for _, login, _ in rows] + [[KeyboardButton(text="РћС‚РјРµРЅР°")]],
        resize_keyboard=True
    )
    await state.set_state(DeleteAccount.select_account)
    await state.update_data(accounts=rows)
    await message.answer("Р’С‹Р±РµСЂРёС‚Рµ Р°РєРєР°СѓРЅС‚ РґР»СЏ СѓРґР°Р»РµРЅРёСЏ:", reply_markup=kb)

@dp.message(StateFilter(DeleteAccount.select_account))
async def delete_select_account(message: types.Message, state: FSMContext):
    login = (message.text or "").strip()
    data = await state.get_data()
    row = next((item for item in data.get("accounts", []) if item[1] == login), None)

    if row is None:
        return await message.answer("РђРєРєР°СѓРЅС‚ РЅРµ РЅР°Р№РґРµРЅ РІ СЃРїРёСЃРєРµ", reply_markup=main_menu)

    aid, selected_login, status = row
    confirm_kb = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="РЈРґР°Р»РёС‚СЊ Р°РєРєР°СѓРЅС‚")],
            [KeyboardButton(text="РћС‚РјРµРЅР°")]
        ],
        resize_keyboard=True
    )

    await state.update_data(selected_id=aid, selected_login=selected_login, selected_status=status)
    await state.set_state(DeleteAccount.confirm)
    await message.answer(
        f"Р’С‹ РІС‹Р±СЂР°Р»Рё Р°РєРєР°СѓРЅС‚: {selected_login}\n"
        f"РўРµРєСѓС‰РёР№ СЃС‚Р°С‚СѓСЃ: {status}\n\n"
        "РџРѕРґС‚РІРµСЂРґРёС‚Рµ СѓРґР°Р»РµРЅРёРµ. Р­С‚Рѕ РґРµР№СЃС‚РІРёРµ РЅРµРѕР±СЂР°С‚РёРјРѕ.",
        reply_markup=confirm_kb
    )

@dp.message(StateFilter(DeleteAccount.confirm))
async def delete_confirm(message: types.Message, state: FSMContext):
    if (message.text or "").strip().lower() != "СѓРґР°Р»РёС‚СЊ Р°РєРєР°СѓРЅС‚":
        await state.clear()
        return await message.answer("РЈРґР°Р»РµРЅРёРµ РѕС‚РјРµРЅРµРЅРѕ.", reply_markup=main_menu)

    data = await state.get_data()
    aid = data.get("selected_id")
    login = data.get("selected_login")

    try:
        cursor.execute("DELETE FROM accounts WHERE id = ?", (aid,))
        if cursor.rowcount == 0:
            conn.rollback()
            await message.answer("РђРєРєР°СѓРЅС‚ СѓР¶Рµ СѓРґР°Р»С‘РЅ РёР»Рё РЅРµ РЅР°Р№РґРµРЅ.", reply_markup=main_menu)
        else:
            conn.commit()
            await message.answer(f"РђРєРєР°СѓРЅС‚ {login} СѓРґР°Р»С‘РЅ.", reply_markup=main_menu)
    except Exception as e:
        conn.rollback()
        logging.error(f"delete error: {e}")
        await message.answer("РћС€РёР±РєР° РїСЂРё СѓРґР°Р»РµРЅРёРё Р°РєРєР°СѓРЅС‚Р°.", reply_markup=main_menu)

    await state.clear()

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  РЎС‚Р°С‚СѓСЃ
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

@dp.message(F.text == "рџ“Љ РЎС‚Р°С‚СѓСЃ")
async def show_status(message: types.Message):
    if message.from_user.id not in ADMIN_IDS: return
    clean_invalid_dates()
    cursor.execute("SELECT COUNT(*) FROM accounts WHERE status='free'")
    free = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM accounts WHERE status='busy'")
    busy = cursor.fetchone()[0]
    await message.answer(f"РЎРІРѕР±РѕРґРЅС‹С…: {free}\nР—Р°РЅСЏС‚С‹С…: {busy}", reply_markup=main_menu)

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  РЎРґР°С‡Р° РІ Р°СЂРµРЅРґСѓ
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

@dp.message(F.text == "рџЋ® РЎРґР°С‚СЊ")
async def rent_start(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS: return
    clean_invalid_dates()

    cursor.execute("SELECT id, steam_login FROM accounts WHERE status='free' ORDER BY steam_login")
    rows = cursor.fetchall()
    if not rows:
        return await message.answer("РќРµС‚ СЃРІРѕР±РѕРґРЅС‹С… Р°РєРєР°СѓРЅС‚РѕРІ", reply_markup=main_menu)

    kb = ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=login)] for _, login in rows] + [[KeyboardButton(text="РћС‚РјРµРЅР°")]],
        resize_keyboard=True
    )
    await state.set_state(RentAccount.select_account)
    await state.update_data(accounts=rows)
    await message.answer("Р’С‹Р±РµСЂРёС‚Рµ Р°РєРєР°СѓРЅС‚:", reply_markup=kb)

@dp.message(StateFilter(RentAccount.select_account))
async def rent_select_account(message: types.Message, state: FSMContext):
    login = message.text.strip()
    data = await state.get_data()
    acc = next((aid for aid, l in data.get("accounts", []) if l == login), None)

    if acc is None:
        return await message.answer("РђРєРєР°СѓРЅС‚ РЅРµ РЅР°Р№РґРµРЅ РІ СЃРїРёСЃРєРµ СЃРІРѕР±РѕРґРЅС‹С…", reply_markup=main_menu)

    await state.update_data(selected_id=acc, selected_login=login)

    times_kb = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="1 С‡Р°СЃ"), KeyboardButton(text="2 С‡Р°СЃР°"), KeyboardButton(text="3 С‡Р°СЃР°")],
            [KeyboardButton(text="6 С‡Р°СЃРѕРІ"), KeyboardButton(text="12 С‡Р°СЃРѕРІ"), KeyboardButton(text="24 С‡Р°СЃР°")],
            [KeyboardButton(text="РћС‚РјРµРЅР°")]
        ],
        resize_keyboard=True
    )
    await state.set_state(RentAccount.select_time)
    await message.answer("РќР° СЃРєРѕР»СЊРєРѕ С‡Р°СЃРѕРІ?", reply_markup=times_kb)

@dp.message(StateFilter(RentAccount.select_time))
async def rent_confirm_time(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()
    if txt == "РѕС‚РјРµРЅР°":
        await state.clear()
        return await message.answer("РЎРґР°С‡Р° РѕС‚РјРµРЅРµРЅР°", reply_markup=main_menu)

    if not any(txt.startswith(str(h)) for h in (1,2,3,6,12,24)):
        return await message.answer("Р’С‹Р±РµСЂРёС‚Рµ РІСЂРµРјСЏ РёР· СЃРїРёСЃРєР°", reply_markup=main_menu)

    hours = int(txt.split()[0])
    await state.update_data(selected_hours=hours)

    code_action_kb = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="Request Steam Code")],
            [KeyboardButton(text="Code entered manually")],
            [KeyboardButton(text="Get Faceit Code")],
            [KeyboardButton(text="Cancel")]
        ],
        resize_keyboard=True
    )
    await state.set_state(RentAccount.waiting_code_action)
    await message.answer("Р’С‹Р±РµСЂРёС‚Рµ РґРµР№СЃС‚РІРёРµ СЃ РєРѕРґРѕРј:", reply_markup=code_action_kb)
    return

    data = await state.get_data()
    aid = data["selected_id"]
    login = data["selected_login"]

    end = datetime.now() + timedelta(hours=hours)

    try:
        cursor.execute(
            "UPDATE accounts SET status='busy', rent_end=? WHERE id=? AND status='free'",
            (end.isoformat(), aid)
        )
        if cursor.rowcount == 0:
            conn.rollback()
            await message.answer("РђРєРєР°СѓРЅС‚ СѓР¶Рµ Р·Р°РЅСЏС‚ РёР»Рё СѓРґР°Р»С‘РЅ", reply_markup=main_menu)
        else:
            conn.commit()
            await message.answer(
                f"РђРєРєР°СѓРЅС‚ **{login}** СЃРґР°РЅ РґРѕ {end.strftime('%d.%m %H:%M')}",
                reply_markup=main_menu
            )

            # РћС‚РїСЂР°РІР»СЏРµРј Р°РґРјРёРЅРёСЃС‚СЂР°С‚РѕСЂСѓ С‚РѕР»СЊРєРѕ Steam Р»РѕРіРёРЅ/РїР°СЂРѕР»СЊ РґР»СЏ РїРѕРєСѓРїР°С‚РµР»СЏ
            cursor.execute(
                """
                SELECT steam_login, steam_password
                  FROM accounts
                 WHERE id = ?
                """,
                (aid,)
            )
            row = cursor.fetchone()
            if row:
                s_login, s_pw_enc = row
                s_pw = decrypt(s_pw_enc)

                await message.answer(
                    "Р”Р°РЅРЅС‹Рµ РґР»СЏ РїРѕРєСѓРїР°С‚РµР»СЏ:\n"
                    f"Steam Р»РѕРіРёРЅ: {s_login}\n"
                    f"Steam РїР°СЂРѕР»СЊ: {s_pw}"
                )
    except Exception as e:
        conn.rollback()
        logging.error(f"rent error: {e}")
        await message.answer("РћС€РёР±РєР° РїСЂРё СЃРґР°С‡Рµ", reply_markup=main_menu)

    await state.clear()

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  РћСЃРІРѕР±РѕР¶РґРµРЅРёРµ
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

@dp.message(StateFilter(RentAccount.waiting_code_action))
async def rent_waiting_code_action(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()
    if txt in ("cancel", "РѕС‚РјРµРЅР°"):
        await state.clear()
        return await message.answer("РЎРґР°С‡Р° РѕС‚РјРµРЅРµРЅР°", reply_markup=main_menu)

    data = await state.get_data()
    aid = data["selected_id"]
    login = data["selected_login"]
    hours = data["selected_hours"]
    end = datetime.now() + timedelta(hours=hours)

    async def complete_rent() -> bool:
        cursor.execute(
            "UPDATE accounts SET status='busy', rent_end=? WHERE id=? AND status='free'",
            (end.isoformat(), aid)
        )
        if cursor.rowcount == 0:
            conn.rollback()
            await message.answer("РђРєРєР°СѓРЅС‚ СѓР¶Рµ Р·Р°РЅСЏС‚ РёР»Рё СѓРґР°Р»С‘РЅ", reply_markup=main_menu)
            return False

        conn.commit()
        await message.answer(
            f"РђРєРєР°СѓРЅС‚ **{login}** СЃРґР°РЅ РґРѕ {end.strftime('%d.%m %H:%M')}",
            reply_markup=main_menu
        )

        cursor.execute(
            """
            SELECT steam_login, steam_password
              FROM accounts
             WHERE id = ?
            """,
            (aid,)
        )
        row = cursor.fetchone()
        if row:
            s_login, s_pw_enc = row
            s_pw = decrypt(s_pw_enc)
            await message.answer(
                "Р”Р°РЅРЅС‹Рµ РґР»СЏ РїРѕРєСѓРїР°С‚РµР»СЏ:\n"
                f"Steam Р»РѕРіРёРЅ: {s_login}\n"
                f"Steam РїР°СЂРѕР»СЊ: {s_pw}"
            )
        return True

    try:
        if txt == "code entered manually":
            await complete_rent()
            await state.clear()
            return

        if txt == "request steam code":
            try:
                code = await check_steam_code(aid)
            except Exception as e:
                logging.error(f"steam code check error: {e}")
                await state.clear()
                return await message.answer("Email check failed", reply_markup=main_menu)

            if not code:
                await state.clear()
                return await message.answer("Steam code not found", reply_markup=main_menu)

            for admin_id in ADMIN_IDS:
                try:
                    await bot.send_message(admin_id, f"Steam Guard {login}: {code}")
                except Exception as e:
                    logging.error(f"steam code send error: {e}")

            await complete_rent()
            await state.clear()
            return

        if txt == "get faceit code":
            try:
                code = await check_faceit_code(aid)
            except Exception as e:
                logging.error(f"faceit code check error: {e}")
                return await message.answer("Email check failed")

            if not code:
                return await message.answer("Faceit code not found")

            return await message.answer(code)

        await message.answer("Р’С‹Р±РµСЂРёС‚Рµ РґРµР№СЃС‚РІРёРµ РёР· СЃРїРёСЃРєР°")
    except Exception as e:
        conn.rollback()
        logging.error(f"rent error: {e}")
        await state.clear()
        await message.answer("РћС€РёР±РєР° РїСЂРё СЃРґР°С‡Рµ", reply_markup=main_menu)

@dp.message(F.text == "вњ… РћСЃРІРѕР±РѕРґРёС‚СЊ")
async def free_start(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS: return
    clean_invalid_dates()

    cursor.execute("SELECT id, steam_login FROM accounts WHERE status='busy' ORDER BY steam_login")
    rows = cursor.fetchall()
    if not rows:
        return await message.answer("РќРµС‚ Р·Р°РЅСЏС‚С‹С… Р°РєРєР°СѓРЅС‚РѕРІ", reply_markup=main_menu)

    kb = ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=login)] for _, login in rows] + [[KeyboardButton(text="РћС‚РјРµРЅР°")]],
        resize_keyboard=True
    )
    await state.set_state(FreeAccount.select_account)
    await state.update_data(accounts=rows)
    await message.answer("Р’С‹Р±РµСЂРёС‚Рµ Р°РєРєР°СѓРЅС‚ РґР»СЏ РѕСЃРІРѕР±РѕР¶РґРµРЅРёСЏ:", reply_markup=kb)

@dp.message(StateFilter(FreeAccount.select_account))
async def free_select(message: types.Message, state: FSMContext):
    login = message.text.strip()
    data = await state.get_data()
    aid = next((a for a, l in data.get("accounts", []) if l == login), None)

    if aid is None:
        return await message.answer("РђРєРєР°СѓРЅС‚ РЅРµ РЅР°Р№РґРµРЅ РІ СЃРїРёСЃРєРµ Р·Р°РЅСЏС‚С‹С…", reply_markup=main_menu)

    try:
        cursor.execute("UPDATE accounts SET status='free', rent_end=NULL WHERE id=?", (aid,))
        conn.commit()
        await message.answer(f"РђРєРєР°СѓРЅС‚ {login} РѕСЃРІРѕР±РѕР¶РґС‘РЅ", reply_markup=main_menu)
    except Exception as e:
        conn.rollback()
        logging.error(f"free error: {e}")
        await message.answer("РћС€РёР±РєР° РѕСЃРІРѕР±РѕР¶РґРµРЅРёСЏ", reply_markup=main_menu)

    await state.clear()

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  РџСЂРѕРґР»РµРЅРёРµ
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

@dp.message(F.text == "вЏ± РџСЂРѕРґР»РёС‚СЊ")
async def extend_start(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS: return
    clean_invalid_dates()

    cursor.execute("SELECT id, steam_login, rent_end FROM accounts WHERE status='busy' ORDER BY steam_login")
    rows = cursor.fetchall()
    if not rows:
        return await message.answer("РќРµС‚ Р·Р°РЅСЏС‚С‹С… Р°РєРєР°СѓРЅС‚РѕРІ", reply_markup=main_menu)

    kb = ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=login)] for _, login, _ in rows] + [[KeyboardButton(text="РћС‚РјРµРЅР°")]],
        resize_keyboard=True
    )
    await state.set_state(ExtendAccount.select_account)
    await state.update_data(accounts=rows)
    await message.answer("Р’С‹Р±РµСЂРёС‚Рµ Р°РєРєР°СѓРЅС‚ РґР»СЏ РїСЂРѕРґР»РµРЅРёСЏ:", reply_markup=kb)

@dp.message(StateFilter(ExtendAccount.select_account))
async def extend_select(message: types.Message, state: FSMContext):
    login = message.text.strip()
    data = await state.get_data()
    row = next((r for r in data.get("accounts", []) if r[1] == login), None)

    if row is None:
        return await message.answer("РђРєРєР°СѓРЅС‚ РЅРµ РЅР°Р№РґРµРЅ РІ СЃРїРёСЃРєРµ Р·Р°РЅСЏС‚С‹С…", reply_markup=main_menu)

    aid, _, current_end = row
    await state.update_data(selected_id=aid, selected_login=login, current_end=current_end)

    times_kb = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="+1 С‡Р°СЃ"), KeyboardButton(text="+2 С‡Р°СЃР°"), KeyboardButton(text="+3 С‡Р°СЃР°")],
            [KeyboardButton(text="+6 С‡Р°СЃРѕРІ"), KeyboardButton(text="+12 С‡Р°СЃРѕРІ"), KeyboardButton(text="+24 С‡Р°СЃР°")],
            [KeyboardButton(text="РћС‚РјРµРЅР°")]
        ],
        resize_keyboard=True
    )
    await state.set_state(ExtendAccount.select_time)
    await message.answer("РќР° СЃРєРѕР»СЊРєРѕ РїСЂРѕРґР»РёС‚СЊ?", reply_markup=times_kb)

@dp.message(StateFilter(ExtendAccount.select_time))
async def extend_confirm(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()
    if txt == "РѕС‚РјРµРЅР°":
        await state.clear()
        return await message.answer("РџСЂРѕРґР»РµРЅРёРµ РѕС‚РјРµРЅРµРЅРѕ", reply_markup=main_menu)

    if not txt.startswith("+") or not any(txt[1:].startswith(str(h)) for h in (1,2,3,6,12,24)):
        return await message.answer("Р’С‹Р±РµСЂРёС‚Рµ РІСЂРµРјСЏ РёР· СЃРїРёСЃРєР°", reply_markup=main_menu)

    hours = int(txt[1:].split()[0])
    data = await state.get_data()
    aid = data["selected_id"]
    login = data["selected_login"]
    cur_end_str = data.get("current_end")

    try:
        cur_end = datetime.fromisoformat(cur_end_str) if cur_end_str else datetime.now()
    except:
        cur_end = datetime.now()

    new_end = cur_end + timedelta(hours=hours)

    try:
        cursor.execute(
            "UPDATE accounts SET rent_end = ? WHERE id = ? AND status = 'busy'",
            (new_end.isoformat(), aid)
        )
        if cursor.rowcount == 0:
            conn.rollback()
            await message.answer("РђРєРєР°СѓРЅС‚ СѓР¶Рµ СЃРІРѕР±РѕРґРµРЅ РёР»Рё СѓРґР°Р»С‘РЅ", reply_markup=main_menu)
        else:
            conn.commit()
            await message.answer(
                f"РђРєРєР°СѓРЅС‚ **{login}** РїСЂРѕРґР»С‘РЅ РґРѕ {new_end.strftime('%d.%m %H:%M')}",
                reply_markup=main_menu
            )
    except Exception as e:
        conn.rollback()
        logging.error(f"extend error: {e}")
        await message.answer("РћС€РёР±РєР° РїСЂРѕРґР»РµРЅРёСЏ", reply_markup=main_menu)

    await state.clear()

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  Р¤РѕРЅРѕРІР°СЏ РїСЂРѕРІРµСЂРєР° РѕРєРѕРЅС‡Р°РЅРёСЏ Р°СЂРµРЅРґС‹
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

async def checker_loop():
    while True:
        try:
            clean_invalid_dates()
            cursor.execute("SELECT id, steam_login, rent_end FROM accounts WHERE status='busy'")
            for row in cursor.fetchall():
                try:
                    end = datetime.fromisoformat(row[2])
                    left = (end - datetime.now()).total_seconds()
                    if 240 < left < 300:
                        for admin_id in ADMIN_IDS:
                            await bot.send_message(admin_id, f"вљ пёЏ {row[1]} вЂ” ~5 РјРёРЅСѓС‚ РґРѕ РєРѕРЅС†Р°")
                    if left <= 0:
                        cursor.execute("UPDATE accounts SET status='free', rent_end=NULL WHERE id=?", (row[0],))
                        conn.commit()
                        for admin_id in ADMIN_IDS:
                            await bot.send_message(admin_id, f"вњ… {row[1]} РѕСЃРІРѕР±РѕР¶РґС‘РЅ Р°РІС‚РѕРјР°С‚РёС‡РµСЃРєРё")
                except:
                    pass
        except Exception as e:
            logging.error(f"checker_loop: {e}")
        await asyncio.sleep(30)

# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
#  Р—Р°РїСѓСЃРє
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

async def main():
    migrate_encryption()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.create_task(checker_loop())
    print("Р‘РѕС‚ Р·Р°РїСѓС‰РµРЅ")
    await dp.start_polling(bot, allowed_updates=["message"])

if __name__ == "__main__":
    asyncio.run(main())

