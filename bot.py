import asyncio
import sqlite3
import logging
import os
import shutil
import tempfile
import re
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, unquote, parse_qs
import base64
import hashlib
import hmac
import struct
import time
import random
import threading
from zoneinfo import ZoneInfo

import aiohttp
from dotenv import load_dotenv, dotenv_values
from cryptography.fernet import Fernet, InvalidToken

from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command, StateFilter
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton, FSInputFile, InlineKeyboardMarkup, InlineKeyboardButton, CopyTextButton
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.context import FSMContext

try:
    from FunPayAPI import Account as FunPayAccount
    from FunPayAPI import Runner as FunPayRunner
    from FunPayAPI import enums as FunPayEnums
except Exception:
    FunPayAccount = None
    FunPayRunner = None
    FunPayEnums = None

try:
    LOCAL_TIMEZONE = ZoneInfo("Asia/Omsk")
except Exception:
    LOCAL_TIMEZONE = timezone.utc

# ────────────────────────────────────────────────
#  Настройки и шифрование
# ────────────────────────────────────────────────

load_dotenv()

TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID_RAW = os.getenv("ADMIN_ID") or ""
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
DATA_DIR = os.getenv("DATA_DIR", "/app/data")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
DATA_ENV_PATH = os.path.join(DATA_DIR, ".env")
FACEIT_API_KEY_RUNTIME = os.getenv("FACEIT_API_KEY") or ""

os.makedirs(BACKUP_DIR, exist_ok=True)

DATA_ENV_VALUES = dotenv_values(DATA_ENV_PATH) if os.path.exists(DATA_ENV_PATH) else {}

FACEIT_API_KEY = FACEIT_API_KEY_RUNTIME or (DATA_ENV_VALUES.get("FACEIT_API_KEY") or "")


def log_runtime_config():
    faceit_key, source = resolve_faceit_api_key_with_source()
    data_env_exists = os.path.exists(DATA_ENV_PATH)
    if faceit_key:
        logging.info("FACEIT_API_KEY loaded: yes, length=%d, source=%s", len(faceit_key), source)
    else:
        logging.warning("FACEIT_API_KEY loaded: no, data_env_exists=%s", data_env_exists)


def _parse_admin_ids(raw: str) -> list[int]:
    # Поддержка формата:
    #   ADMIN_ID=123456789
    #   ADMIN_ID=123456789,987654321,555666777
    #   ADMIN_ID=123456789 987654321 (через пробелы тоже)
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
                raise SystemExit(f"❌ ADMIN_ID содержит нечисловой идентификатор: {token!r}")
            ids.append(int(token))
    return ids

ADMIN_IDS = _parse_admin_ids(ADMIN_ID_RAW)

if not all([TOKEN, ADMIN_IDS, ENCRYPTION_KEY]):
    raise SystemExit("❌ В .env должны быть BOT_TOKEN, ADMIN_ID (можно несколько через запятую), ENCRYPTION_KEY")

def _normalize_fernet_key(key: str) -> bytes:
    """
    Fernet key должна быть base64url строкой (обычно 44 символа, заканчивается на '=')
    Иногда в .env ключ копируют без padding или с пробелами/кавычками.
    """
    k = (key or "").strip()

    # Уберём возможные обрамляющие кавычки
    if (k.startswith('"') and k.endswith('"')) or (k.startswith("'") and k.endswith("'")):
        k = k[1:-1]

    # Уберём пробелы/переносы строк внутри
    k = "".join(k.split())

    # Добавим padding base64url, если не кратно 4
    rem = len(k) % 4
    if rem:
        k = k + ("=" * (4 - rem))

    return k.encode()

try:
    cipher = Fernet(_normalize_fernet_key(ENCRYPTION_KEY))
except Exception as e:
    raise SystemExit(
        "❌ ENCRYPTION_KEY не является корректным Fernet-ключом. "
        "Проверьте переменную окружения/файл .env (ключ Fernet.generate_key())."
    ) from e

def encrypt(text: str | None) -> str | None:
    if text is None: return None
    return cipher.encrypt(text.encode()).decode()

def decrypt(encrypted: str | None) -> str | None:
    if encrypted is None: return None
    try:
        return cipher.decrypt(encrypted.encode()).decode()
    except InvalidToken:
        return "[ошибка расшифровки — старый формат]"


def get_db_path() -> str:
    return os.path.abspath("accounts.db")


def create_backup_filename() -> str:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(BACKUP_DIR, f"accounts_{stamp}.db")


def get_setting_raw(key: str) -> str | None:
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    return row[0] if row else None


def set_setting_raw(key: str, value: str | None) -> None:
    if value is None:
        cursor.execute("DELETE FROM settings WHERE key = ?", (key,))
    else:
        cursor.execute(
            """
            INSERT INTO settings(key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value=excluded.value
            """,
            (key, value),
        )
    conn.commit()


def get_faceit_api_key_from_storage() -> str:
    raw_value = get_setting_raw("faceit_api_key")
    if raw_value:
        try:
            return decrypt(raw_value) or ""
        except Exception:
            return ""
    return ""


def set_faceit_api_key(value: str | None) -> None:
    if value is None or not value.strip():
        set_setting_raw("faceit_api_key", None)
        logging.info("FACEIT API key removed from settings")
    else:
        set_setting_raw("faceit_api_key", encrypt(value.strip()))
        logging.info("FACEIT API key updated in settings")


def resolve_faceit_api_key_with_source() -> tuple[str, str]:
    stored_key = get_faceit_api_key_from_storage()
    if stored_key:
        return stored_key, "settings db"

    runtime_key = (os.getenv("FACEIT_API_KEY") or "").strip()
    if runtime_key:
        return runtime_key, "runtime env"

    file_key = (DATA_ENV_VALUES.get("FACEIT_API_KEY") or "").strip()
    if file_key:
        return file_key, "data env file"

    return "", "missing"


def resolve_faceit_api_key() -> str:
    key, _ = resolve_faceit_api_key_with_source()
    return key


def get_funpay_golden_key_from_storage() -> str:
    raw_value = get_setting_raw("funpay_golden_key")
    if raw_value:
        try:
            return decrypt(raw_value) or ""
        except Exception:
            return ""
    return ""


def set_funpay_golden_key(value: str | None) -> None:
    if value is None or not value.strip():
        set_setting_raw("funpay_golden_key", None)
        logging.info("FunPay golden key removed from settings")
    else:
        set_setting_raw("funpay_golden_key", encrypt(value.strip()))
        logging.info("FunPay golden key updated in settings")


def resolve_funpay_golden_key() -> str:
    return get_funpay_golden_key_from_storage()


def get_funpay_user_agent_from_storage() -> str:
    raw_value = get_setting_raw("funpay_user_agent")
    if raw_value:
        try:
            return decrypt(raw_value) or ""
        except Exception:
            return ""
    return ""


def set_funpay_user_agent(value: str | None) -> None:
    if value is None or not value.strip():
        set_setting_raw("funpay_user_agent", None)
        logging.info("FunPay user-agent removed from settings")
    else:
        set_setting_raw("funpay_user_agent", encrypt(value.strip()))
        logging.info("FunPay user-agent updated in settings")


def resolve_funpay_user_agent() -> str:
    return get_funpay_user_agent_from_storage()


def get_steam_api_key_from_storage() -> str:
    raw_value = get_setting_raw("steam_api_key")
    if raw_value:
        try:
            return decrypt(raw_value) or ""
        except Exception:
            return ""
    return ""


def set_steam_api_key(value: str | None) -> None:
    if value is None or not value.strip():
        set_setting_raw("steam_api_key", None)
        logging.info("Steam API key removed from settings")
    else:
        set_setting_raw("steam_api_key", encrypt(value.strip()))
        logging.info("Steam API key updated in settings")


def resolve_steam_api_key() -> str:
    return get_steam_api_key_from_storage()


def get_funpay_auto_raise_enabled() -> bool:
    value = (get_setting_raw("funpay_auto_raise_enabled") or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def set_funpay_auto_raise_enabled(enabled: bool) -> None:
    set_setting_raw("funpay_auto_raise_enabled", "1" if enabled else "0")


def _schedule_next_funpay_auto_raise(now_ts: float, mode: str = "normal") -> int:
    global FUNPAY_AUTO_RAISE_NEXT_RUN_TS

    if mode == "warmup":
        delay = random.randint(
            FUNPAY_AUTO_RAISE_WARMUP_MIN_SECONDS,
            FUNPAY_AUTO_RAISE_WARMUP_MAX_SECONDS,
        )
    elif mode == "error":
        delay = random.randint(
            FUNPAY_AUTO_RAISE_ERROR_BACKOFF_MIN_SECONDS,
            FUNPAY_AUTO_RAISE_ERROR_BACKOFF_MAX_SECONDS,
        )
    else:
        raw_delay = FUNPAY_AUTO_RAISE_INTERVAL_SECONDS + random.randint(
            -FUNPAY_AUTO_RAISE_JITTER_SECONDS,
            FUNPAY_AUTO_RAISE_JITTER_SECONDS,
        )
        delay = max(1800, raw_delay)

    FUNPAY_AUTO_RAISE_NEXT_RUN_TS = now_ts + delay
    return delay


def _clear_funpay_auto_raise_schedule() -> None:
    global FUNPAY_AUTO_RAISE_NEXT_RUN_TS, FUNPAY_AUTO_RAISE_ROTATION_OFFSET
    FUNPAY_AUTO_RAISE_NEXT_RUN_TS = 0.0
    FUNPAY_AUTO_RAISE_ROTATION_OFFSET = 0


def get_funpay_next_auto_raise_in() -> str:
    if FUNPAY_AUTO_RAISE_NEXT_RUN_TS <= 0:
        return "не запланирован"

    try:
        now_ts = asyncio.get_running_loop().time()
    except RuntimeError:
        now_ts = time.monotonic()
    left = max(0, int(FUNPAY_AUTO_RAISE_NEXT_RUN_TS - now_ts))
    return format_interval_seconds(left)


def funpay_toggle_auto_raise() -> bool:
    global FUNPAY_AUTO_RAISE_LAST_RUN
    new_value = not get_funpay_auto_raise_enabled()
    set_funpay_auto_raise_enabled(new_value)
    now_ts = asyncio.get_running_loop().time()
    if new_value:
        _schedule_next_funpay_auto_raise(now_ts, "warmup")
    else:
        _clear_funpay_auto_raise_schedule()
    FUNPAY_AUTO_RAISE_LAST_RUN = 0.0
    logging.info("FunPay auto raise toggled to %s", new_value)
    return new_value


def funpay_ensure_available() -> None:
    if FunPayAccount is None:
        raise RuntimeError(
            "Библиотека FunPayAPI не установлена. Установите пакет `FunPayAPI`."
        )


def get_funpay_op_lock() -> asyncio.Lock:
    global FUNPAY_OP_LOCK
    if FUNPAY_OP_LOCK is None:
        FUNPAY_OP_LOCK = asyncio.Lock()
    return FUNPAY_OP_LOCK

# ────────────────────────────────────────────────
#  База данных
# ────────────────────────────────────────────────

conn = sqlite3.connect("accounts.db", check_same_thread=False)
cursor = conn.cursor()
DB_MAINTENANCE = False
FUNPAY_OP_LOCK: asyncio.Lock | None = None
MAIN_LOOP: asyncio.AbstractEventLoop | None = None
FUNPAY_LISTENER_THREAD_STARTED = False
FUNPAY_LISTENER_THREAD: threading.Thread | None = None
FUNPAY_AUTO_RAISE_LAST_RUN = 0.0
FUNPAY_AUTO_RAISE_NEXT_RUN_TS = 0.0
FUNPAY_AUTO_RAISE_ROTATION_OFFSET = 0
FUNPAY_AUTO_RAISE_INTERVAL_SECONDS = 3600
FUNPAY_AUTO_RAISE_JITTER_SECONDS = 900
FUNPAY_AUTO_RAISE_ERROR_BACKOFF_MIN_SECONDS = 1200
FUNPAY_AUTO_RAISE_ERROR_BACKOFF_MAX_SECONDS = 2700
FUNPAY_AUTO_RAISE_WARMUP_MIN_SECONDS = 480
FUNPAY_AUTO_RAISE_WARMUP_MAX_SECONDS = 1500
FUNPAY_AUTO_RAISE_MAX_CATEGORIES_PER_RUN = 3
FUNPAY_AUTO_RAISE_REQUEST_PAUSE_MIN_SECONDS = 2.0
FUNPAY_AUTO_RAISE_REQUEST_PAUSE_MAX_SECONDS = 6.0

cursor.execute("""
CREATE TABLE IF NOT EXISTS accounts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    steam_login     TEXT UNIQUE NOT NULL,
    steam_password  TEXT,
    email           TEXT,
    email_password  TEXT,
    faceit_url      TEXT,
    faceit_email    TEXT,
    faceit_password TEXT,
    faceit_2fa_secret TEXT,
    status          TEXT DEFAULT 'free',
    rent_end        TEXT
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS settings (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
)
""")
cursor.execute("""
CREATE TABLE IF NOT EXISTS rent_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id      INTEGER NOT NULL,
    steam_login     TEXT NOT NULL,
    rent_package    TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    planned_end_at  TEXT NOT NULL,
    actual_end_at   TEXT,
    close_reason    TEXT
)
""")
conn.commit()


def ensure_faceit_block_columns():
    cursor.execute("PRAGMA table_info(accounts)")
    columns = {row[1] for row in cursor.fetchall()}

    additions = [
        ("faceit_blocked", "INTEGER DEFAULT 0"),
        ("faceit_block_ends_at", "TEXT"),
        ("faceit_block_reason", "TEXT"),
        ("faceit_block_type", "TEXT"),
        ("faceit_block_game", "TEXT"),
        ("faceit_ban_signature", "TEXT"),
        ("faceit_block_last_checked_at", "TEXT"),
        ("faceit_block_source", "TEXT DEFAULT 'api'"),
    ]

    changed = False
    for column_name, column_def in additions:
        if column_name not in columns:
            cursor.execute(f"ALTER TABLE accounts ADD COLUMN {column_name} {column_def}")
            changed = True

    if changed:
        conn.commit()


def ensure_steam_block_columns():
    cursor.execute("PRAGMA table_info(accounts)")
    columns = {row[1] for row in cursor.fetchall()}

    additions = [
        ("steam_blocked", "INTEGER DEFAULT 0"),
        ("steam_block_ends_at", "TEXT"),
        ("steam_block_reason", "TEXT"),
        ("steam_block_type", "TEXT"),
        ("steam_block_source", "TEXT DEFAULT 'manual'"),
    ]

    changed = False
    for column_name, column_def in additions:
        if column_name not in columns:
            cursor.execute(f"ALTER TABLE accounts ADD COLUMN {column_name} {column_def}")
            changed = True

    if changed:
        conn.commit()


def ensure_faceit_2fa_column():
    cursor.execute("PRAGMA table_info(accounts)")
    columns = {row[1] for row in cursor.fetchall()}
    if "faceit_2fa_secret" not in columns:
        cursor.execute("ALTER TABLE accounts ADD COLUMN faceit_2fa_secret TEXT")
        conn.commit()


def ensure_steam_shared_secret_column():
    cursor.execute("PRAGMA table_info(accounts)")
    columns = {row[1] for row in cursor.fetchall()}
    if "steam_shared_secret" not in columns:
        cursor.execute("ALTER TABLE accounts ADD COLUMN steam_shared_secret TEXT")
        conn.commit()


def ensure_steam_trade_columns():
    cursor.execute("PRAGMA table_info(accounts)")
    columns = {row[1] for row in cursor.fetchall()}

    additions = [
        ("steam_identity_secret", "TEXT"),
        ("steam_device_id", "TEXT"),
        ("steam_mafile_name", "TEXT"),
        ("steam_session_id", "TEXT"),
        ("steam_login_cookie", "TEXT"),
        ("steam_login_secure_cookie", "TEXT"),
        ("steam_webcookie", "TEXT"),
        ("steam_steamid64", "TEXT"),
        ("steam_access_token", "TEXT"),
        ("steam_refresh_token", "TEXT"),
    ]

    changed = False
    for column_name, column_def in additions:
        if column_name not in columns:
            cursor.execute(f"ALTER TABLE accounts ADD COLUMN {column_name} {column_def}")
            changed = True

    if changed:
        conn.commit()


def ensure_steam_presence_columns():
    cursor.execute("PRAGMA table_info(accounts)")
    columns = {row[1] for row in cursor.fetchall()}

    additions = [
        ("steam_presence_state", "TEXT"),
        ("steam_presence_game", "TEXT"),
        ("steam_presence_checked_at", "TEXT"),
    ]

    changed = False
    for column_name, column_def in additions:
        if column_name not in columns:
            cursor.execute(f"ALTER TABLE accounts ADD COLUMN {column_name} {column_def}")
            changed = True

    if changed:
        conn.commit()


def ensure_account_note_columns():
    cursor.execute("PRAGMA table_info(accounts)")
    columns = {row[1] for row in cursor.fetchall()}

    additions = [
        ("account_note", "TEXT"),
        ("weekly_drop_claimed_period", "TEXT"),
        ("weekly_drop_claimed_at", "TEXT"),
    ]

    changed = False
    for column_name, column_def in additions:
        if column_name not in columns:
            cursor.execute(f"ALTER TABLE accounts ADD COLUMN {column_name} {column_def}")
            changed = True

    if changed:
        conn.commit()


def ensure_funpay_order_columns():
    cursor.execute("PRAGMA table_info(accounts)")
    columns = {row[1] for row in cursor.fetchall()}

    additions = [
        ("funpay_order_id", "TEXT"),
        ("funpay_order_url", "TEXT"),
        ("funpay_order_status", "TEXT"),
        ("funpay_order_price", "TEXT"),
        ("funpay_order_buyer", "TEXT"),
        ("funpay_order_chat_id", "TEXT"),
        ("funpay_order_last_sync_at", "TEXT"),
        ("funpay_order_last_code_sent_at", "TEXT"),
        ("rent_reminder_5m_sent_at", "TEXT"),
        ("rent_overdue_notified_at", "TEXT"),
    ]

    changed = False
    for column_name, column_def in additions:
        if column_name not in columns:
            cursor.execute(f"ALTER TABLE accounts ADD COLUMN {column_name} {column_def}")
            changed = True

    if changed:
        conn.commit()


def ensure_rent_history_table():
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS rent_history (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id      INTEGER NOT NULL,
            steam_login     TEXT NOT NULL,
            rent_package    TEXT NOT NULL,
            started_at      TEXT NOT NULL,
            planned_end_at  TEXT NOT NULL,
            actual_end_at   TEXT,
            close_reason    TEXT
        )
        """
    )
    conn.commit()


def ensure_faceit_url_column():
    cursor.execute("PRAGMA table_info(accounts)")
    columns = {row[1] for row in cursor.fetchall()}
    if "faceit_url" not in columns:
        cursor.execute("ALTER TABLE accounts ADD COLUMN faceit_url TEXT")
        conn.commit()

def migrate_encryption():
    cursor.execute(
        """
        SELECT id, steam_password, email_password, faceit_password,
               faceit_2fa_secret, steam_shared_secret, steam_identity_secret,
               steam_session_id, steam_login_cookie, steam_login_secure_cookie, steam_webcookie,
               steam_access_token, steam_refresh_token
          FROM accounts
        """
    )
    updated = False
    for row in cursor.fetchall():
        (
            aid, sp, ep, fp, secret, steam_secret, steam_identity_secret,
            steam_session_id, steam_login_cookie, steam_login_secure_cookie, steam_webcookie,
            steam_access_token, steam_refresh_token
        ) = row
        if sp and not sp.startswith("gAAAA"):
            cursor.execute("UPDATE accounts SET steam_password=? WHERE id=?", (encrypt(sp), aid))
            updated = True
        if ep and not ep.startswith("gAAAA"):
            cursor.execute("UPDATE accounts SET email_password=? WHERE id=?", (encrypt(ep), aid))
            updated = True
        if fp and not fp.startswith("gAAAA"):
            cursor.execute("UPDATE accounts SET faceit_password=? WHERE id=?", (encrypt(fp), aid))
            updated = True
        if secret and not secret.startswith("gAAAA"):
            cursor.execute("UPDATE accounts SET faceit_2fa_secret=? WHERE id=?", (encrypt(secret), aid))
            updated = True
        if steam_secret and not steam_secret.startswith("gAAAA"):
            cursor.execute("UPDATE accounts SET steam_shared_secret=? WHERE id=?", (encrypt(steam_secret), aid))
            updated = True
        if steam_identity_secret and not steam_identity_secret.startswith("gAAAA"):
            cursor.execute("UPDATE accounts SET steam_identity_secret=? WHERE id=?", (encrypt(steam_identity_secret), aid))
            updated = True
        if steam_session_id and not steam_session_id.startswith("gAAAA"):
            cursor.execute("UPDATE accounts SET steam_session_id=? WHERE id=?", (encrypt(steam_session_id), aid))
            updated = True
        if steam_login_cookie and not steam_login_cookie.startswith("gAAAA"):
            cursor.execute("UPDATE accounts SET steam_login_cookie=? WHERE id=?", (encrypt(steam_login_cookie), aid))
            updated = True
        if steam_login_secure_cookie and not steam_login_secure_cookie.startswith("gAAAA"):
            cursor.execute("UPDATE accounts SET steam_login_secure_cookie=? WHERE id=?", (encrypt(steam_login_secure_cookie), aid))
            updated = True
        if steam_webcookie and not steam_webcookie.startswith("gAAAA"):
            cursor.execute("UPDATE accounts SET steam_webcookie=? WHERE id=?", (encrypt(steam_webcookie), aid))
            updated = True
        if steam_access_token and not steam_access_token.startswith("gAAAA"):
            cursor.execute("UPDATE accounts SET steam_access_token=? WHERE id=?", (encrypt(steam_access_token), aid))
            updated = True
        if steam_refresh_token and not steam_refresh_token.startswith("gAAAA"):
            cursor.execute("UPDATE accounts SET steam_refresh_token=? WHERE id=?", (encrypt(steam_refresh_token), aid))
            updated = True
    if updated:
        conn.commit()
    logging.info("Миграция шифрования завершена")

# ────────────────────────────────────────────────
#  Состояния FSM
# ────────────────────────────────────────────────

class AddAccount(StatesGroup):
    steam_login     = State()
    steam_password  = State()
    email           = State()
    email_password  = State()
    faceit_choice   = State()
    faceit_url      = State()
    faceit_email    = State()
    faceit_password = State()
    confirm         = State()

class RentAccount(StatesGroup):
    mode = State()
    select_account = State()
    select_time    = State()
    enter_order    = State()

class ExtendAccount(StatesGroup):
    select_account = State()
    select_time    = State()

class FreeAccount(StatesGroup):
    select_account = State()

class AccountDetails(StatesGroup):
    select_account = State()
    view_action = State()

class AccountDrop(StatesGroup):
    menu = State()

class EditAccount(StatesGroup):
    choose_field = State()
    enter_value = State()
    wait_mafile = State()

class DeleteAccount(StatesGroup):
    confirm = State()

class BlockAccount(StatesGroup):
    menu = State()

class TradeMenu(StatesGroup):
    menu = State()
    wait_mafile = State()

class DataBackup(StatesGroup):
    choose_action = State()
    restore_wait_file = State()
    faceit_api_menu = State()
    faceit_api_wait_key = State()
    steam_api_menu = State()
    steam_api_wait_key = State()
    funpay_menu = State()
    funpay_wait_key = State()
    funpay_wait_user_agent = State()


class FunPayMenu(StatesGroup):
    menu = State()


class StatusMenu(StatesGroup):
    menu = State()

# ────────────────────────────────────────────────
#  Бот и клавиатуры
# ────────────────────────────────────────────────

bot = Bot(token=TOKEN, timeout=120)
dp = Dispatcher()

cancel_kb = ReplyKeyboardMarkup(
    keyboard=[[KeyboardButton(text="Отмена")]],
    resize_keyboard=True
)

skip_or_cancel_kb = ReplyKeyboardMarkup(
    keyboard=[[KeyboardButton(text="Пропустить")], [KeyboardButton(text="Отмена")]],
    resize_keyboard=True
)

main_menu = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="📊 Статус"),     KeyboardButton(text="📦 Аккаунты")],
        [KeyboardButton(text="➕ Добавить"),    KeyboardButton(text="🎮 Сдать")],
        [KeyboardButton(text="🎯 FunPay"),      KeyboardButton(text="⏱ Продлить")],
        [KeyboardButton(text="✅ Освободить")],
        [KeyboardButton(text="💾 Данные")]
    ],
    resize_keyboard=True
)


def status_menu_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="Статистика аренд")],
            [KeyboardButton(text="Проверка блокировок Faceit")],
            [KeyboardButton(text="Назад")],
        ],
        resize_keyboard=True
    )

# ────────────────────────────────────────────────
#  Вспомогательные функции
# ────────────────────────────────────────────────

def clean_invalid_dates():
    try:
        conn.execute("""
            UPDATE accounts
               SET status = 'free',
                   rent_end = NULL
             WHERE status = 'busy'
               AND (rent_end IS NULL OR rent_end = '' OR rent_end <= datetime('now'))
        """)
        conn.commit()
    except Exception as e:
        logging.error(f"clean_invalid_dates error: {e}")


def clean_expired_faceit_blocks():
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, faceit_block_ends_at
              FROM accounts
             WHERE faceit_blocked = 1
               AND faceit_block_ends_at IS NOT NULL
            """
        )
        expired_ids = []
        for aid, ends_at_raw in cur.fetchall():
            ends_at = parse_iso_datetime(ends_at_raw)
            if ends_at is None:
                continue
            local_now = datetime.now(ends_at.tzinfo) if ends_at.tzinfo else datetime.now()
            if ends_at <= local_now:
                expired_ids.append(aid)

        for aid in expired_ids:
            conn.execute(
                """
                UPDATE accounts
                   SET faceit_blocked = 0,
                       faceit_block_ends_at = NULL,
                       faceit_block_reason = NULL,
                       faceit_block_type = NULL,
                       faceit_block_game = NULL,
                       faceit_ban_signature = NULL,
                       faceit_block_source = NULL,
                       faceit_block_last_checked_at = NULL
                 WHERE id = ?
                """,
                (aid,),
            )
        if expired_ids:
            conn.commit()
    except Exception as e:
        logging.error(f"clean_expired_faceit_blocks error: {e}")


def clean_expired_steam_blocks():
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, steam_block_ends_at
              FROM accounts
             WHERE steam_blocked = 1
               AND steam_block_ends_at IS NOT NULL
            """
        )
        expired_ids = []
        for aid, ends_at_raw in cur.fetchall():
            ends_at = parse_iso_datetime(ends_at_raw)
            if ends_at is None:
                continue
            local_now = datetime.now(ends_at.tzinfo) if ends_at.tzinfo else datetime.now()
            if ends_at <= local_now:
                expired_ids.append(aid)

        for aid in expired_ids:
            conn.execute(
                """
                UPDATE accounts
                   SET steam_blocked = 0,
                       steam_block_ends_at = NULL,
                       steam_block_reason = NULL,
                       steam_block_type = NULL,
                       steam_block_source = NULL
                 WHERE id = ?
                """,
                (aid,),
            )
        if expired_ids:
            conn.commit()
    except Exception as e:
        logging.error(f"clean_expired_steam_blocks error: {e}")


def get_account_by_id(aid: int):
    cursor.execute(
        """
        SELECT steam_login, steam_password, email, email_password, faceit_url, faceit_email, faceit_password, status, rent_end,
               COALESCE(faceit_blocked, 0),
               faceit_block_ends_at,
               faceit_block_reason,
               faceit_block_type,
               faceit_block_game,
               faceit_ban_signature,
               faceit_block_last_checked_at,
               faceit_block_source,
               COALESCE(steam_blocked, 0),
               steam_block_ends_at,
               steam_block_reason,
               steam_block_type,
               steam_block_source,
               faceit_2fa_secret,
               steam_shared_secret,
               steam_identity_secret,
               steam_device_id,
               steam_mafile_name,
               steam_session_id,
               steam_login_cookie,
               steam_login_secure_cookie,
               steam_webcookie,
               steam_steamid64,
               steam_access_token,
               steam_refresh_token,
               steam_presence_state,
               steam_presence_game,
               steam_presence_checked_at,
               account_note,
               weekly_drop_claimed_period,
               weekly_drop_claimed_at,
               funpay_order_id,
               funpay_order_url,
               funpay_order_status,
               funpay_order_price,
               funpay_order_buyer,
               funpay_order_chat_id,
               funpay_order_last_sync_at,
               funpay_order_last_code_sent_at,
               rent_reminder_5m_sent_at,
               rent_overdue_notified_at
          FROM accounts
         WHERE id = ?
        """,
        (aid,),
    )
    return cursor.fetchone()


def get_account_by_funpay_order_id(order_id: str):
    cursor.execute(
        """
        SELECT *
          FROM accounts
         WHERE funpay_order_id = ?
           AND status = 'busy'
         LIMIT 1
        """,
        (order_id,),
    )
    return cursor.fetchone()


def add_rent_history_entry(account_id: int, steam_login: str, rent_package: str, started_at: datetime, planned_end_at: datetime) -> None:
    cursor.execute(
        """
        INSERT INTO rent_history (account_id, steam_login, rent_package, started_at, planned_end_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            account_id,
            steam_login,
            rent_package,
            started_at.isoformat(),
            planned_end_at.isoformat(),
        ),
    )


def close_open_rent_history(account_id: int, actual_end_at: datetime, close_reason: str) -> None:
    cursor.execute(
        """
        UPDATE rent_history
           SET actual_end_at = ?,
               close_reason = ?
         WHERE id = (
            SELECT id
              FROM rent_history
             WHERE account_id = ?
               AND actual_end_at IS NULL
             ORDER BY id DESC
             LIMIT 1
         )
        """,
        (actual_end_at.isoformat(), close_reason, account_id),
    )


def update_open_rent_history_planned_end(account_id: int, new_planned_end_at: datetime) -> None:
    cursor.execute(
        """
        UPDATE rent_history
           SET planned_end_at = ?
         WHERE id = (
            SELECT id
              FROM rent_history
             WHERE account_id = ?
               AND actual_end_at IS NULL
             ORDER BY id DESC
             LIMIT 1
         )
        """,
        (new_planned_end_at.isoformat(), account_id),
    )


def get_rent_history(account_id: int, limit: int = 10) -> list[tuple]:
    cursor.execute(
        """
        SELECT started_at, planned_end_at, actual_end_at, rent_package, close_reason
          FROM rent_history
         WHERE account_id = ?
         ORDER BY id DESC
         LIMIT ?
        """,
        (account_id, limit),
    )
    return cursor.fetchall()


def format_rent_history_text(steam_login: str, rows: list[tuple]) -> str:
    if not rows:
        return f"История аренд для {steam_login} пока пустая."

    lines = [f"История аренд: {steam_login}", ""]
    for idx, (started_at_raw, planned_end_raw, actual_end_raw, rent_package, close_reason) in enumerate(rows, start=1):
        started_at = parse_iso_datetime(started_at_raw)
        planned_end = parse_iso_datetime(planned_end_raw)
        actual_end = parse_iso_datetime(actual_end_raw)

        package_label = "Steam + Faceit" if rent_package == "steam_faceit" else "Steam only"
        start_text = started_at.strftime("%d.%m %H:%M") if started_at else "-"
        planned_text = planned_end.strftime("%d.%m %H:%M") if planned_end else "-"

        if actual_end:
            end_text = actual_end.strftime("%d.%m %H:%M")
            reason_map = {
                "manual_free": "завершена вручную",
                "auto_free": "завершена автоматически",
                "deleted": "завершена при удалении аккаунта",
            }
            status_text = reason_map.get(close_reason or "", "завершена")
            lines.append(f"{idx}. {start_text} - {end_text} | {package_label} | {status_text}")
        else:
            left_text = format_remaining_time(planned_end) if planned_end else "неизвестно"
            lines.append(f"{idx}. {start_text} - {planned_text} | {package_label} | активна ({left_text})")

    return "\n".join(lines)


def get_current_drop_period_start(now: datetime | None = None) -> str:
    current = now or datetime.now(LOCAL_TIMEZONE)
    if current.tzinfo is None:
        current = current.replace(tzinfo=LOCAL_TIMEZONE)
    else:
        current = current.astimezone(LOCAL_TIMEZONE)

    days_since_wednesday = (current.weekday() - 2) % 7
    period_start = (current - timedelta(days=days_since_wednesday)).replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
    )
    return period_start.date().isoformat()


def get_weekly_drop_status(row) -> tuple[bool, str | None, str | None]:
    claimed_period = None
    claimed_at = None
    if row and len(row) > 30:
        claimed_period = row[29]
        claimed_at = row[30]

    current_period = get_current_drop_period_start()
    return claimed_period == current_period, claimed_period, claimed_at


def set_weekly_drop_claimed(aid: int, claimed: bool) -> None:
    current_period = get_current_drop_period_start()
    cursor.execute(
        """
        UPDATE accounts
           SET weekly_drop_claimed_period = ?,
               weekly_drop_claimed_at = ?
         WHERE id = ?
        """,
        (
            current_period if claimed else None,
            datetime.now(timezone.utc).isoformat() if claimed else None,
            aid,
        ),
    )


def format_weekly_drop_label(row) -> str:
    claimed, _, _ = get_weekly_drop_status(row)
    if claimed:
        return "🟢 еженедельный дроп забран"
    return "🔴 еженедельный дроп не забран"


def get_next_drop_reset(now: datetime | None = None) -> datetime:
    current = now or datetime.now(LOCAL_TIMEZONE)
    if current.tzinfo is None:
        current = current.replace(tzinfo=LOCAL_TIMEZONE)
    else:
        current = current.astimezone(LOCAL_TIMEZONE)

    days_until_wednesday = (2 - current.weekday()) % 7
    next_reset = (current + timedelta(days=days_until_wednesday)).replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
    )
    if next_reset <= current:
        next_reset += timedelta(days=7)
    return next_reset


def format_account_note_preview(note: str | None) -> str:
    if not note:
        return "нет"

    normalized = " ".join(str(note).split())
    if len(normalized) <= 180:
        return normalized
    return normalized[:177] + "..."


def build_weekly_drop_menu_text(row) -> str:
    login = row[0] if row else "-"
    claimed, claimed_period, claimed_at = get_weekly_drop_status(row)
    claimed_at_dt = parse_iso_datetime(claimed_at)
    current_period = get_current_drop_period_start()
    current_period_text = datetime.fromisoformat(current_period).strftime("%d.%m.%Y")
    next_reset = get_next_drop_reset()

    lines = [
        f"Еженедельный дроп: {login}",
        "",
        f"Статус: {'🟢 забран' if claimed else '🔴 не забран'}",
        f"Текущий период: {current_period_text}",
        f"Сбросится автоматически: {next_reset.astimezone(LOCAL_TIMEZONE).strftime('%d.%m.%Y %H:%M')}",
    ]

    if claimed_period and claimed_period != current_period:
        try:
            claimed_period_text = datetime.fromisoformat(claimed_period).strftime("%d.%m.%Y")
        except Exception:
            claimed_period_text = claimed_period
        lines.append(f"Последняя отметка: {claimed_period_text}")

    if claimed_at_dt:
        lines.append(f"Отметка поставлена: {claimed_at_dt.astimezone(LOCAL_TIMEZONE).strftime('%d.%m.%Y %H:%M')}")

    lines.extend([
        "",
        "Здесь можно вручную отметить, что недельный дроп забран.",
    ])
    return "\n".join(lines)


FUNPAY_ORDER_ID_RE = re.compile(r"/orders/([A-Za-z0-9]+)/?")


def parse_funpay_order_ref(value: str | None) -> tuple[str | None, str | None]:
    raw = (value or "").strip()
    if not raw or raw.lower() in {"-", "нет", "пусто", "none", "пропустить"}:
        return None, None

    match = FUNPAY_ORDER_ID_RE.search(raw)
    if match:
        order_id = match.group(1).strip().upper()
        return order_id, f"https://funpay.com/orders/{order_id}/"

    cleaned = raw.strip().strip("/")
    if cleaned:
        order_id = cleaned.upper()
        return order_id, f"https://funpay.com/orders/{order_id}/"

    return None, None


def normalize_funpay_order_fields(order_id: str | None, order_url: str | None) -> tuple[str | None, str | None]:
    parsed_id, parsed_url = parse_funpay_order_ref(order_url or order_id)
    if parsed_id and not parsed_url:
        parsed_url = f"https://funpay.com/orders/{parsed_id}/"
    return parsed_id, parsed_url


def _funpay_collect_text_parts(obj, field_names: list[str]) -> list[str]:
    parts: list[str] = []
    for field_name in field_names:
        try:
            value = getattr(obj, field_name, None)
        except Exception:
            value = None
        if value is None:
            continue
        text = str(value).strip()
        if text:
            parts.append(text)
    return parts


def _funpay_detect_faceit_from_text(parts: list[str]) -> bool:
    joined = " ".join(parts).lower()
    if not joined:
        return False
    tokens = ("faceit", "фейсит", "фэйсит")
    return any(token in joined for token in tokens)


def _funpay_find_order_record_sync(order_id: str, user_agent: str | None = None) -> dict:
    golden_key = resolve_funpay_golden_key()
    if not golden_key:
        return {"error": "FunPay golden key не задан"}

    acc = _funpay_build_account_sync(golden_key, user_agent or resolve_funpay_user_agent())
    available_methods = [
        name for name in (
            "get_order",
            "getOrder",
            "getNewOrders",
            "getLastOrders",
            "getDialogs",
            "get_chat_by_name",
            "send_message",
        )
        if callable(getattr(acc, name, None))
    ]

    direct_lookup_errors: list[str] = []
    direct_lookup_methods = ("get_order", "getOrder")
    normalized_id = str(order_id).strip().upper()
    for method_name in direct_lookup_methods:
        method = getattr(acc, method_name, None)
        if method is None:
            continue
        try:
            direct_order = method(normalized_id)
            if direct_order:
                text_parts = _funpay_collect_text_parts(
                    direct_order,
                    ["description", "title", "name", "subject", "label", "text"],
                )
                description = " | ".join(text_parts)
                buyer_username = getattr(direct_order, "buyer_username", None) or getattr(direct_order, "buyer", None)
                chat_id = getattr(direct_order, "chat_id", None) or getattr(direct_order, "dialog_id", None)
                if chat_id is None:
                    chat_obj = getattr(direct_order, "chat", None) or getattr(direct_order, "dialog", None)
                    chat_id = getattr(chat_obj, "id", None) if chat_obj is not None else None
                order_status = getattr(direct_order, "status", None) or getattr(direct_order, "state", None)
                order_price = getattr(direct_order, "price", None) or getattr(direct_order, "sum", None)
                return {
                    "id": normalized_id,
                    "description": description,
                    "buyer_username": buyer_username,
                    "chat_id": chat_id,
                    "status": normalize_db_text(order_status),
                    "price": normalize_db_text(order_price),
                    "is_faceit": _funpay_detect_faceit_from_text(text_parts),
                    "debug": {
                        "matched": True,
                        "source": f"direct_lookup:{method_name}",
                        "available_methods": available_methods,
                        "text_parts": text_parts[:10],
                    },
                }
        except Exception as e:
            logging.error(f"FunPay direct order lookup error ({method_name}): {e}")
            direct_lookup_errors.append(f"{method_name}:{e}")

    candidates: list[object] = []
    lookup_sources: list[str] = []
    lookup_errors: list[str] = []
    for getter_name in ("getNewOrders", "getLastOrders"):
        getter = getattr(acc, getter_name, None)
        if getter is None:
            continue
        try:
            items = getter() or []
            candidates.extend(items)
            lookup_sources.append(f"{getter_name}:{len(items)}")
        except Exception as e:
            logging.error(f"FunPay order lookup error ({getter_name}): {e}")
            lookup_errors.append(f"{getter_name}:{e}")

    for order in candidates:
        current_id = str(getattr(order, "id", "") or "").strip().upper()
        if current_id != normalized_id:
            continue

        text_parts = _funpay_collect_text_parts(
            order,
            ["description", "title", "name", "subject", "label", "text"],
        )
        description = " | ".join(text_parts)
        buyer_username = getattr(order, "buyer_username", None) or getattr(order, "buyer", None)
        chat_id = getattr(order, "chat_id", None) or getattr(order, "dialog_id", None)
        if chat_id is None:
            chat_obj = getattr(order, "chat", None) or getattr(order, "dialog", None)
            chat_id = getattr(chat_obj, "id", None) if chat_obj is not None else None
        order_status = getattr(order, "status", None) or getattr(order, "state", None)
        order_price = getattr(order, "price", None) or getattr(order, "sum", None)
        return {
            "id": current_id,
            "description": description,
            "buyer_username": buyer_username,
            "chat_id": chat_id,
            "status": normalize_db_text(order_status),
            "price": normalize_db_text(order_price),
            "is_faceit": _funpay_detect_faceit_from_text(text_parts),
            "debug": {
                "matched": True,
                "source": "orders_lookup",
                "available_methods": available_methods,
                "text_parts": text_parts[:10],
            },
        }

    dialog_candidates: list[object] = []
    try:
        dialogs = getattr(acc, "getDialogs", None)
        if dialogs is not None:
            items = dialogs() or []
            dialog_candidates.extend(items)
            lookup_sources.append(f"getDialogs:{len(items)}")
    except Exception as e:
        logging.error(f"FunPay dialog lookup error: {e}")
        lookup_errors.append(f"getDialogs:{e}")

    for dialog in dialog_candidates:
        dialog_text_parts = _funpay_collect_text_parts(
            dialog,
            ["description", "title", "name", "subject", "label", "text", "last_message", "last_text"],
        )
        dialog_text = " | ".join(dialog_text_parts) or str(dialog)
        if normalized_id not in dialog_text.upper():
            continue

        dialog_id = getattr(dialog, "id", None) or getattr(dialog, "chat_id", None) or getattr(dialog, "dialog_id", None)
        dialog_user = getattr(dialog, "username", None) or getattr(dialog, "buyer_username", None) or getattr(dialog, "user", None)
        if dialog_user is None:
            dialog_user_obj = getattr(dialog, "user", None)
            dialog_user = getattr(dialog_user_obj, "name", None) or getattr(dialog_user_obj, "username", None)
        return {
            "id": normalized_id,
            "description": dialog_text,
            "buyer_username": dialog_user,
            "chat_id": dialog_id,
            "status": normalize_db_text(getattr(dialog, "status", None)),
            "price": normalize_db_text(getattr(dialog, "price", None)),
            "is_faceit": _funpay_detect_faceit_from_text(dialog_text_parts),
            "debug": {
                "matched": True,
                "source": "dialogs_lookup",
                "available_methods": available_methods,
                "text_parts": dialog_text_parts[:10],
            },
        }

    return {
        "id": normalized_id,
        "description": "",
        "buyer_username": None,
        "chat_id": None,
        "status": None,
        "price": None,
        "is_faceit": False,
        "debug": {
            "matched": False,
            "direct_lookup_errors": direct_lookup_errors,
            "lookup_sources": lookup_sources,
            "lookup_errors": lookup_errors,
            "candidate_count": len(candidates),
            "dialog_candidate_count": len(dialog_candidates),
            "available_methods": available_methods,
            "candidate_ids": [
                str(getattr(item, "id", "") or "").strip().upper()
                for item in candidates[:10]
            ],
            "dialog_preview": [
                " | ".join(_funpay_collect_text_parts(item, ["description", "title", "name", "subject", "text"]))[:120]
                for item in dialog_candidates[:5]
            ],
        },
    }


def _funpay_format_order_debug_text(
    stage: str,
    order: dict,
    *,
    fallback_chat_id: int | str | None = None,
    fallback_buyer_username: str | None = None,
    include_faceit: bool | None = None,
    extra_error: str | None = None,
) -> str:
    debug = order.get("debug") or {}
    lines = [
        f"stage={stage}",
        f"order_id={order.get('id') or '-'}",
        f"buyer_username={order.get('buyer_username') or fallback_buyer_username or '-'}",
        f"chat_id={order.get('chat_id') or fallback_chat_id or '-'}",
        f"description={order.get('description') or '-'}",
        f"status={order.get('status') or '-'}",
        f"price={order.get('price') or '-'}",
        f"is_faceit={order.get('is_faceit')}",
        f"fallback_chat_used={bool(fallback_chat_id)}",
        f"fallback_buyer_used={bool(fallback_buyer_username)}",
    ]
    if include_faceit is not None:
        lines.append(f"include_faceit={include_faceit}")
    if extra_error:
        lines.append(f"error={extra_error}")
    if isinstance(debug, dict):
        if "matched" in debug:
            lines.append(f"order_matched={debug.get('matched')}")
        if debug.get("direct_lookup_errors"):
            lines.append(f"direct_lookup_errors={'; '.join(map(str, debug.get('direct_lookup_errors')))}")
        if debug.get("lookup_sources"):
            lines.append(f"lookup_sources={', '.join(map(str, debug.get('lookup_sources')))}")
        if debug.get("lookup_errors"):
            lines.append(f"lookup_errors={'; '.join(map(str, debug.get('lookup_errors')))}")
        if debug.get("candidate_count") is not None:
            lines.append(f"candidate_count={debug.get('candidate_count')}")
        if debug.get("dialog_candidate_count") is not None:
            lines.append(f"dialog_candidate_count={debug.get('dialog_candidate_count')}")
        if debug.get("candidate_ids"):
            lines.append(f"candidate_ids={', '.join(map(str, debug.get('candidate_ids')))}")
        if debug.get("dialog_preview"):
            lines.append(f"dialog_preview={'; '.join(map(str, debug.get('dialog_preview')))}")
        if debug.get("available_methods"):
            lines.append(f"available_methods={', '.join(map(str, debug.get('available_methods')))}")
        if debug.get("source"):
            lines.append(f"source={debug.get('source')}")
    return "FunPay debug:\n" + "\n".join(lines)


def _funpay_send_initial_order_message_sync(
    order_id: str,
    steam_login: str,
    steam_password: str,
    faceit_email: str | None = None,
    faceit_password: str | None = None,
    include_faceit: bool = True,
    persist_account_id: int | None = None,
    fallback_chat_id: int | str | None = None,
    fallback_buyer_username: str | None = None,
    user_agent: str | None = None,
) -> dict:
    golden_key = resolve_funpay_golden_key()
    if not golden_key:
        return {"error": "FunPay golden key не задан"}

    acc = _funpay_build_account_sync(golden_key, user_agent or resolve_funpay_user_agent())
    order = _funpay_find_order_record_sync(order_id, user_agent)
    if order.get("error"):
        return order

    buyer_username = order.get("buyer_username") or fallback_buyer_username
    chat_id = order.get("chat_id") or fallback_chat_id
    chat = None
    if chat_id is None and buyer_username:
        try:
            chat = acc.get_chat_by_name(buyer_username, True)
        except Exception as e:
            return {
                "error": "Не удалось получить чат заказа\n"
                + _funpay_format_order_debug_text(
                    "resolve_chat_by_name",
                    order,
                    fallback_chat_id=fallback_chat_id,
                    fallback_buyer_username=fallback_buyer_username,
                    include_faceit=bool(order.get("is_faceit") and include_faceit),
                    extra_error=str(e),
                )
            }

        chat_id = getattr(chat, "id", None)
    if not chat_id:
        return {
            "error": "Не удалось определить чат заказа\n"
            + _funpay_format_order_debug_text(
                "initial_order_message",
                order,
                fallback_chat_id=fallback_chat_id,
                fallback_buyer_username=fallback_buyer_username,
                include_faceit=bool(order.get("is_faceit") and include_faceit),
            )
        }

    is_faceit_order = bool(order.get("is_faceit"))

    if persist_account_id is not None:
        try:
            set_funpay_order_context(
                persist_account_id,
                order.get("id") or str(order_id).strip().upper(),
                f"https://funpay.com/orders/{str(order.get('id') or str(order_id).strip().upper())}/",
                buyer_username,
                chat_id,
                order.get("status"),
                order.get("price"),
            )
            conn.commit()
        except Exception as e:
            logging.error(f"FunPay order context persist error: {e}")

    order_text_lines = [
        "Данные для покупателя:",
        f"Steam логин: {steam_login}",
        f"Steam пароль: {steam_password}",
    ]
    order_copy_lines = [
        f"Steam логин: {steam_login}",
        f"Steam пароль: {steam_password}",
    ]

    if is_faceit_order and include_faceit:
        faceit_email_display = faceit_email or "-"
        faceit_password_display = faceit_password or "-"
        order_text_lines.extend([
            "",
            f"Faceit email: {faceit_email_display}",
            f"Faceit пароль: {faceit_password_display}",
        ])
        order_copy_lines.extend([
            f"Faceit email: {faceit_email_display}",
            f"Faceit пароль: {faceit_password_display}",
        ])

    try:
        acc.send_message(chat_id, "\n".join(order_text_lines))
    except Exception as e:
        err_text = str(e)
        if "NoneType" in err_text and "text" in err_text:
            logging.warning(
                "FunPay initial order message sent, but library raised harmless error: %s",
                err_text,
            )
        else:
            return {"error": f"Не удалось отправить данные в чат заказа: {e}"}

    return {
        "success": True,
        "chat_id": chat_id,
        "buyer_username": buyer_username,
        "order_id": order.get("id"),
        "order_status": order.get("status"),
        "order_price": order.get("price"),
        "is_faceit_order": is_faceit_order,
        "copy_text": "\n".join(order_copy_lines),
    }


def _funpay_send_code_to_order_sync(
    order_id: str,
    code_type: str,
    account_login: str | None = None,
    steam_shared_secret: str | None = None,
    faceit_2fa_secret: str | None = None,
    persist_account_id: int | None = None,
    fallback_chat_id: int | str | None = None,
    fallback_buyer_username: str | None = None,
    user_agent: str | None = None,
) -> dict:
    golden_key = resolve_funpay_golden_key()
    if not golden_key:
        return {"error": "FunPay golden key не задан"}

    acc = _funpay_build_account_sync(golden_key, user_agent or resolve_funpay_user_agent())
    order = _funpay_find_order_record_sync(order_id, user_agent)
    if order.get("error"):
        return order

    if code_type == "faceit" and not order.get("is_faceit"):
        return {"error": "Этот заказ не FACEIT, код Faceit не требуется."}

    buyer_username = order.get("buyer_username") or fallback_buyer_username
    chat_id = order.get("chat_id") or fallback_chat_id
    chat = None
    if chat_id is None and buyer_username:
        try:
            chat = acc.get_chat_by_name(buyer_username, True)
        except Exception as e:
            return {
                "error": "Не удалось получить чат заказа\n"
                + _funpay_format_order_debug_text(
                    "resolve_chat_by_name",
                    order,
                    fallback_chat_id=fallback_chat_id,
                    fallback_buyer_username=fallback_buyer_username,
                    include_faceit=bool(order.get("is_faceit")),
                    extra_error=str(e),
                )
            }

        chat_id = getattr(chat, "id", None)
    if not chat_id:
        return {
            "error": "Не удалось определить чат заказа\n"
            + _funpay_format_order_debug_text(
                "send_order_code",
                order,
                fallback_chat_id=fallback_chat_id,
                fallback_buyer_username=fallback_buyer_username,
                extra_error=f"code_type={code_type}",
            )
        }

    if persist_account_id is not None:
        try:
            set_funpay_order_context(
                persist_account_id,
                order.get("id") or str(order_id).strip().upper(),
                f"https://funpay.com/orders/{str(order.get('id') or str(order_id).strip().upper())}/",
                buyer_username,
                chat_id,
                order.get("status"),
                order.get("price"),
            )
            conn.commit()
        except Exception as e:
            logging.error(f"FunPay order context persist error (code): {e}")

    if code_type == "steam":
        if not steam_shared_secret:
            return {"error": "Steam shared secret не задан"}
        code, _seconds_left = generate_steam_guard_code(decrypt(steam_shared_secret))
        message_text = f"Steam Guard код" + (f" для аккаунта {account_login}" if account_login else "") + f": {code}"
    elif code_type == "faceit":
        if not faceit_2fa_secret:
            return {"error": "Faceit 2FA secret не задан"}
        code, _seconds_left = generate_totp_code(decrypt(faceit_2fa_secret))
        message_text = f"Faceit код" + (f" для аккаунта {account_login}" if account_login else "") + f": {code}"
    else:
        return {"error": "Неизвестный тип кода"}

    try:
        acc.send_message(chat_id, message_text)
    except Exception as e:
        err_text = str(e)
        if "NoneType" in err_text and "text" in err_text:
            logging.warning(
                "FunPay code sent, but library raised harmless error: %s",
                err_text,
            )
        else:
            return {"error": f"Не удалось отправить код в чат заказа: {e}"}
    return {
        "success": True,
        "chat_id": chat_id,
        "buyer_username": buyer_username,
        "code_type": code_type,
        "code": code,
    }


def set_funpay_order_context(
    aid: int,
    order_id: str | None,
    order_url: str | None,
    buyer_username: str | None = None,
    chat_id: int | str | None = None,
    status: str | None = None,
    price: str | None = None,
) -> None:
    now_iso = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        """
        UPDATE accounts
           SET funpay_order_id = ?,
               funpay_order_url = ?,
               funpay_order_buyer = COALESCE(?, funpay_order_buyer),
               funpay_order_chat_id = COALESCE(?, funpay_order_chat_id),
               funpay_order_status = COALESCE(?, funpay_order_status),
               funpay_order_price = COALESCE(?, funpay_order_price),
               funpay_order_last_sync_at = ?
         WHERE id = ?
        """,
        (
            order_id,
            order_url,
            normalize_db_text(buyer_username),
            str(chat_id) if chat_id is not None else None,
            normalize_db_text(status),
            normalize_db_text(price),
            now_iso,
            aid,
        ),
    )


def mark_funpay_order_notification_for_busy_accounts(order_id: str | None, column_name: str, value: str) -> None:
    if not order_id:
        return
    if column_name not in {"rent_reminder_5m_sent_at", "rent_overdue_notified_at"}:
        raise ValueError("Unsupported notification column")
    cursor.execute(
        f"""
        UPDATE accounts
           SET {column_name} = ?
         WHERE status = 'busy'
           AND funpay_order_id = ?
        """,
        (value, order_id),
    )


def clear_funpay_order_context(aid: int) -> None:
    cursor.execute(
        """
        UPDATE accounts
           SET funpay_order_id = NULL,
               funpay_order_url = NULL,
               funpay_order_status = NULL,
               funpay_order_price = NULL,
               funpay_order_buyer = NULL,
               funpay_order_chat_id = NULL,
               funpay_order_last_sync_at = NULL,
               funpay_order_last_code_sent_at = NULL,
               rent_reminder_5m_sent_at = NULL,
               rent_overdue_notified_at = NULL
         WHERE id = ?
        """,
        (aid,),
    )


def format_funpay_order_label(row) -> str:
    order_id = row[40] if len(row) > 40 else None
    order_status = row[42] if len(row) > 42 else None
    order_price = row[43] if len(row) > 43 else None
    buyer = row[44] if len(row) > 44 else None

    if not order_id:
        return "не привязан"

    parts = [str(order_id)]
    if order_status:
        parts.append(str(order_status))
    if order_price:
        parts.append(str(order_price))
    if buyer:
        parts.append(f"buyer: {buyer}")
    return " | ".join(parts)


def format_funpay_optional_value(value, linked: bool = False) -> str:
    if value is None or str(value).strip() == "":
        return "не получено" if linked else "-"
    return str(value)


def normalize_db_text(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, (str, int, float, bool)):
        text = str(value).strip()
        return text or None
    name = getattr(value, "name", None)
    if isinstance(name, str) and name.strip():
        return name.strip()
    value_text = str(value).strip()
    return value_text or None


def is_funpay_order_closed(status) -> bool:
    text = normalize_db_text(status)
    if not text:
        return False
    normalized = text.lower()
    closed_tokens = (
        "closed",
        "complete",
        "completed",
        "finished",
        "done",
        "resolved",
        "закрыт",
        "закрыто",
        "заверш",
        "выполнен",
    )
    return any(token in normalized for token in closed_tokens)


def get_rent_statistics_text() -> str:
    cursor.execute(
        """
        SELECT steam_login, started_at, actual_end_at, rent_package, close_reason
          FROM rent_history
         ORDER BY id DESC
        """
    )
    rows = cursor.fetchall()

    now = datetime.now(timezone.utc)
    total = len(rows)
    active = 0
    closed = 0
    manual_closed = 0
    auto_closed = 0
    last_24h = 0
    last_7d = 0
    durations_minutes: list[int] = []
    top_counts: dict[str, int] = {}

    for steam_login, started_at_raw, actual_end_raw, rent_package, close_reason in rows:
        started_at = parse_iso_datetime(started_at_raw)
        actual_end = parse_iso_datetime(actual_end_raw)

        top_counts[steam_login] = top_counts.get(steam_login, 0) + 1

        if started_at and (now - started_at).total_seconds() <= 86400:
            last_24h += 1
        if started_at and (now - started_at).total_seconds() <= 604800:
            last_7d += 1

        if actual_end is None:
            active += 1
            continue

        closed += 1
        if close_reason == "manual_free":
            manual_closed += 1
        elif close_reason == "auto_free":
            auto_closed += 1

        if started_at:
            duration_minutes = max(0, int((actual_end - started_at).total_seconds() / 60))
            durations_minutes.append(duration_minutes)

    top_rows = sorted(top_counts.items(), key=lambda item: (-item[1], item[0]))[:5]

    avg_text = "нет данных"
    if durations_minutes:
        total_minutes = int(sum(durations_minutes) / len(durations_minutes))
        avg_hours_part, avg_minutes_part = divmod(total_minutes, 60)
        if avg_hours_part:
            avg_text = f"{avg_hours_part}ч {avg_minutes_part}м"
        else:
            avg_text = f"{avg_minutes_part}м"

    lines = [
        "Статистика аренд:",
        "",
        f"Всего записей: {total}",
        f"Активных сейчас: {active}",
        f"Завершено: {closed}",
        f"За 24 часа: {last_24h}",
        f"За 7 дней: {last_7d}",
        f"Средняя длительность завершённых: {avg_text}",
        f"Завершено вручную: {manual_closed}",
        f"Завершено автоматически: {auto_closed}",
    ]

    if top_rows:
        lines.extend(["", "Топ аккаунтов:"])
        for idx, (login, cnt) in enumerate(top_rows, start=1):
            lines.append(f"{idx}. {login} — {cnt}")

    return "\n".join(lines)


def set_account_block(aid: int, target: str, ends_at: datetime | None, reason: str | None = None, block_type: str | None = None, source: str | None = None) -> None:
    if target == "faceit":
        cursor.execute(
            """
            UPDATE accounts
               SET faceit_blocked = ?,
                   faceit_block_ends_at = ?,
                   faceit_block_reason = ?,
                   faceit_block_type = ?,
                   faceit_block_source = ?,
                   faceit_block_last_checked_at = ?
             WHERE id = ?
            """,
            (
                1 if ends_at else 0,
                ends_at.isoformat() if ends_at else None,
                reason,
                block_type,
                source or "manual",
                datetime.now(timezone.utc).isoformat(),
                aid,
            ),
        )
        return

    if target == "steam":
        cursor.execute(
            """
            UPDATE accounts
               SET steam_blocked = ?,
                   steam_block_ends_at = ?,
                   steam_block_reason = ?,
                   steam_block_type = ?,
                   steam_block_source = ?
             WHERE id = ?
            """,
            (
                1 if ends_at else 0,
                ends_at.isoformat() if ends_at else None,
                reason,
                block_type,
                source or "manual",
                aid,
            ),
        )
        return

    raise ValueError(f"Unknown block target: {target}")


def clear_account_block(aid: int, target: str) -> None:
    if target == "faceit":
        cursor.execute(
            """
            UPDATE accounts
               SET faceit_blocked = 0,
                   faceit_block_ends_at = NULL,
                   faceit_block_reason = NULL,
                   faceit_block_type = NULL,
                   faceit_block_game = NULL,
                   faceit_ban_signature = NULL,
                   faceit_block_source = NULL,
                   faceit_block_last_checked_at = NULL
             WHERE id = ?
            """,
            (aid,),
        )
        return

    if target == "steam":
        cursor.execute(
            """
            UPDATE accounts
               SET steam_blocked = 0,
                   steam_block_ends_at = NULL,
                   steam_block_reason = NULL,
                   steam_block_type = NULL,
                   steam_block_source = NULL
             WHERE id = ?
            """,
            (aid,),
        )
        return

    raise ValueError(f"Unknown block target: {target}")


def extract_faceit_nickname(faceit_url: str | None) -> str | None:
    if not faceit_url:
        return None

    raw = faceit_url.strip()
    if not raw:
        return None

    if "faceit.com" in raw:
        parsed = urlparse(raw)
        parts = [part for part in parsed.path.split("/") if part]
        if parts:
            return unquote(parts[-1]).strip() or None
        return None

    return raw


async def fetch_faceit_profile_stats(faceit_url: str | None) -> dict:
    nickname = extract_faceit_nickname(faceit_url)
    if not nickname:
        return {"nickname": None, "player_id": None, "elo": None, "level": None, "error": None}

    faceit_api_key = resolve_faceit_api_key()
    if not faceit_api_key:
        return {"nickname": nickname, "player_id": None, "elo": None, "level": None, "error": "FACEIT_API_KEY не задан"}

    url = "https://open.faceit.com/data/v4/players"
    headers = {"Authorization": f"Bearer {faceit_api_key}"}
    timeout = aiohttp.ClientTimeout(total=15)

    async def fetch_for_game(game_name: str) -> tuple[dict | None, str | None, str | None]:
        params = {"nickname": nickname, "game": game_name}
        try:
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                async with session.get(url, params=params) as response:
                    if response.status != 200:
                        return None, None, f"HTTP {response.status}"
                    data = await response.json()
        except Exception as e:
            return None, None, str(e)

        games = data.get("games") or {}
        player_id = data.get("player_id") or data.get("user_id") or data.get("id")
        payload = games.get("cs2") or games.get("csgo") or {}
        return payload, player_id, None

    game, player_id, error = await fetch_for_game("cs2")
    if not game:
        fallback_game, fallback_player_id, fallback_error = await fetch_for_game("csgo")
        if fallback_game:
            game = fallback_game
        if not player_id:
            player_id = fallback_player_id
        if fallback_game:
            error = None
        else:
            error = fallback_error or error

    game = game or {}
    elo = game.get("faceit_elo")
    level = game.get("skill_level")

    return {
        "nickname": nickname,
        "player_id": player_id,
        "elo": elo,
        "level": level,
        "error": error,
    }


def parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def normalize_steam_secret(raw_value: str | None) -> str | None:
    if not raw_value:
        return None

    value = raw_value.strip()
    if not value:
        return None

    return value.replace(" ", "")


def generate_steam_guard_code(shared_secret: str) -> tuple[str, int]:
    normalized = normalize_steam_secret(shared_secret)
    if not normalized:
        raise ValueError("Пустой Steam shared_secret")

    padding = "=" * (-len(normalized) % 4)
    secret = base64.b64decode(normalized + padding)

    time_buffer = struct.pack(">Q", int(time.time() / 30))
    digest = hmac.new(secret, time_buffer, hashlib.sha1).digest()

    start = digest[19] & 0x0F
    full_code = struct.unpack(">I", digest[start:start + 4])[0] & 0x7FFFFFFF
    alphabet = "23456789BCDFGHJKMNPQRTVWXY"
    code_chars = []
    for _ in range(5):
        code_chars.append(alphabet[full_code % len(alphabet)])
        full_code //= len(alphabet)
    code = "".join(code_chars)
    seconds_left = 30 - (int(time.time()) % 30)
    return code, seconds_left


def build_steam_device_id(steam_id: str | int | None) -> str | None:
    if steam_id is None:
        return None

    value = str(steam_id).strip()
    if not value or not value.isdigit():
        return None

    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()
    return (
        "android:"
        f"{digest[:8]}-"
        f"{digest[8:12]}-"
        f"{digest[12:16]}-"
        f"{digest[16:20]}-"
        f"{digest[20:32]}"
    )


def parse_steam_mafile_content(raw_text: str) -> dict:
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as e:
        raise ValueError("Файл не является корректным JSON.") from e

    if not isinstance(payload, dict):
        raise ValueError("maFile должен содержать JSON-объект.")

    session = payload.get("Session") if isinstance(payload.get("Session"), dict) else {}
    shared_secret = normalize_steam_secret(payload.get("shared_secret"))
    identity_secret = normalize_steam_secret(payload.get("identity_secret"))
    steam_id = session.get("SteamID") or payload.get("steamid")
    device_id = payload.get("device_id") or build_steam_device_id(steam_id)

    if not shared_secret:
        raise ValueError("В maFile не найден shared_secret.")

    return {
        "shared_secret": shared_secret,
        "identity_secret": identity_secret,
        "steam_id": str(steam_id).strip() if steam_id is not None else None,
        "device_id": device_id,
        "session_id": (session.get("SessionID") or "").strip() or None,
        "steam_login_cookie": (session.get("SteamLogin") or "").strip() or None,
        "steam_login_secure_cookie": (session.get("SteamLoginSecure") or "").strip() or None,
        "webcookie": (session.get("WebCookie") or "").strip() or None,
        "access_token": (session.get("AccessToken") or "").strip() or None,
        "refresh_token": (session.get("RefreshToken") or "").strip() or None,
    }


def parse_faceit_ban_end(item: dict) -> datetime | None:
    for key in ("ends_at", "banEnd", "ban_end", "endsAt"):
        dt = parse_iso_datetime(item.get(key))
        if dt is not None:
            return dt
    return None


def generate_steam_confirmation_key(identity_secret: str, tag: str, timestamp: int) -> str:
    normalized = normalize_steam_secret(identity_secret)
    if not normalized:
        raise ValueError("Пустой identity secret")

    padding = "=" * (-len(normalized) % 4)
    secret = base64.b64decode(normalized + padding)
    buffer = struct.pack(">Q", timestamp) + tag.encode("ascii")
    digest = hmac.new(secret, buffer, hashlib.sha1).digest()
    return base64.b64encode(digest).decode()


def build_steam_confirmation_params(identity_secret: str, steam_id64: str, device_id: str, tag: str) -> dict:
    timestamp = int(time.time())
    return {
        "p": device_id,
        "a": steam_id64,
        "k": generate_steam_confirmation_key(identity_secret, tag, timestamp),
        "t": str(timestamp),
        "m": "android",
        "tag": tag,
    }


def extract_steam_confirmations_from_html(html: str) -> list[dict]:
    if not html:
        return []

    entries = []
    entry_pattern = re.compile(
        r'(<div[^>]+class="mobileconf_list_entry[^"]*"[^>]+data-confid="(?P<confid>\d+)"[^>]+data-key="(?P<key>[^"]+)"[^>]*>.*?</div>\s*</div>)',
        re.IGNORECASE | re.DOTALL,
    )
    desc_pattern = re.compile(r'<div[^>]*class="mobileconf_list_entry_description"[^>]*>(.*?)</div>', re.IGNORECASE | re.DOTALL)
    line_pattern = re.compile(r"<div[^>]*>(.*?)</div>", re.IGNORECASE | re.DOTALL)

    for match in entry_pattern.finditer(html):
        block = match.group(1) or ""
        desc_block_match = desc_pattern.search(block)
        desc_block = desc_block_match.group(1) if desc_block_match else ""
        text_lines = [
            re.sub(r"<.*?>", "", item).strip()
            for item in line_pattern.findall(desc_block)
        ]
        text_lines = [unquote(item) for item in text_lines if item]
        title = text_lines[0] if text_lines else "Без названия"
        details = text_lines[1] if len(text_lines) > 1 else ""
        entries.append(
            {
                "id": match.group("confid"),
                "nonce": match.group("key"),
                "title": title,
                "details": details,
            }
        )

    return entries


def build_steam_confirmation_cookies(row) -> dict:
    steam_id64 = (row[31] if len(row) > 31 else None) or ""
    session_id = decrypt(row[27]) if len(row) > 27 and row[27] else None
    steam_login = decrypt(row[28]) if len(row) > 28 and row[28] else None
    steam_login_secure = decrypt(row[29]) if len(row) > 29 and row[29] else None
    webcookie = decrypt(row[30]) if len(row) > 30 and row[30] else None

    cookies = {
        "steamid": steam_id64,
        "sessionid": session_id or "",
        "steamLogin": steam_login or "",
        "steamLoginSecure": steam_login_secure or "",
        "mobileClient": "android",
        "mobileClientVersion": "777777 3.0.0",
        "Steam_Language": "russian",
    }
    if webcookie:
        cookies["webTradeEligibility"] = webcookie
    return {k: v for k, v in cookies.items() if v}


def steam_trade_ready(row) -> bool:
    if not row or len(row) <= 33:
        return False
    has_base = bool(row[23] and row[24] and row[25] and row[31])
    has_cookie_session = bool(row[27] and row[29])
    return has_base and has_cookie_session


def steam_token_session_ready(row) -> bool:
    if not row or len(row) <= 33:
        return False
    return bool(row[23] and row[24] and row[25] and row[31] and row[32] and row[33])


def steam_session_mode(row) -> str:
    if steam_trade_ready(row):
        return "cookie"
    if steam_token_session_ready(row):
        return "token"
    return "partial"


def format_steam_presence_label(state: str | None, game: str | None) -> str:
    normalized = (state or "").strip().lower()
    if normalized == "in_game":
        return f"в игре ({game})" if game else "в игре"
    if normalized == "online":
        return "в сети"
    if normalized == "offline":
        return "не в игре"
    if normalized == "hidden":
        return "статус скрыт"
    if normalized == "unknown":
        return "статус неизвестен"
    return "нет данных"


async def fetch_steam_presence_batch(steam_api_key: str, steam_ids: list[str]) -> dict[str, dict]:
    if not steam_api_key or not steam_ids:
        return {}

    url = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/"
    params = {
        "key": steam_api_key,
        "steamids": ",".join(steam_ids),
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(url, params=params, timeout=30) as resp:
            resp.raise_for_status()
            payload = await resp.json(content_type=None)

    players = ((payload or {}).get("response") or {}).get("players") or []
    result: dict[str, dict] = {}

    for player in players:
        steam_id = str(player.get("steamid") or "").strip()
        if not steam_id:
            continue

        game_name = player.get("gameextrainfo")
        visibility = int(player.get("communityvisibilitystate") or 0)
        persona_state = int(player.get("personastate") or 0)

        if player.get("gameid"):
            state = "in_game"
        elif visibility and visibility < 3:
            state = "hidden"
        elif persona_state > 0:
            state = "online"
        else:
            state = "offline"

        result[steam_id] = {
            "state": state,
            "game": game_name or None,
        }

    return result


async def sync_steam_presence() -> None:
    steam_api_key = resolve_steam_api_key()
    if not steam_api_key:
        return

    cursor.execute(
        """
        SELECT id, steam_steamid64
          FROM accounts
         WHERE steam_steamid64 IS NOT NULL
           AND TRIM(steam_steamid64) != ''
        """
    )
    rows = cursor.fetchall()
    if not rows:
        return

    id_to_steamid: dict[int, str] = {}
    steam_ids: list[str] = []
    for aid, steam_id_raw in rows:
        steam_id = str(steam_id_raw).strip()
        if not steam_id:
            continue
        id_to_steamid[aid] = steam_id
        steam_ids.append(steam_id)

    if not steam_ids:
        return

    now_iso = datetime.now(timezone.utc).isoformat()
    results: dict[str, dict] = {}

    for start in range(0, len(steam_ids), 100):
        batch = steam_ids[start:start + 100]
        batch_result = await fetch_steam_presence_batch(steam_api_key, batch)
        results.update(batch_result)

    for aid, steam_id in id_to_steamid.items():
        item = results.get(steam_id)
        if item:
            state = item.get("state") or "unknown"
            game = item.get("game")
        else:
            state = "unknown"
            game = None

        cursor.execute(
            """
            UPDATE accounts
               SET steam_presence_state = ?,
                   steam_presence_game = ?,
                   steam_presence_checked_at = ?
             WHERE id = ?
            """,
            (state, game, now_iso, aid),
        )

    conn.commit()


def save_steam_mafile_to_account(aid: int, filename: str, raw_text: str) -> None:
    parsed = parse_steam_mafile_content(raw_text)
    cursor.execute(
        """
        UPDATE accounts
           SET steam_shared_secret = ?,
               steam_identity_secret = ?,
               steam_device_id = ?,
               steam_mafile_name = ?,
               steam_session_id = ?,
               steam_login_cookie = ?,
               steam_login_secure_cookie = ?,
               steam_webcookie = ?,
               steam_steamid64 = ?,
               steam_access_token = ?,
               steam_refresh_token = ?
         WHERE id = ?
        """,
        (
            encrypt(parsed["shared_secret"]) if parsed.get("shared_secret") else None,
            encrypt(parsed["identity_secret"]) if parsed.get("identity_secret") else None,
            parsed.get("device_id"),
            filename,
            encrypt(parsed["session_id"]) if parsed.get("session_id") else None,
            encrypt(parsed["steam_login_cookie"]) if parsed.get("steam_login_cookie") else None,
            encrypt(parsed["steam_login_secure_cookie"]) if parsed.get("steam_login_secure_cookie") else None,
            encrypt(parsed["webcookie"]) if parsed.get("webcookie") else None,
            parsed.get("steam_id"),
            encrypt(parsed["access_token"]) if parsed.get("access_token") else None,
            encrypt(parsed["refresh_token"]) if parsed.get("refresh_token") else None,
            aid,
        ),
    )


async def steam_fetch_confirmations(aid: int, row) -> dict:
    if steam_token_session_ready(row) and not steam_trade_ready(row):
        return {
            "error": (
                "Загружен новый token-based maFile Steam "
                "(AccessToken/RefreshToken), но для подтверждений "
                "в Python-версии бота пока всё ещё нужна cookie-сессия "
                "(SessionID и SteamLoginSecure)."
            )
        }
    if not steam_trade_ready(row):
        return {"error": "Для подтверждений не хватает данных из maFile: identity secret, device id или Steam cookies."}

    identity_secret = decrypt(row[24])
    device_id = row[25]
    steam_id64 = row[31]
    params = build_steam_confirmation_params(identity_secret, steam_id64, device_id, "conf")
    cookies = build_steam_confirmation_cookies(row)

    try:
        async with aiohttp.ClientSession(cookies=cookies) as session:
            async with session.get("https://steamcommunity.com/mobileconf/getlist", params=params, timeout=30) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    return {"error": f"Steam вернул HTTP {resp.status}: {text[:200]}"}
                payload = await resp.json(content_type=None)
    except Exception as e:
        return {"error": str(e)}

    if not payload.get("success"):
        message = payload.get("message") or "Steam не подтвердил запрос."
        return {"error": message}

    html = payload.get("html") or ""
    confirmations = extract_steam_confirmations_from_html(html)
    return {"confirmations": confirmations}


async def steam_send_confirmation_multi(aid: int, row, op: str, confirmations: list[dict]) -> dict:
    if not confirmations:
        return {"error": "Нет подтверждений для обработки."}
    if steam_token_session_ready(row) and not steam_trade_ready(row):
        return {
            "error": (
                "Загружен новый token-based maFile Steam "
                "(AccessToken/RefreshToken), но массовые действия "
                "по подтверждениям в Python-версии бота пока ещё ожидают "
                "cookie-сессию Steam."
            )
        }
    if not steam_trade_ready(row):
        return {"error": "Для обработки подтверждений не хватает данных из maFile."}

    identity_secret = decrypt(row[24])
    device_id = row[25]
    steam_id64 = row[31]
    params = build_steam_confirmation_params(identity_secret, steam_id64, device_id, "conf")
    cookies = build_steam_confirmation_cookies(row)
    data = {
        "op": op,
        "cid[]": [item["id"] for item in confirmations],
        "ck[]": [item["nonce"] for item in confirmations],
    }

    try:
        async with aiohttp.ClientSession(cookies=cookies) as session:
            async with session.post("https://steamcommunity.com/mobileconf/multiajaxop", params=params, data=data, timeout=30) as resp:
                if resp.status != 200:
                    text = await resp.text()
                    return {"error": f"Steam вернул HTTP {resp.status}: {text[:200]}"}
                payload = await resp.json(content_type=None)
    except Exception as e:
        return {"error": str(e)}

    if not payload.get("success"):
        message = payload.get("message") or "Steam не выполнил действие."
        return {"error": message}

    return {"success": True, "count": len(confirmations)}


def parse_faceit_ban_start(item: dict) -> datetime | None:
    for key in ("starts_at", "banStart", "ban_start", "startsAt"):
        dt = parse_iso_datetime(item.get(key))
        if dt is not None:
            return dt
    return None


def format_remaining_time(end_at: datetime | None) -> str:
    if end_at is None:
        return "неизвестно"

    now = datetime.now(end_at.tzinfo) if end_at.tzinfo else datetime.now()
    delta = end_at - now
    total_seconds = int(delta.total_seconds())
    if total_seconds <= 0:
        return "0м"

    days, rem = divmod(total_seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)

    parts = []
    if days:
        parts.append(f"{days}д")
    if hours:
        parts.append(f"{hours}ч")
    if minutes:
        parts.append(f"{minutes}м")

    return " ".join(parts) if parts else "0м"


def format_interval_seconds(seconds: int) -> str:
    total = max(0, int(seconds))
    hours, rem = divmod(total, 3600)
    minutes, _ = divmod(rem, 60)

    parts = []
    if hours:
        parts.append(f"{hours}ч")
    if minutes:
        parts.append(f"{minutes}м")
    if not parts:
        parts.append("0м")
    return " ".join(parts)


def normalize_totp_secret(raw_value: str | None) -> str | None:
    if not raw_value:
        return None

    value = raw_value.strip()
    if not value:
        return None

    if value.lower().startswith("otpauth://"):
        parsed = urlparse(value)
        query = parse_qs(parsed.query)
        secret_values = query.get("secret") or []
        if secret_values:
            value = secret_values[0].strip()

    value = value.replace(" ", "").replace("-", "").upper()
    return value or None


def generate_totp_code(secret: str, period: int = 30, digits: int = 6) -> tuple[str, int]:
    normalized = normalize_totp_secret(secret)
    if not normalized:
        raise ValueError("Пустой secret")

    padding = "=" * (-len(normalized) % 8)
    key = base64.b32decode(normalized + padding, casefold=True)

    counter = int(time.time()) // period
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()

    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    code = f"{code_int:0{digits}d}"

    seconds_left = period - (int(time.time()) % period)
    return code, seconds_left


async def resolve_faceit_player_id(faceit_url: str | None) -> tuple[str | None, str | None]:
    stats = await fetch_faceit_profile_stats(faceit_url)
    return stats.get("player_id"), stats.get("error")


def normalize_faceit_ban_item(item: dict, player_id: str | None, nickname: str) -> dict | None:
    if not isinstance(item, dict):
        return None

    ends_at = parse_faceit_ban_end(item)
    starts_at = parse_faceit_ban_start(item)
    expired = item.get("expired")

    if expired is True:
        return None

    now = datetime.now(timezone.utc)
    if ends_at is None:
        return None
    if ends_at is not None and ends_at <= now:
        return None

    ban_id = item.get("banId") or item.get("ban_id") or item.get("id") or ""
    return {
        "ban_id": str(ban_id),
        "game": item.get("game") or "",
        "nickname": item.get("nickname") or nickname,
        "reason": item.get("reason") or "",
        "type": item.get("type") or "",
        "starts_at": starts_at,
        "ends_at": ends_at,
        "user_id": item.get("user_id") or item.get("userId") or player_id,
    }


def extract_active_bans_from_payload(payload: dict, player_id: str | None, nickname: str) -> list[dict]:
    active_bans: list[dict] = []

    items = payload.get("items")
    if isinstance(items, list):
        for item in items:
            normalized = normalize_faceit_ban_item(item, player_id, nickname)
            if normalized is not None:
                active_bans.append(normalized)

    infractions = payload.get("infractions")
    if isinstance(infractions, dict):
        infractions_items = infractions.get("items")
    else:
        infractions_items = infractions

    if isinstance(infractions_items, list):
        for item in infractions_items:
            normalized = normalize_faceit_ban_item(item, player_id, nickname)
            if normalized is not None:
                active_bans.append(normalized)

    return active_bans


async def fetch_faceit_player_details(player_id: str, api_key: str) -> dict:
    url = f"https://open.faceit.com/data/v4/players/{player_id}"
    headers = {"Authorization": f"Bearer {api_key}"}
    timeout = aiohttp.ClientTimeout(total=15)

    async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
        async with session.get(url) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status}")
            return await response.json()


async def fetch_faceit_active_ban(faceit_url: str | None, api_key: str) -> dict:
    nickname = extract_faceit_nickname(faceit_url)
    if not nickname:
        return {"nickname": None, "player_id": None, "ban": None, "error": None}

    player_id, error = await resolve_faceit_player_id(faceit_url)
    if not player_id:
        return {"nickname": nickname, "player_id": None, "ban": None, "error": error or "Не удалось определить player_id"}

    url = f"https://open.faceit.com/data/v4/players/{player_id}/bans"
    headers = {"Authorization": f"Bearer {api_key}"}
    timeout = aiohttp.ClientTimeout(total=15)

    try:
        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status != 200:
                    return {
                        "nickname": nickname,
                        "player_id": player_id,
                        "ban": None,
                        "error": f"HTTP {response.status}",
                    }
                data = await response.json()
    except Exception as e:
        return {"nickname": nickname, "player_id": player_id, "ban": None, "error": str(e)}

    active_bans = extract_active_bans_from_payload(data, player_id, nickname)

    if not active_bans:
        try:
            player_payload = await fetch_faceit_player_details(player_id, api_key)
            active_bans = extract_active_bans_from_payload(player_payload, player_id, nickname)
        except Exception as e:
            return {"nickname": nickname, "player_id": player_id, "ban": None, "error": str(e)}

    if not active_bans:
        return {"nickname": nickname, "player_id": player_id, "ban": None, "error": None}

    active_bans.sort(key=lambda x: x["ends_at"])
    return {"nickname": nickname, "player_id": player_id, "ban": active_bans[-1], "error": None}


def _funpay_build_account_sync(golden_key: str, user_agent: str | None = None):
    funpay_ensure_available()
    acc = FunPayAccount(golden_key, user_agent=user_agent or None)
    acc.get()
    return acc


def _funpay_send_chat_message_sync(chat_id: int | str, message_text: str, user_agent: str | None = None) -> None:
    golden_key = resolve_funpay_golden_key()
    if not golden_key:
        raise RuntimeError("FunPay golden key не задан")

    acc = _funpay_build_account_sync(golden_key, user_agent or resolve_funpay_user_agent())
    try:
        acc.send_message(int(chat_id), message_text)
    except Exception as e:
        err_text = str(e)
        if "NoneType" in err_text and "text" in err_text:
            logging.warning(
                "FunPay chat message sent, but library raised harmless error: %s",
                err_text,
            )
            return
        raise


async def _funpay_register_new_order(
    order_id: str | None,
    order_url: str | None,
    buyer_username: str | None,
    chat_id: int | None,
    status: str | None,
    price: str | None,
) -> None:
    if not order_id:
        return

    cursor.execute(
        """
        SELECT id
          FROM accounts
         WHERE status = 'busy'
           AND funpay_order_id = ?
         LIMIT 1
        """,
        (order_id,),
    )
    row = cursor.fetchone()
    if not row:
        return

    aid = row[0]
    set_funpay_order_context(aid, order_id, order_url, buyer_username, chat_id, status, price)
    conn.commit()


async def _funpay_handle_chat_message(
    chat_id: int | None,
    author_id: int | None,
    text: str | None,
) -> None:
    if chat_id is None:
        return

    normalized = (text or "").strip().lower()
    if normalized not in {"/code", "/steam", "/faceit", "код", "code", "steam code", "steam", "faceit code", "faceit"}:
        return

    logging.info(
        "FunPay incoming chat message: chat_id=%s author_id=%s text=%r",
        chat_id,
        author_id,
        text,
    )

    cursor.execute(
        """
        SELECT *
          FROM accounts
         WHERE status = 'busy'
           AND funpay_order_chat_id = ?
         LIMIT 1
        """,
        (str(chat_id),),
    )
    row = cursor.fetchone()
    if not row:
        logging.warning("FunPay chat message ignored: no account bound to chat_id=%s", chat_id)
        return

    if row[0] is None:
        return

    faceit_blocked = bool(row[11]) if len(row) > 11 else False
    steam_shared_secret = row[24] if len(row) > 24 else None
    faceit_2fa_secret = row[8] if len(row) > 8 else None
    order_id = row[40] if len(row) > 40 else None

    code_type = "faceit" if normalized in {"/faceit", "faceit code", "faceit"} else "steam"
    if code_type == "faceit" and order_id:
        order_info = _funpay_find_order_record_sync(order_id)
        if not order_info.get("is_faceit"):
            return

    if code_type == "steam" and not steam_shared_secret:
        return
    if code_type == "faceit" and not faceit_2fa_secret:
        return
    if code_type == "faceit" and faceit_blocked:
        return

    try:
        if code_type == "steam":
            code, _seconds_left = generate_steam_guard_code(decrypt(steam_shared_secret))
        else:
            code, _seconds_left = generate_totp_code(decrypt(faceit_2fa_secret))
    except Exception as e:
        logging.error(f"funpay code generation error: {e}")
        return

    try:
        label = "Steam Guard" if code_type == "steam" else "Faceit"
        await asyncio.to_thread(_funpay_send_chat_message_sync, chat_id, f"{label} код: {code}")
        cursor.execute(
            "UPDATE accounts SET funpay_order_last_code_sent_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), row[0]),
        )
        conn.commit()
    except Exception as e:
        logging.error(f"funpay code send error: {e}")


def _funpay_listener_thread(loop: asyncio.AbstractEventLoop) -> None:
    global FUNPAY_LISTENER_THREAD_STARTED
    if FunPayRunner is None:
        logging.warning("FunPayRunner not available; FunPay listener disabled")
        return

    golden_key = resolve_funpay_golden_key()
    if not golden_key:
        logging.warning("FunPay golden key not set; FunPay listener disabled")
        return

    try:
        acc = _funpay_build_account_sync(golden_key, resolve_funpay_user_agent())
        runner = FunPayRunner(acc)
    except Exception as e:
        logging.error(f"FunPay listener init error: {e}")
        return

    FUNPAY_LISTENER_THREAD_STARTED = True
    logging.info("FunPay listener started")

    try:
        for event in runner.listen(requests_delay=4):
            try:
                event_type = getattr(event, "type", None)
                if event_type == getattr(FunPayEnums.EventTypes, "NEW_ORDER", None):
                    order = getattr(event, "order", None)
                    order_id = str(getattr(order, "id", "") or "").strip().upper() or None
                    buyer_username = getattr(order, "buyer_username", None)
                    chat_id = getattr(order, "chat_id", None) or getattr(order, "dialog_id", None)
                    if chat_id is None:
                        chat_obj = getattr(order, "chat", None) or getattr(order, "dialog", None)
                        chat_id = int(getattr(chat_obj, "id", None) or 0) or None
                    order_status = getattr(order, "status", None) or getattr(order, "state", None)
                    order_price = getattr(order, "price", None) or getattr(order, "sum", None)
                    order_url = f"https://funpay.com/orders/{order_id}/" if order_id else None
                    if chat_id is None and buyer_username:
                        try:
                            chat = acc.get_chat_by_name(buyer_username, True)
                            chat_id = int(getattr(chat, "id", None) or 0) or None
                        except Exception as e:
                            logging.error(f"FunPay chat resolve error: {e}")

                    if loop.is_running():
                        future = asyncio.run_coroutine_threadsafe(
                            _funpay_register_new_order(
                                order_id,
                                order_url,
                                buyer_username,
                                chat_id,
                                normalize_db_text(order_status),
                                normalize_db_text(order_price),
                            ),
                            loop,
                        )
                        try:
                            future.result(timeout=15)
                        except Exception as e:
                            logging.error(f"FunPay new order sync error: {e}")

                elif event_type == getattr(FunPayEnums.EventTypes, "NEW_MESSAGE", None):
                    message_obj = getattr(event, "message", None)
                    chat_id = getattr(message_obj, "chat_id", None)
                    author_id = getattr(message_obj, "author_id", None)
                    text = getattr(message_obj, "text", None)
                    if loop.is_running():
                        future = asyncio.run_coroutine_threadsafe(
                            _funpay_handle_chat_message(chat_id, author_id, text),
                            loop,
                        )
                        try:
                            future.result(timeout=15)
                        except Exception as e:
                            logging.error(f"FunPay chat message sync error: {e}")
            except Exception as e:
                logging.error(f"FunPay listener event error: {e}")
    except Exception as e:
        logging.error(f"FunPay listener stopped: {e}")


def start_funpay_listener(loop: asyncio.AbstractEventLoop) -> None:
    global FUNPAY_LISTENER_THREAD
    if FUNPAY_LISTENER_THREAD_STARTED:
        return

    if FunPayRunner is None:
        logging.warning("FunPay listener not started: FunPayRunner unavailable")
        return

    thread = threading.Thread(
        target=_funpay_listener_thread,
        args=(loop,),
        name="funpay-listener",
        daemon=True,
    )
    FUNPAY_LISTENER_THREAD = thread
    thread.start()


def _funpay_collect_balance_lot_candidates(acc, limit: int = 12) -> list[int]:
    candidates: list[int] = []
    seen: set[int] = set()

    try:
        subcats_map = acc.get_sorted_subcategories() or {}
    except Exception:
        return candidates

    preferred_type = None
    if FunPayEnums is not None:
        preferred_type = getattr(FunPayEnums.SubCategoryTypes, "COMMON", None)

    ordered_types = []
    if preferred_type in subcats_map:
        ordered_types.append(preferred_type)
    for subcat_type in subcats_map.keys():
        if subcat_type != preferred_type:
            ordered_types.append(subcat_type)

    for subcat_type in ordered_types:
        subcats = subcats_map.get(subcat_type) or {}
        if not isinstance(subcats, dict):
            continue

        for subcat_id in subcats.keys():
            try:
                lots = acc.get_subcategory_public_lots(subcat_type, int(subcat_id)) or []
            except Exception:
                continue

            for lot in lots:
                lot_id = getattr(lot, "id", None)
                if lot_id is None:
                    continue
                try:
                    lot_id_int = int(lot_id)
                except Exception:
                    continue
                if lot_id_int in seen:
                    continue
                seen.add(lot_id_int)
                candidates.append(lot_id_int)
                if len(candidates) >= limit:
                    return candidates

    return candidates


def _funpay_fetch_balance_sync(golden_key: str, user_agent: str | None = None) -> dict:
    acc = _funpay_build_account_sync(golden_key, user_agent)
    fallback_used = False
    fallback_lot_id = None

    try:
        balance = acc.get_balance()
    except Exception as primary_error:
        candidates = _funpay_collect_balance_lot_candidates(acc)
        if not candidates:
            raise RuntimeError(
                "Не удалось получить баланс через стандартный lot_id и не найдено "
                "кандидатов лотов для fallback. "
                f"Ошибка: {primary_error}"
            ) from primary_error

        last_error = primary_error
        balance = None
        for lot_id in candidates:
            try:
                balance = acc.get_balance(lot_id=lot_id)
                fallback_used = True
                fallback_lot_id = lot_id
                break
            except Exception as e:
                last_error = e

        if balance is None:
            raise RuntimeError(
                "Не удалось получить баланс даже после подбора lot_id. "
                f"Последняя ошибка: {last_error}"
            ) from last_error

    return {
        "username": getattr(acc, "username", None),
        "id": getattr(acc, "id", None),
        "balance": balance,
        "fallback_used": fallback_used,
        "fallback_lot_id": fallback_lot_id,
    }


def _funpay_raise_all_lots_sync(
    golden_key: str,
    user_agent: str | None = None,
    max_categories_per_run: int | None = None,
    rotation_offset: int = 0,
    pause_min_seconds: float = 0.0,
    pause_max_seconds: float = 0.0,
) -> dict:
    acc = _funpay_build_account_sync(golden_key, user_agent)
    categories = acc.get_sorted_categories() or {}
    category_items = list(categories.items())
    total_categories = len(category_items)

    if total_categories:
        safe_offset = rotation_offset % total_categories
        if safe_offset:
            category_items = category_items[safe_offset:] + category_items[:safe_offset]

    if max_categories_per_run and max_categories_per_run > 0:
        category_items = category_items[:max_categories_per_run]

    raised = []
    errors = []
    processed_categories = 0
    for index, (category_id, category) in enumerate(category_items):
        cid = None
        try:
            cid = int(category_id)
        except Exception:
            cid = getattr(category, "id", None)

        if cid is None:
            errors.append(f"Не удалось определить category_id для {getattr(category, 'name', category_id)}")
            continue

        try:
            result = acc.raise_lots(cid)
            raised.append({
                "category_id": cid,
                "category_name": getattr(category, "name", str(category_id)),
                "result": result,
            })
            processed_categories += 1
        except Exception as e:
            errors.append(f"{getattr(category, 'name', category_id)}: {e}")
        finally:
            if (
                index < len(category_items) - 1
                and pause_max_seconds > 0
                and pause_max_seconds >= pause_min_seconds
            ):
                time.sleep(random.uniform(max(0.0, pause_min_seconds), pause_max_seconds))

    return {
        "username": getattr(acc, "username", None),
        "id": getattr(acc, "id", None),
        "total_categories": total_categories,
        "selected_categories": len(category_items),
        "processed_categories": processed_categories,
        "rotation_offset": rotation_offset,
        "raised": raised,
        "errors": errors,
    }


async def funpay_get_balance() -> dict:
    golden_key = resolve_funpay_golden_key()
    if not golden_key:
        return {"error": "FunPay golden key не задан"}

    user_agent = resolve_funpay_user_agent()
    async with get_funpay_op_lock():
        try:
            return await asyncio.to_thread(_funpay_fetch_balance_sync, golden_key, user_agent)
        except Exception as e:
            return {"error": str(e)}


async def funpay_raise_all_lots() -> dict:
    global FUNPAY_AUTO_RAISE_ROTATION_OFFSET
    golden_key = resolve_funpay_golden_key()
    if not golden_key:
        return {"error": "FunPay golden key не задан"}

    user_agent = resolve_funpay_user_agent()
    async with get_funpay_op_lock():
        try:
            result = await asyncio.to_thread(
                _funpay_raise_all_lots_sync,
                golden_key,
                user_agent,
                FUNPAY_AUTO_RAISE_MAX_CATEGORIES_PER_RUN,
                FUNPAY_AUTO_RAISE_ROTATION_OFFSET,
                FUNPAY_AUTO_RAISE_REQUEST_PAUSE_MIN_SECONDS,
                FUNPAY_AUTO_RAISE_REQUEST_PAUSE_MAX_SECONDS,
            )
            total_categories = int(result.get("total_categories") or 0)
            selected_categories = int(result.get("selected_categories") or 0)
            if total_categories > 0 and selected_categories > 0:
                FUNPAY_AUTO_RAISE_ROTATION_OFFSET = (
                    FUNPAY_AUTO_RAISE_ROTATION_OFFSET + selected_categories
                ) % total_categories
            return result
        except Exception as e:
            return {"error": str(e)}


async def sync_faceit_bans(send_notifications: bool = False) -> dict:
    api_key = resolve_faceit_api_key()
    if not api_key:
        return {
            "active_blocks": [],
            "blocked_count": 0,
            "notifications": [],
            "errors": ["FACEIT_API_KEY не задан"],
        }

    clean_expired_faceit_blocks()
    clean_expired_steam_blocks()
    cursor.execute(
        """
        SELECT id, steam_login, faceit_url, faceit_blocked, faceit_block_ends_at, faceit_ban_signature, faceit_block_source
          FROM accounts
         WHERE faceit_url IS NOT NULL
           AND TRIM(faceit_url) != ''
         ORDER BY steam_login
        """
    )
    rows = cursor.fetchall()

    active_blocks = []
    notifications = []
    errors = []
    updated_count = 0

    for aid, steam_login, faceit_url, faceit_blocked, faceit_block_ends_at, faceit_ban_signature, faceit_block_source in rows:
        result = await fetch_faceit_active_ban(faceit_url, api_key)
        error = result.get("error")
        ban = result.get("ban")
        now = datetime.now(timezone.utc)

        if error:
            errors.append(f"{steam_login}: {error}")
            continue

        if ban is None:
            if faceit_blocked and (faceit_block_source or "api") != "manual":
                cursor.execute(
                    """
                    UPDATE accounts
                       SET faceit_blocked = 0,
                           faceit_block_ends_at = NULL,
                           faceit_block_reason = NULL,
                           faceit_block_type = NULL,
                           faceit_block_game = NULL,
                           faceit_ban_signature = NULL,
                           faceit_block_source = NULL,
                           faceit_block_last_checked_at = ?
                     WHERE id = ?
                    """,
                    (now.isoformat(), aid),
                )
                updated_count += 1
            else:
                cursor.execute(
                    "UPDATE accounts SET faceit_block_last_checked_at = ? WHERE id = ?",
                    (now.isoformat(), aid),
                )
            continue

        signature = f"{ban.get('ban_id') or ''}:{ban.get('ends_at').isoformat()}"
        active_blocks.append({
            "id": aid,
            "login": steam_login,
            "nickname": result.get("nickname") or steam_login,
            "reason": ban.get("reason") or "-",
            "type": ban.get("type") or "-",
            "game": ban.get("game") or "-",
            "ends_at": ban.get("ends_at"),
        })

        newly_detected = (not faceit_blocked) or (faceit_ban_signature != signature)
        cursor.execute(
            """
            UPDATE accounts
               SET faceit_blocked = 1,
                   faceit_block_ends_at = ?,
                   faceit_block_reason = ?,
                   faceit_block_type = ?,
                   faceit_block_game = ?,
                   faceit_ban_signature = ?,
                   faceit_block_source = 'api',
                   faceit_block_last_checked_at = ?
             WHERE id = ?
            """,
            (
                ban.get("ends_at").isoformat(),
                ban.get("reason") or None,
                ban.get("type") or None,
                ban.get("game") or None,
                signature,
                now.isoformat(),
                aid,
            ),
        )
        if newly_detected and send_notifications:
            notifications.append(
                "🔒 Найдена блокировка Faceit\n"
                f"Аккаунт: {steam_login}\n"
                f"Ник: {result.get('nickname') or steam_login}\n"
                f"Срок блокировки: {format_remaining_time(ban.get('ends_at'))}\n"
                f"До окончания: {ban.get('ends_at').astimezone().strftime('%d.%m.%Y %H:%M') if ban.get('ends_at').tzinfo else ban.get('ends_at').strftime('%d.%m.%Y %H:%M')}\n"
                f"Причина: {ban.get('reason') or '-'}"
            )
        updated_count += 1

    if updated_count:
        conn.commit()

    return {
        "active_blocks": active_blocks,
        "blocked_count": len(active_blocks),
        "notifications": notifications,
        "errors": errors,
    }


def append_block_section(
    details_lines: list[str],
    title: str,
    blocked: bool,
    ends_at_raw,
    reason: str | None,
    block_type: str | None,
    source: str | None,
) -> None:
    if not blocked:
        return

    source_text = source or "-"
    block_type_text = block_type or "-"
    reason_text = reason or "-"
    ends_at = parse_iso_datetime(ends_at_raw)

    details_lines.extend([
        "",
        f"{title} блокировка:",
        "  Статус: активна",
        f"  Источник: {source_text}",
        f"  Тип: {block_type_text}",
        f"  Причина: {reason_text}",
        f"  До конца блокировки: {format_remaining_time(ends_at) if ends_at else 'неизвестно'}",
    ])


def build_block_menu_text(row, target: str) -> str:
    login = row[0]

    if target == "faceit":
        blocked = bool(row[9])
        ends_at_raw = row[10]
        reason = row[11]
        block_type = row[12]
        source = row[16] if len(row) > 16 else None
        title = "Faceit"
    else:
        blocked = bool(row[17])
        ends_at_raw = row[18]
        reason = row[19]
        block_type = row[20]
        source = row[21] if len(row) > 21 else None
        title = "Steam"

    ends_text = "не установлена"
    ends_dt = parse_iso_datetime(ends_at_raw)
    if blocked and ends_dt:
        ends_text = f"{ends_dt.astimezone().strftime('%d.%m.%Y %H:%M')} ({format_remaining_time(ends_dt)})"

    return (
        f"{title} блокировка для аккаунта {login}\n"
        f"Статус: {'активна' if blocked else 'не установлена'}\n"
        f"Источник: {source or '-'}\n"
        f"Тип: {block_type or '-'}\n"
        f"Причина: {reason or '-'}\n"
        f"До конца блокировки: {ends_text}\n\n"
        "Выберите срок кнопкой или отправьте текстом, например: 2 дня, 5 часов, 30 минут."
    )


def get_rentable_accounts() -> list[tuple]:
    cursor.execute(
        """
        SELECT id, steam_login, faceit_url, faceit_email, faceit_password, COALESCE(faceit_blocked, 0), COALESCE(steam_blocked, 0)
          FROM accounts
         WHERE status='free'
           AND NOT (COALESCE(steam_blocked, 0) = 1 AND COALESCE(faceit_blocked, 0) = 1)
         ORDER BY steam_login
        """
    )
    return cursor.fetchall()


def determine_rent_package(
    faceit_url: str | None,
    faceit_email: str | None,
    faceit_password: str | None,
    faceit_blocked: bool,
    steam_blocked: bool,
) -> str | None:
    has_faceit = any(
        value and str(value).strip()
        for value in (faceit_url, faceit_email, faceit_password)
    )

    if steam_blocked and not has_faceit:
        return None

    if not has_faceit and faceit_blocked:
        return None

    if faceit_blocked or not has_faceit:
        return "steam"

    return "steam_faceit"


def rent_package_label(package: str) -> str:
    return "Steam + Faceit" if package == "steam_faceit" else "Steam only"


async def build_account_details_text(row) -> str:
    s_login, s_pw_enc, email, e_pw_enc, f_url, f_email, f_pw_enc, st, rent_end, *rest = row
    s_pw = decrypt(s_pw_enc)
    e_pw = decrypt(e_pw_enc)
    f_pw = decrypt(f_pw_enc) if f_pw_enc is not None else None
    faceit_blocked = bool(rest[0]) if len(rest) > 0 and rest[0] is not None else False
    faceit_block_ends_at = rest[1] if len(rest) > 1 else None
    faceit_block_reason = rest[2] if len(rest) > 2 else None
    faceit_block_type = rest[3] if len(rest) > 3 else None
    faceit_block_source = rest[7] if len(rest) > 7 else None
    steam_blocked = bool(rest[8]) if len(rest) > 8 and rest[8] is not None else False
    steam_block_ends_at = rest[9] if len(rest) > 9 else None
    steam_block_reason = rest[10] if len(rest) > 10 else None
    steam_block_type = rest[11] if len(rest) > 11 else None
    steam_block_source = rest[12] if len(rest) > 12 else None
    faceit_2fa_secret = rest[13] if len(rest) > 13 else None
    steam_shared_secret = rest[14] if len(rest) > 14 else None
    steam_mafile_name = rest[17] if len(rest) > 17 else None
    steam_presence_state = rest[25] if len(rest) > 25 else None
    steam_presence_game = rest[26] if len(rest) > 26 else None
    steam_presence_checked_at = rest[27] if len(rest) > 27 else None
    account_note = rest[28] if len(rest) > 28 else None
    weekly_drop_claimed_period = rest[29] if len(rest) > 29 else None
    weekly_drop_claimed_at = rest[30] if len(rest) > 30 else None
    funpay_order_id = rest[31] if len(rest) > 31 else None
    funpay_order_url = rest[32] if len(rest) > 32 else None
    funpay_order_status = rest[33] if len(rest) > 33 else None
    funpay_order_price = rest[34] if len(rest) > 34 else None
    funpay_order_buyer = rest[35] if len(rest) > 35 else None
    funpay_order_chat_id = rest[36] if len(rest) > 36 else None
    funpay_order_last_sync_at = rest[37] if len(rest) > 37 else None
    funpay_order_last_code_sent_at = rest[38] if len(rest) > 38 else None
    rent_reminder_5m_sent_at = rest[39] if len(rest) > 39 else None
    rent_overdue_notified_at = rest[40] if len(rest) > 40 else None

    details_lines = [
        f"Данные аккаунта: {s_login}",
        f"Статус: {st}",
        f"Steam статус: {format_steam_presence_label(steam_presence_state, steam_presence_game)}",
        "",
        "Steam:",
        f"  Логин: {s_login}",
        f"  Пароль: {s_pw}",
        "",
        "Email:",
        f"  Адрес: {email or '-'}",
        f"  Пароль: {e_pw or '-'}",
    ]

    if f_url or f_email or f_pw_enc or faceit_2fa_secret:
        faceit_stats = await fetch_faceit_profile_stats(f_url)
        details_lines.extend([
            "",
            "Faceit:",
            f"  Ссылка: {f_url or '-'}",
            f"  Ник: {faceit_stats['nickname'] or '-'}",
            f"  Email: {f_email or '-'}",
            f"  Пароль: {f_pw or '-'}",
        ])
        if faceit_stats["elo"] is not None:
            details_lines.append(f"  Elo: {faceit_stats['elo']}")
            if faceit_stats["level"] is not None:
                details_lines.append(f"  Уровень: {faceit_stats['level']}")
        else:
            reason = faceit_stats["error"] or "не удалось получить"
            details_lines.append(f"  Elo: недоступно ({reason})")

        details_lines.append(f"  2FA: {'подключена' if faceit_2fa_secret else 'не настроена'}")

    details_lines.extend([
        "",
        "Steam Guard:",
        f"  Статус: {'подключён' if steam_shared_secret else 'не настроен'}",
    ])
    if steam_mafile_name:
        details_lines.append(f"  maFile: {steam_mafile_name}")

    details_lines.extend([
        "",
        "Заметка:",
        f"  {format_account_note_preview(account_note)}",
        f"Еженедельный дроп: {format_weekly_drop_label(row)}",
    ])
    if weekly_drop_claimed_period or weekly_drop_claimed_at:
        drop_meta = []
        if weekly_drop_claimed_period:
            drop_meta.append(f"период {weekly_drop_claimed_period}")
        if weekly_drop_claimed_at:
            dt = parse_iso_datetime(weekly_drop_claimed_at)
            drop_meta.append(
                f"отметка {dt.astimezone(LOCAL_TIMEZONE).strftime('%d.%m.%Y %H:%M') if dt else weekly_drop_claimed_at}"
            )
        details_lines.append("  " + " | ".join(drop_meta))

    details_lines.extend([
        "",
        "FunPay заказ:",
        f"  Номер: {funpay_order_id or '-'}",
        f"  Ссылка: {funpay_order_url or '-'}",
        f"  Чат: {'привязан' if funpay_order_chat_id else 'не привязан'}",
        f"  Статус: {format_funpay_optional_value(funpay_order_status, bool(funpay_order_id))}",
        f"  Цена: {format_funpay_optional_value(funpay_order_price, bool(funpay_order_id))}",
        f"  Покупатель: {format_funpay_optional_value(funpay_order_buyer, bool(funpay_order_id))}",
    ])
    if funpay_order_chat_id:
        details_lines.append(f"  Chat ID: {funpay_order_chat_id}")
    if funpay_order_last_sync_at:
        dt = parse_iso_datetime(funpay_order_last_sync_at)
        if dt:
            details_lines.append(f"  Синхронизация: {dt.astimezone(LOCAL_TIMEZONE).strftime('%d.%m.%Y %H:%M')}")
    elif funpay_order_id:
        details_lines.append("  Синхронизация: не получено")
    if funpay_order_last_code_sent_at:
        dt = parse_iso_datetime(funpay_order_last_code_sent_at)
        if dt:
            details_lines.append(f"  Код отправлен: {dt.astimezone(LOCAL_TIMEZONE).strftime('%d.%m.%Y %H:%M')}")
    if rent_reminder_5m_sent_at:
        dt = parse_iso_datetime(rent_reminder_5m_sent_at)
        if dt:
            details_lines.append(f"  Напоминание 5 мин: {dt.astimezone(LOCAL_TIMEZONE).strftime('%d.%m.%Y %H:%M')}")
    if rent_overdue_notified_at:
        dt = parse_iso_datetime(rent_overdue_notified_at)
        if dt:
            details_lines.append(f"  Просрочка: {dt.astimezone(LOCAL_TIMEZONE).strftime('%d.%m.%Y %H:%M')}")

    if steam_presence_checked_at:
        checked_at_dt = parse_iso_datetime(steam_presence_checked_at)
        if checked_at_dt:
            details_lines.append(
                f"Steam статус обновлён: {checked_at_dt.astimezone(LOCAL_TIMEZONE).strftime('%d.%m.%Y %H:%M')}"
            )

    append_block_section(
        details_lines,
        "Faceit",
        faceit_blocked,
        faceit_block_ends_at,
        faceit_block_reason,
        faceit_block_type,
        faceit_block_source,
    )
    append_block_section(
        details_lines,
        "Steam",
        steam_blocked,
        steam_block_ends_at,
        steam_block_reason,
        steam_block_type,
        steam_block_source or "manual",
    )

    if st == "busy" and rent_end:
        try:
            dt = datetime.fromisoformat(rent_end)
            mins = max(0, int((dt - datetime.now()).total_seconds() / 60))
            details_lines.extend(["", f"До конца аренды: ~{mins} мин"])
        except Exception:
            pass

    return "\n".join(details_lines)


def detail_actions_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="Код Steam"), KeyboardButton(text="Код Faceit")],
            [KeyboardButton(text="Код Steam в заказ"), KeyboardButton(text="Код Faceit в заказ")],
            [KeyboardButton(text="Блокировка Faceit"), KeyboardButton(text="Блокировка Steam")],
            [KeyboardButton(text="История аренд"), KeyboardButton(text="Дроп")],
            [KeyboardButton(text="Редактировать"), KeyboardButton(text="Удалить")],
            [KeyboardButton(text="Назад")],
        ],
        resize_keyboard=True
    )


def drop_actions_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="Забрал дроп")],
            [KeyboardButton(text="Сбросить отметку")],
            [KeyboardButton(text="Назад")],
        ],
        resize_keyboard=True
    )


def block_actions_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="30 минут"), KeyboardButton(text="1 час"), KeyboardButton(text="3 часа")],
            [KeyboardButton(text="6 часов"), KeyboardButton(text="12 часов"), KeyboardButton(text="1 день")],
            [KeyboardButton(text="Снять блок")],
            [KeyboardButton(text="Назад")],
        ],
        resize_keyboard=True
    )


def trade_actions_kb(has_mafile: bool) -> ReplyKeyboardMarkup:
    clear_row = [KeyboardButton(text="Очистить maFile")] if has_mafile else [KeyboardButton(text="Назад")]

    keyboard = [
        [KeyboardButton(text="Показать подтверждения Steam")],
        [KeyboardButton(text="Подтвердить все"), KeyboardButton(text="Отклонить все")],
    ]
    if has_mafile:
        keyboard.append(clear_row)
        keyboard.append([KeyboardButton(text="Назад")])
    else:
        keyboard.append(clear_row)

    return ReplyKeyboardMarkup(keyboard=keyboard, resize_keyboard=True)


def rent_mode_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="Steam"), KeyboardButton(text="Faceit")],
            [KeyboardButton(text="Steam + Faceit")],
            [KeyboardButton(text="Назад")],
        ],
        resize_keyboard=True
    )


def rent_time_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="30 минут"), KeyboardButton(text="1 час"), KeyboardButton(text="2 часа")],
            [KeyboardButton(text="3 часа"), KeyboardButton(text="6 часов"), KeyboardButton(text="12 часов")],
            [KeyboardButton(text="24 часа")],
            [KeyboardButton(text="Отмена")]
        ],
        resize_keyboard=True
    )


def copy_buffer_kb(copy_text: str, button_text: str = "Скопировать в буфер") -> InlineKeyboardMarkup | None:
    value = (copy_text or "").strip()
    if not value or len(value) > 256:
        return None

    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=button_text, copy_text=CopyTextButton(text=value))]
        ]
    )


def build_trade_menu_text(row) -> str:
    steam_shared_secret = row[23] if len(row) > 23 else None
    steam_identity_secret = row[24] if len(row) > 24 else None
    steam_device_id = row[25] if len(row) > 25 else None
    steam_mafile_name = row[26] if len(row) > 26 else None
    steam_session_id = row[27] if len(row) > 27 else None
    steam_login_secure_cookie = row[29] if len(row) > 29 else None
    steam_steamid64 = row[31] if len(row) > 31 else None
    steam_access_token = row[32] if len(row) > 32 else None
    steam_refresh_token = row[33] if len(row) > 33 else None

    shared_ready = bool(steam_shared_secret)
    trade_ready = steam_trade_ready(row)
    token_ready = steam_token_session_ready(row)
    session_mode = steam_session_mode(row)

    lines = [
        f"Трейд-меню: {row[0]}",
        "",
        f"Steam Guard вход: {'настроен' if shared_ready else 'не настроен'}",
        f"Трейд-подтверждения: {'готовы' if trade_ready else ('токены загружены' if token_ready else 'не настроены')}",
        f"Identity secret: {'есть' if steam_identity_secret else 'нет'}",
        f"Device ID: {'есть' if steam_device_id else 'нет'}",
        f"SteamID64: {'есть' if steam_steamid64 else 'нет'}",
        f"Session ID: {'есть' if steam_session_id else 'нет'}",
        f"SteamLoginSecure: {'есть' if steam_login_secure_cookie else 'нет'}",
        f"AccessToken: {'есть' if steam_access_token else 'нет'}",
        f"RefreshToken: {'есть' if steam_refresh_token else 'нет'}",
        f"maFile: {steam_mafile_name or 'не загружен'}",
    ]

    if not steam_mafile_name:
        lines.extend([
            "",
            "Для подготовки трейдов загрузите maFile аккаунта.",
        ])
    elif not trade_ready:
        if session_mode == "token":
            lines.extend([
                "",
                "maFile загружен в новом token-формате Steam.",
                "Токены сохранены, но текущая логика подтверждений ещё ожидает cookie-сессию Steam.",
            ])
        else:
            lines.extend([
                "",
                "maFile загружен, но в нём не хватает данных для трейд-подтверждений.",
            ])

    return "\n".join(lines)


def delete_confirm_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="Подтвердить удаление")],
            [KeyboardButton(text="Отмена")],
        ],
        resize_keyboard=True
    )


def data_menu_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="Создать копию"), KeyboardButton(text="Загрузить копию")],
            [KeyboardButton(text="FACEIT API"), KeyboardButton(text="STEAM API")],
            [KeyboardButton(text="FUNPAY")],
            [KeyboardButton(text="Назад")],
        ],
        resize_keyboard=True
    )


def faceit_api_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="Ввести/обновить ключ")],
            [KeyboardButton(text="Удалить ключ")],
            [KeyboardButton(text="Назад")],
        ],
        resize_keyboard=True
    )


def steam_api_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="Ввести/обновить ключ")],
            [KeyboardButton(text="Удалить ключ")],
            [KeyboardButton(text="Назад")],
        ],
        resize_keyboard=True
    )


def funpay_api_kb() -> ReplyKeyboardMarkup:
    key_status = "изменить" if resolve_funpay_golden_key() else "ввести"
    ua_status = "изменить" if resolve_funpay_user_agent() else "ввести"

    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text=f"{key_status.title()} Golden Key")],
            [KeyboardButton(text=f"{ua_status.title()} User-Agent")],
            [KeyboardButton(text="Назад")],
        ],
        resize_keyboard=True
    )


def funpay_settings_kb() -> ReplyKeyboardMarkup:
    key_status = "изменить" if resolve_funpay_golden_key() else "ввести"
    ua_status = "изменить" if resolve_funpay_user_agent() else "ввести"
    auto_status = "выключен"
    if get_funpay_auto_raise_enabled():
        auto_status = "включён"

    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="Баланс FunPay")],
            [KeyboardButton(text=f"Автоподъём: {auto_status}")],
            [KeyboardButton(text=f"{key_status.title()} Golden Key"), KeyboardButton(text=f"{ua_status.title()} User-Agent")],
            [KeyboardButton(text="Назад")],
        ],
        resize_keyboard=True
    )


def edit_fields_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="Steam логин"), KeyboardButton(text="Steam пароль")],
            [KeyboardButton(text="Steam shared secret"), KeyboardButton(text="Steam identity secret")],
            [KeyboardButton(text="SteamID64"), KeyboardButton(text="Загрузить maFile")],
            [KeyboardButton(text="Заметка")],
            [KeyboardButton(text="Email"), KeyboardButton(text="Пароль email")],
            [KeyboardButton(text="Faceit ссылка"), KeyboardButton(text="Faceit email")],
            [KeyboardButton(text="Пароль Faceit"), KeyboardButton(text="Faceit 2FA secret")],
            [KeyboardButton(text="Назад")],
        ],
        resize_keyboard=True
    )


def parse_extend_delta(text: str) -> timedelta | None:
    txt = (text or "").strip().lower().replace("минут", "мин").replace("часов", "час").replace("часа", "час")
    if txt in {"30 мин", "30 минут", "+30 мин", "+30 минут"}:
        return timedelta(minutes=30)

    if txt.startswith("+"):
        txt = txt[1:].strip()

    if " " not in txt:
        return None

    amount_raw, unit = txt.split(maxsplit=1)
    if not amount_raw.isdigit():
        return None

    amount = int(amount_raw)
    if unit.startswith("мин"):
        if amount < 30:
            return None
        return timedelta(minutes=amount)
    if unit.startswith("час"):
        return timedelta(hours=amount)
    return None


def parse_block_duration(text: str) -> timedelta | None:
    raw = (text or "").strip().lower()
    if not raw:
        return None

    normalized = raw.replace(",", ".")
    presets = {
        "30 минут": timedelta(minutes=30),
        "1 час": timedelta(hours=1),
        "3 часа": timedelta(hours=3),
        "6 часов": timedelta(hours=6),
        "12 часов": timedelta(hours=12),
        "1 день": timedelta(days=1),
    }
    if normalized in presets:
        return presets[normalized]

    match = re.fullmatch(r"(\d+)\s*(минут(?:а|ы)?|мин|час(?:а|ов)?|day|days|дн(?:я|ей)?|день)", normalized)
    if not match:
        return None

    amount = int(match.group(1))
    unit = match.group(2)
    if unit in {"минут", "минута", "минуты", "мин"}:
        return timedelta(minutes=amount)
    if unit in {"час", "часа", "часов"}:
        return timedelta(hours=amount)
    if unit in {"day", "days", "день", "дня", "дней"}:
        return timedelta(days=amount)
    return None


def write_database_backup(backup_path: str) -> None:
    conn.commit()
    dest = sqlite3.connect(backup_path)
    try:
        conn.backup(dest)
        dest.commit()
    finally:
        dest.close()


def validate_backup_file(backup_path: str) -> None:
    test_conn = sqlite3.connect(backup_path)
    try:
        test_cursor = test_conn.cursor()
        test_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='accounts'")
        if test_cursor.fetchone() is None:
            raise ValueError("В копии нет таблицы accounts")
    finally:
        test_conn.close()


def restore_database_from_file(backup_path: str) -> None:
    conn.commit()
    src = sqlite3.connect(backup_path)
    try:
        src.backup(conn)
        conn.commit()
    finally:
        src.close()

    ensure_faceit_url_column()
    ensure_faceit_block_columns()
    ensure_steam_block_columns()
    ensure_rent_history_table()
    ensure_steam_trade_columns()
    ensure_steam_presence_columns()
    ensure_account_note_columns()
    ensure_funpay_order_columns()
    migrate_encryption()

# ────────────────────────────────────────────────
#  Отмена любого состояния
# ────────────────────────────────────────────────

@dp.message(F(equals=["отмена", "cancel"], ignore_case=True))
@dp.message(Command("cancel"))
async def cancel_any_state(message: types.Message, state: FSMContext):
    if await state.get_state() is None:
        return await message.answer("Нечего отменять.", reply_markup=main_menu)

    await state.clear()
    await message.answer("Действие отменено.", reply_markup=main_menu)

# ────────────────────────────────────────────────
#  /start
# ────────────────────────────────────────────────

@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    if message.from_user.id not in ADMIN_IDS:
        return
    clean_invalid_dates()
    await message.answer("Добро пожаловать в панель аренды", reply_markup=main_menu)

# ────────────────────────────────────────────────
#  Добавление аккаунта — полный цикл
# ────────────────────────────────────────────────

@dp.message(F.text == "➕ Добавить")
async def add_start(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS: return
    await state.set_state(AddAccount.steam_login)
    await message.answer("Логин Steam:", reply_markup=cancel_kb)

@dp.message(StateFilter(AddAccount.steam_login))
async def add_login(message: types.Message, state: FSMContext):
    await state.update_data(steam_login=message.text.strip())
    await state.set_state(AddAccount.steam_password)
    await message.answer("Пароль Steam:", reply_markup=cancel_kb)

@dp.message(StateFilter(AddAccount.steam_password))
async def add_steam_pw(message: types.Message, state: FSMContext):
    await state.update_data(steam_password=message.text.strip())
    await state.set_state(AddAccount.email)
    await message.answer("Email:", reply_markup=cancel_kb)

@dp.message(StateFilter(AddAccount.email))
async def add_email(message: types.Message, state: FSMContext):
    await state.update_data(email=message.text.strip())
    await state.set_state(AddAccount.email_password)
    await message.answer("Пароль email:", reply_markup=cancel_kb)

@dp.message(StateFilter(AddAccount.email_password))
async def add_email_pw(message: types.Message, state: FSMContext):
    await state.update_data(email_password=message.text.strip())
    await state.set_state(AddAccount.faceit_choice)
    await message.answer("Есть Faceit? (да / нет)", reply_markup=cancel_kb)

@dp.message(StateFilter(AddAccount.faceit_choice))
async def add_faceit_choice(message: types.Message, state: FSMContext):
    txt = message.text.lower().strip()
    if txt == "да":
        await state.set_state(AddAccount.faceit_url)
        await message.answer(
            "Ссылка на Faceit профиль:\n"
            "Пример: https://www.faceit.com/ru/players/Rinaharl",
            reply_markup=cancel_kb
        )
    elif txt == "нет":
        await state.update_data(faceit_url=None, faceit_email=None, faceit_password=None)
        await show_confirm_add(message, state)
    else:
        await message.answer("Ответьте «да» или «нет».", reply_markup=cancel_kb)

@dp.message(StateFilter(AddAccount.faceit_url))
async def add_faceit_url(message: types.Message, state: FSMContext):
    value = (message.text or "").strip()
    if not value:
        return await message.answer("Ссылка не может быть пустой.", reply_markup=cancel_kb)

    await state.update_data(faceit_url=value)
    await state.set_state(AddAccount.faceit_email)
    await message.answer("Email Faceit:", reply_markup=cancel_kb)

@dp.message(StateFilter(AddAccount.faceit_email))
async def add_faceit_email(message: types.Message, state: FSMContext):
    await state.update_data(faceit_email=message.text.strip())
    await state.set_state(AddAccount.faceit_password)
    await message.answer("Пароль Faceit:", reply_markup=cancel_kb)

@dp.message(StateFilter(AddAccount.faceit_password))
async def add_faceit_pw(message: types.Message, state: FSMContext):
    await state.update_data(faceit_password=message.text.strip())
    await show_confirm_add(message, state)

async def show_confirm_add(message: types.Message, state: FSMContext):
    d = await state.get_data()
    text = (
        f"Подтвердите добавление:\n\n"
        f"Steam: {d['steam_login']} : ********\n"
        f"Email: {d['email']} : ********\n"
        f"Faceit ссылка: {d.get('faceit_url') or 'Нет'}\n"
        f"Faceit email: {d.get('faceit_email') or 'Нет'}"
    )
    kb = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="Подтвердить")],
            [KeyboardButton(text="Отмена")]
        ],
        resize_keyboard=True
    )
    await state.set_state(AddAccount.confirm)
    await message.answer(text, reply_markup=kb)

@dp.message(StateFilter(AddAccount.confirm))
async def add_confirm(message: types.Message, state: FSMContext):
    if (message.text or "").strip().lower() != "подтвердить":
        await state.clear()
        return await message.answer("Добавление отменено.", reply_markup=main_menu)

    d = await state.get_data()
    login = d["steam_login"]

    cursor.execute("SELECT 1 FROM accounts WHERE steam_login = ?", (login,))
    if cursor.fetchone():
        await state.clear()
        return await message.answer("Такой логин уже существует!", reply_markup=main_menu)

    try:
        cursor.execute("""
            INSERT INTO accounts (
                steam_login, steam_password, email, email_password,
                faceit_url, faceit_email, faceit_password, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'free')
        """, (
            login,
            encrypt(d["steam_password"]),
            d["email"],
            encrypt(d["email_password"]),
            d.get("faceit_url"),
            d.get("faceit_email"),
            encrypt(d.get("faceit_password"))
        ))
        conn.commit()
        await message.answer("Аккаунт успешно добавлен!", reply_markup=main_menu)
    except sqlite3.IntegrityError:
        conn.rollback()
        await message.answer("Ошибка: такой логин уже существует.", reply_markup=main_menu)
    except Exception as e:
        conn.rollback()
        logging.error(f"add_confirm error: {e}")
        await message.answer("Ошибка сохранения. Попробуйте позже.", reply_markup=main_menu)

    await state.clear()

# ────────────────────────────────────────────────
#  Просмотр списка
# ────────────────────────────────────────────────

@dp.message(F.text == "📦 Аккаунты")
async def show_accounts(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS: return
    clean_invalid_dates()
    clean_expired_faceit_blocks()
    clean_expired_steam_blocks()

    await render_accounts_list(message, state)


async def render_accounts_list(message: types.Message, state: FSMContext):
    await state.clear()
    cursor.execute(
        """
        SELECT id, steam_login, status, rent_end,
               faceit_blocked, faceit_block_ends_at,
               steam_blocked, steam_block_ends_at,
               steam_presence_state, steam_presence_game,
               funpay_order_id, funpay_order_status
          FROM accounts
         ORDER BY steam_login
        """
    )
    rows = cursor.fetchall()

    if not rows:
        return await message.answer("Аккаунтов нет", reply_markup=main_menu)

    lines = []
    rows_data = []
    for aid, login, st, end, faceit_blocked, faceit_block_end, steam_blocked, steam_block_end, steam_presence_state, steam_presence_game, funpay_order_id, funpay_order_status in rows:
        rows_data.append({
            "id": aid,
            "login": login,
            "status": st,
            "end": end,
            "faceit_blocked": faceit_blocked,
            "faceit_block_end": faceit_block_end,
            "steam_blocked": steam_blocked,
            "steam_block_end": steam_block_end,
            "steam_presence_state": steam_presence_state,
            "steam_presence_game": steam_presence_game,
            "funpay_order_id": funpay_order_id,
            "funpay_order_status": funpay_order_status,
        })

        has_blocks = bool(faceit_blocked) or bool(steam_blocked)
        prefix = "🔴" if st == "busy" else ("🔒" if has_blocks else "🟢")
        parts = [f"{prefix} {login}"]

        if st == "busy" and end:
            try:
                dt = datetime.fromisoformat(end)
                mins = max(0, int((dt - datetime.now()).total_seconds() / 60))
                parts.append(f"аренда {mins} мин")
            except Exception:
                parts.append("аренда: ошибка даты")

        if faceit_blocked:
            block_dt = parse_iso_datetime(faceit_block_end)
            parts.append("Faceit " + (format_remaining_time(block_dt) if block_dt else "блокировка"))

        if steam_blocked:
            block_dt = parse_iso_datetime(steam_block_end)
            parts.append("Steam " + (format_remaining_time(block_dt) if block_dt else "блокировка"))

        presence_text = format_steam_presence_label(steam_presence_state, steam_presence_game)
        if presence_text != "нет данных":
            parts.append("Steam " + presence_text)

        if funpay_order_id:
            order_part = f"FunPay заказ {funpay_order_id}"
            if funpay_order_status:
                order_part += f" ({funpay_order_status})"
            parts.append(order_part)

        lines.append(" | ".join(parts))

    kb = ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=acc["login"])] for acc in rows_data] + [[KeyboardButton(text="Отмена")]],
        resize_keyboard=True
    )
    await state.set_state(AccountDetails.select_account)
    await state.update_data(accounts=rows_data)
    await message.answer(
        (("\n".join(lines) or "Пусто") + "\n\nВыберите аккаунт для просмотра данных:"),
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
        return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

    aid = chosen["id"]
    row = get_account_by_id(aid)
    if not row:
        await state.clear()
        return await message.answer("Ошибка: аккаунт не найден в базе.", reply_markup=main_menu)

    await state.update_data(selected_id=aid, selected_login=login)
    await state.set_state(AccountDetails.view_action)
    await message.answer(await build_account_details_text(row), reply_markup=detail_actions_kb())


@dp.message(StateFilter(AccountDetails.view_action))
async def account_detail_action(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()
    data = await state.get_data()
    aid = data.get("selected_id")
    row = get_account_by_id(aid) if aid else None
    faceit_blocked = bool(row[9]) if row and len(row) > 9 else False
    faceit_2fa_secret = row[22] if row and len(row) > 22 else None
    steam_shared_secret = row[23] if row and len(row) > 23 else None

    if txt == "назад":
        await state.clear()
        return await render_accounts_list(message, state)

    if txt == "трейд":
        return await message.answer(
            "Раздел трейдов скрыт из интерфейса и пока не используется в работе.",
            reply_markup=detail_actions_kb()
        )

    if txt == "дроп":
        if not row:
            await state.clear()
            return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

        await state.set_state(AccountDrop.menu)
        return await message.answer(
            build_weekly_drop_menu_text(row),
            reply_markup=drop_actions_kb()
        )

    if txt in {"steam код", "код steam", "код стим"}:
        if not row:
            await state.clear()
            return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

        if not steam_shared_secret:
            return await message.answer(
                "Для этого аккаунта не сохранён Steam shared secret.\n"
                "Сначала добавьте его в поле «Steam shared secret».",
                reply_markup=detail_actions_kb()
            )

        try:
            code, seconds_left = generate_steam_guard_code(decrypt(steam_shared_secret))
        except Exception as e:
            logging.error(f"steam code error: {e}")
            return await message.answer(
                "Не удалось сгенерировать Steam код. Проверьте, что shared secret введён корректно.",
                reply_markup=detail_actions_kb()
            )

        return await message.answer(
            f"Steam Guard код для {row[0]}:\n"
            f"{code}\n"
            f"Код обновится через {seconds_left} сек.",
            reply_markup=copy_buffer_kb(code, "Скопировать код")
        )

    if txt in {"2fa код", "код faceit", "код фэйсит", "код фейсит"}:
        if not row:
            await state.clear()
            return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

        if not faceit_2fa_secret:
            return await message.answer(
                "Для этого аккаунта не сохранён Faceit 2FA secret.\n"
                "Сначала добавьте его в поле «Faceit 2FA secret».",
                reply_markup=detail_actions_kb()
            )

        try:
            code, seconds_left = generate_totp_code(decrypt(faceit_2fa_secret))
        except Exception as e:
            logging.error(f"2fa code error: {e}")
            return await message.answer(
                "Не удалось сгенерировать код. Проверьте, что secret введён корректно.",
                reply_markup=detail_actions_kb()
            )

        return await message.answer(
            f"Faceit 2FA код для {row[0]}:\n"
            f"{code}\n"
            f"Код обновится через {seconds_left} сек.",
            reply_markup=copy_buffer_kb(code, "Скопировать код")
        )

    if txt in {"код steam в заказ", "код faceit в заказ"}:
        if not row:
            await state.clear()
            return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

        chat_id = row[45] if len(row) > 45 else None
        buyer_username = row[44] if len(row) > 44 else None
        order_id = row[40] if len(row) > 40 else None
        golden_key = resolve_funpay_golden_key()
        if not chat_id and buyer_username and golden_key:
            try:
                acc = _funpay_build_account_sync(golden_key, resolve_funpay_user_agent())
                chat = acc.get_chat_by_name(buyer_username, True)
                chat_id = getattr(chat, "id", None)
            except Exception as e:
                logging.error(f"order chat resolve error: {e}")

        code_type = "steam" if "steam" in txt else "faceit"
        if code_type == "faceit" and faceit_blocked:
            return await message.answer(
                "Для этого аккаунта Faceit заблокирован, поэтому Faceit-код в заказ не отправляется.",
                reply_markup=detail_actions_kb()
            )

        try:
            result = await asyncio.to_thread(
                _funpay_send_code_to_order_sync,
                order_id or "",
                code_type,
                row[0],
                steam_shared_secret,
                faceit_2fa_secret,
                aid,
            )
            if result.get("error"):
                return await message.answer(str(result["error"]), reply_markup=detail_actions_kb())
            cursor.execute(
                "UPDATE accounts SET funpay_order_last_code_sent_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), aid),
            )
            conn.commit()
        except Exception as e:
            logging.error(f"order code send error: {e}")
            return await message.answer(
                "Не удалось отправить код в чат заказа.",
                reply_markup=detail_actions_kb()
            )

        label = "Steam" if code_type == "steam" else "Faceit"
        return await message.answer(f"{label} код отправлен в чат заказа FunPay.", reply_markup=detail_actions_kb())

    if txt in {"блокировка faceit", "блокировка steam"}:
        if not row:
            await state.clear()
            return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

        block_target = "faceit" if "faceit" in txt else "steam"
        await state.update_data(block_target=block_target)
        await state.set_state(BlockAccount.menu)
        return await message.answer(
            build_block_menu_text(row, block_target),
            reply_markup=block_actions_kb()
        )

    if txt == "история аренд":
        if not row:
            await state.clear()
            return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

        history_rows = get_rent_history(aid, limit=10)
        return await message.answer(
            format_rent_history_text(row[0], history_rows),
            reply_markup=detail_actions_kb()
        )

    if txt != "редактировать":
        if txt == "удалить":
            if not row:
                await state.clear()
                return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

            st = row[7]
            if st == "busy":
                return await message.answer(
                    "Этот аккаунт сейчас в аренде. Сначала освободите его, затем удаляйте.",
                    reply_markup=detail_actions_kb()
                )

            await state.set_state(DeleteAccount.confirm)
            return await message.answer(
                "Подтвердите удаление аккаунта. Это действие необратимо.",
                reply_markup=delete_confirm_kb()
            )

        return await message.answer("Выберите действие из кнопок ниже.", reply_markup=detail_actions_kb())

    if not aid:
        await state.clear()
        return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

    await state.set_state(EditAccount.choose_field)
    await message.answer("Что изменить?", reply_markup=edit_fields_kb())


@dp.message(StateFilter(AccountDrop.menu))
async def account_drop_action(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()
    data = await state.get_data()
    aid = data.get("selected_id")

    if not aid:
        await state.clear()
        return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

    row = get_account_by_id(aid)
    if not row:
        await state.clear()
        return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

    if txt == "назад":
        await state.set_state(AccountDetails.view_action)
        return await message.answer(await build_account_details_text(row), reply_markup=detail_actions_kb())

    if txt == "забрал дроп":
        try:
            set_weekly_drop_claimed(aid, True)
            conn.commit()
        except Exception as e:
            conn.rollback()
            logging.error(f"weekly drop mark error: {e}")
            return await message.answer("Не удалось сохранить отметку о дропе.", reply_markup=drop_actions_kb())

        updated = get_account_by_id(aid)
        await state.set_state(AccountDrop.menu)
        return await message.answer(
            build_weekly_drop_menu_text(updated or row),
            reply_markup=drop_actions_kb()
        )

    if txt == "сбросить отметку":
        try:
            set_weekly_drop_claimed(aid, False)
            conn.commit()
        except Exception as e:
            conn.rollback()
            logging.error(f"weekly drop reset error: {e}")
            return await message.answer("Не удалось сбросить отметку о дропе.", reply_markup=drop_actions_kb())

        updated = get_account_by_id(aid)
        await state.set_state(AccountDrop.menu)
        return await message.answer(
            build_weekly_drop_menu_text(updated or row),
            reply_markup=drop_actions_kb()
        )

    return await message.answer("Выберите действие из кнопок ниже.", reply_markup=drop_actions_kb())


@dp.message(StateFilter(BlockAccount.menu))
async def block_account_action(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()
    data = await state.get_data()
    aid = data.get("selected_id")
    block_target = data.get("block_target")

    if not aid or block_target not in {"faceit", "steam"}:
        await state.clear()
        return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

    row = get_account_by_id(aid)
    if not row:
        await state.clear()
        return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

    if txt == "назад":
        await state.set_state(AccountDetails.view_action)
        return await message.answer(await build_account_details_text(row), reply_markup=detail_actions_kb())

    if txt in {"снять блок", "снять"}:
        try:
            clear_account_block(aid, block_target)
            conn.commit()
        except Exception as e:
            conn.rollback()
            logging.error(f"clear block error: {e}")
            return await message.answer("Не удалось снять блокировку.", reply_markup=block_actions_kb())

        await state.set_state(AccountDetails.view_action)
        updated = get_account_by_id(aid)
        return await message.answer(await build_account_details_text(updated or row), reply_markup=detail_actions_kb())

    duration = parse_block_duration(txt)
    if duration is None:
        return await message.answer(
            "Выберите срок кнопкой или отправьте его текстом, например: 2 дня, 5 часов, 30 минут.",
            reply_markup=block_actions_kb()
        )

    ends_at = datetime.now(timezone.utc) + duration
    try:
        set_account_block(
            aid,
            block_target,
            ends_at,
            reason="ручная блокировка",
            block_type="manual",
            source="manual",
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        logging.error(f"set block error: {e}")
        return await message.answer("Не удалось сохранить блокировку.", reply_markup=block_actions_kb())

    await state.set_state(AccountDetails.view_action)
    updated = get_account_by_id(aid)
    return await message.answer(await build_account_details_text(updated or row), reply_markup=detail_actions_kb())


@dp.message(StateFilter(TradeMenu.menu))
async def trade_menu_action(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()
    data = await state.get_data()
    aid = data.get("selected_id")

    if not aid:
        await state.clear()
        return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

    row = get_account_by_id(aid)
    if not row:
        await state.clear()
        return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

    has_mafile = bool(row[26] if len(row) > 26 else None)

    if txt == "назад":
        await state.set_state(AccountDetails.view_action)
        return await message.answer(await build_account_details_text(row), reply_markup=detail_actions_kb())

    if txt == "очистить mafile":
        try:
            cursor.execute(
                """
                UPDATE accounts
                   SET steam_shared_secret = NULL,
                       steam_identity_secret = NULL,
                       steam_device_id = NULL,
                       steam_mafile_name = NULL,
                       steam_session_id = NULL,
                       steam_login_cookie = NULL,
                       steam_login_secure_cookie = NULL,
                       steam_webcookie = NULL,
                       steam_steamid64 = NULL,
                       steam_access_token = NULL,
                       steam_refresh_token = NULL
                 WHERE id = ?
                """,
                (aid,),
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            logging.error(f"clear mafile error: {e}")
            return await message.answer(
                "Не удалось очистить данные maFile.",
                reply_markup=trade_actions_kb(has_mafile)
            )

        updated = get_account_by_id(aid)
        return await message.answer(
            build_trade_menu_text(updated or row),
            reply_markup=trade_actions_kb(False)
        )

    if txt == "показать подтверждения steam":
        result = await steam_fetch_confirmations(aid, row)
        if result.get("error"):
            return await message.answer(
                f"Не удалось получить подтверждения Steam:\n{result['error']}",
                reply_markup=trade_actions_kb(has_mafile)
            )

        confirmations = result.get("confirmations", [])
        if not confirmations:
            return await message.answer(
                "Активных подтверждений Steam сейчас нет.",
                reply_markup=trade_actions_kb(has_mafile)
            )

        lines = [f"Активных подтверждений Steam: {len(confirmations)}", ""]
        for index, item in enumerate(confirmations[:15], start=1):
            details = item.get("details") or "-"
            lines.append(f"{index}. {item.get('title') or 'Без названия'}")
            lines.append(f"   {details}")

        if len(confirmations) > 15:
            lines.extend(["", f"Показаны первые 15 из {len(confirmations)} подтверждений."])

        return await message.answer("\n".join(lines), reply_markup=trade_actions_kb(has_mafile))

    if txt == "подтвердить все":
        fetch_result = await steam_fetch_confirmations(aid, row)
        if fetch_result.get("error"):
            return await message.answer(
                f"Не удалось получить подтверждения перед подтверждением:\n{fetch_result['error']}",
                reply_markup=trade_actions_kb(has_mafile)
            )

        confirmations = fetch_result.get("confirmations", [])
        action_result = await steam_send_confirmation_multi(aid, row, "allow", confirmations)
        if action_result.get("error"):
            return await message.answer(
                f"Не удалось подтвердить трейды:\n{action_result['error']}",
                reply_markup=trade_actions_kb(has_mafile)
            )

        return await message.answer(
            f"Подтверждено Steam-подтверждений: {action_result.get('count', 0)}",
            reply_markup=trade_actions_kb(has_mafile)
        )

    if txt == "отклонить все":
        fetch_result = await steam_fetch_confirmations(aid, row)
        if fetch_result.get("error"):
            return await message.answer(
                f"Не удалось получить подтверждения перед отклонением:\n{fetch_result['error']}",
                reply_markup=trade_actions_kb(has_mafile)
            )

        confirmations = fetch_result.get("confirmations", [])
        action_result = await steam_send_confirmation_multi(aid, row, "cancel", confirmations)
        if action_result.get("error"):
            return await message.answer(
                f"Не удалось отклонить трейды:\n{action_result['error']}",
                reply_markup=trade_actions_kb(has_mafile)
            )

        return await message.answer(
            f"Отклонено Steam-подтверждений: {action_result.get('count', 0)}",
            reply_markup=trade_actions_kb(has_mafile)
        )

    return await message.answer(
        "Выберите действие из меню трейдов.",
        reply_markup=trade_actions_kb(has_mafile)
    )


@dp.message(StateFilter(TradeMenu.wait_mafile))
async def trade_menu_wait_mafile(message: types.Message, state: FSMContext):
    data = await state.get_data()
    aid = data.get("selected_id")

    if not aid:
        await state.clear()
        return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

    if (message.text or "").strip().lower() == "отмена":
        row = get_account_by_id(aid)
        await state.set_state(TradeMenu.menu)
        if not row:
            await state.clear()
            return await message.answer("Аккаунт не найден.", reply_markup=main_menu)
        return await message.answer(
            build_trade_menu_text(row),
            reply_markup=trade_actions_kb(bool(row[26] if len(row) > 26 else None))
        )

    if not message.document:
        return await message.answer("Нужно отправить именно maFile документом.", reply_markup=cancel_kb)

    filename = message.document.file_name or "steam.maFile"
    if not filename.lower().endswith((".mafile", ".json", ".txt")):
        return await message.answer("Поддерживаются файлы `.maFile`, `.json` или `.txt`.", reply_markup=cancel_kb)

    temp_dir = tempfile.mkdtemp(prefix="steam_mafile_", dir=BACKUP_DIR)
    temp_path = os.path.join(temp_dir, filename)

    try:
        await bot.download(message.document, destination=temp_path)
        with open(temp_path, "r", encoding="utf-8-sig") as f:
            save_steam_mafile_to_account(aid, filename, f.read())
        if cursor.rowcount == 0:
            conn.rollback()
            await state.clear()
            return await message.answer("Аккаунт не найден или уже удалён.", reply_markup=main_menu)
        conn.commit()
    except Exception as e:
        conn.rollback()
        logging.error(f"mafile import error: {e}")
        return await message.answer(
            f"Не удалось обработать maFile: {e}",
            reply_markup=cancel_kb
        )
    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

    row = get_account_by_id(aid)
    if not row:
        await state.clear()
        return await message.answer("Данные сохранены, но аккаунт не найден для повторного открытия.", reply_markup=main_menu)

    await state.set_state(TradeMenu.menu)
    return await message.answer(
        "maFile успешно загружен. Steam Guard и трейд-секреты сохранены.",
        reply_markup=trade_actions_kb(True)
    )


@dp.message(StateFilter(EditAccount.wait_mafile))
async def edit_wait_mafile(message: types.Message, state: FSMContext):
    data = await state.get_data()
    aid = data.get("selected_id")

    if not aid:
        await state.clear()
        return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

    if not message.document:
        return await message.answer("Нужно отправить именно maFile документом.", reply_markup=cancel_kb)

    filename = message.document.file_name or "steam.maFile"
    if not filename.lower().endswith((".mafile", ".json", ".txt")):
        return await message.answer("Поддерживаются файлы `.maFile`, `.json` или `.txt`.", reply_markup=cancel_kb)

    temp_dir = tempfile.mkdtemp(prefix="steam_mafile_edit_", dir=BACKUP_DIR)
    temp_path = os.path.join(temp_dir, filename)

    try:
        await bot.download(message.document, destination=temp_path)
        with open(temp_path, "r", encoding="utf-8-sig") as f:
            save_steam_mafile_to_account(aid, filename, f.read())

        if cursor.rowcount == 0:
            conn.rollback()
            await state.clear()
            return await message.answer("Аккаунт не найден или уже удалён.", reply_markup=main_menu)
        conn.commit()
    except Exception as e:
        conn.rollback()
        logging.error(f"mafile edit import error: {e}")
        return await message.answer(
            f"Не удалось обработать maFile: {e}",
            reply_markup=cancel_kb
        )
    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass

    row = get_account_by_id(aid)
    if not row:
        await state.clear()
        return await message.answer("Данные сохранены, но аккаунт не найден для повторного открытия.", reply_markup=main_menu)

    await state.update_data(selected_login=row[0])
    await state.set_state(AccountDetails.view_action)
    await message.answer("maFile успешно загружен через редактирование аккаунта.", reply_markup=detail_actions_kb())
    await message.answer(await build_account_details_text(row), reply_markup=detail_actions_kb())


@dp.message(StateFilter(DeleteAccount.confirm))
async def delete_account_confirm(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()
    data = await state.get_data()
    aid = data.get("selected_id")

    if txt == "отмена":
        await state.set_state(AccountDetails.view_action)
        row = get_account_by_id(aid) if aid else None
        if not row:
            await state.clear()
            return await message.answer("Аккаунт не найден.", reply_markup=main_menu)
        return await message.answer(await build_account_details_text(row), reply_markup=detail_actions_kb())

    if txt != "подтвердить удаление":
        return await message.answer("Нажмите «Подтвердить удаление» или «Отмена».", reply_markup=delete_confirm_kb())

    if not aid:
        await state.clear()
        return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

    row = get_account_by_id(aid)
    if not row:
        await state.clear()
        return await message.answer("Аккаунт уже удалён или не найден.", reply_markup=main_menu)

    st = row[7]
    login = row[0]

    if st == "busy":
        await state.set_state(AccountDetails.view_action)
        return await message.answer(
            "Нельзя удалить аккаунт, пока он занят. Сначала освободите его.",
            reply_markup=detail_actions_kb()
        )

    try:
        cursor.execute("DELETE FROM accounts WHERE id = ?", (aid,))
        if cursor.rowcount == 0:
            conn.rollback()
            await state.clear()
            return await message.answer("Аккаунт уже удалён или не найден.", reply_markup=main_menu)
        conn.commit()
    except Exception as e:
        conn.rollback()
        logging.error(f"delete_account error: {e}")
        await state.clear()
        return await message.answer("Ошибка удаления аккаунта.", reply_markup=main_menu)

    await state.clear()
    await message.answer(f"Аккаунт {login} удалён.", reply_markup=main_menu)


@dp.message(F.text == "💾 Данные")
async def data_menu(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS: return
    await state.clear()
    await state.set_state(DataBackup.choose_action)
    await message.answer("Раздел данных: резервная копия или восстановление?", reply_markup=data_menu_kb())


@dp.message(StateFilter(DataBackup.choose_action))
async def data_choose_action(message: types.Message, state: FSMContext):
    global DB_MAINTENANCE
    txt = (message.text or "").strip().lower()

    if txt == "назад":
        await state.clear()
        return await message.answer("Возврат в меню.", reply_markup=main_menu)

    if txt == "создать копию":
        backup_path = create_backup_filename()
        try:
            DB_MAINTENANCE = True
            await asyncio.to_thread(write_database_backup, backup_path)
        except Exception as e:
            logging.error(f"backup create error: {e}")
            return await message.answer("Не удалось создать резервную копию.", reply_markup=data_menu_kb())
        finally:
            DB_MAINTENANCE = False

        await message.answer(
            "Резервная копия создана. Отправляю файл.",
            reply_markup=data_menu_kb()
        )
        await message.answer_document(
            document=FSInputFile(backup_path),
            caption="Резервная копия базы данных"
        )
        return

    if txt == "загрузить копию":
        await state.set_state(DataBackup.restore_wait_file)
        return await message.answer(
            "Пришлите сюда файл `.db` резервной копии.",
            reply_markup=cancel_kb
        )

    if txt == "faceit api":
        current_key = resolve_faceit_api_key()
        status_text = "установлен" if current_key else "не установлен"
        await state.set_state(DataBackup.faceit_api_menu)
        return await message.answer(
            f"FACEIT API ключ: {status_text}.",
            reply_markup=faceit_api_kb()
        )

    if txt == "steam api":
        current_key = resolve_steam_api_key()
        status_text = "установлен" if current_key else "не установлен"
        await state.set_state(DataBackup.steam_api_menu)
        return await message.answer(
            f"STEAM API ключ: {status_text}.",
            reply_markup=steam_api_kb()
        )

    if txt == "funpay":
        golden_key = resolve_funpay_golden_key()
        status_text = "установлен" if golden_key else "не установлен"
        await state.update_data(funpay_return_state="data")
        await state.set_state(DataBackup.funpay_menu)
        return await message.answer(
            f"FunPay Golden Key: {status_text}.",
            reply_markup=funpay_api_kb()
        )

    return await message.answer("Выберите действие из меню.", reply_markup=data_menu_kb())


@dp.message(StateFilter(DataBackup.restore_wait_file))
async def data_restore_file(message: types.Message, state: FSMContext):
    global DB_MAINTENANCE
    if not message.document:
        return await message.answer("Нужно отправить файл `.db` документом.", reply_markup=cancel_kb)

    filename = message.document.file_name or "backup.db"
    if not filename.lower().endswith(".db"):
        return await message.answer("Нужен файл с расширением `.db`.", reply_markup=cancel_kb)

    temp_dir = tempfile.mkdtemp(prefix="faceit_restore_", dir=BACKUP_DIR)
    temp_path = os.path.join(temp_dir, filename)

    try:
        await bot.download(message.document, destination=temp_path)
        validate_backup_file(temp_path)

        DB_MAINTENANCE = True
        await asyncio.to_thread(restore_database_from_file, temp_path)
        await state.clear()
        await message.answer("База данных восстановлена из копии.", reply_markup=main_menu)
    except Exception as e:
        logging.error(f"restore error: {e}")
        await message.answer("Не удалось восстановить базу из этого файла.", reply_markup=cancel_kb)
    finally:
        DB_MAINTENANCE = False
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass


@dp.message(StateFilter(DataBackup.faceit_api_menu))
async def faceit_api_menu(message: types.Message, state: FSMContext):
    global FACEIT_API_KEY
    txt = (message.text or "").strip().lower()

    if txt == "назад":
        await state.clear()
        return await message.answer("Возврат в меню.", reply_markup=main_menu)

    if txt == "ввести/обновить ключ":
        await state.set_state(DataBackup.faceit_api_wait_key)
        return await message.answer(
            "Отправьте новый FACEIT API ключ одним сообщением.",
            reply_markup=cancel_kb
        )

    if txt == "удалить ключ":
        set_faceit_api_key(None)
        FACEIT_API_KEY = resolve_faceit_api_key()
        await state.clear()
        return await message.answer("FACEIT API ключ удалён из базы.", reply_markup=main_menu)

    current_key = resolve_faceit_api_key()
    status_text = "установлен" if current_key else "не установлен"
    return await message.answer(
        f"FACEIT API ключ: {status_text}.",
        reply_markup=faceit_api_kb()
    )


@dp.message(StateFilter(DataBackup.faceit_api_wait_key))
async def faceit_api_wait_key(message: types.Message, state: FSMContext):
    global FACEIT_API_KEY
    key = (message.text or "").strip()

    if key.lower() == "отмена":
        await state.set_state(DataBackup.faceit_api_menu)
        return await message.answer("Ввод ключа отменён.", reply_markup=faceit_api_kb())

    if not key:
        return await message.answer("Ключ не может быть пустым.", reply_markup=cancel_kb)

    set_faceit_api_key(key)
    FACEIT_API_KEY = resolve_faceit_api_key()
    await state.set_state(DataBackup.faceit_api_menu)
    await message.answer("FACEIT API ключ сохранён и активирован.", reply_markup=faceit_api_kb())


@dp.message(StateFilter(DataBackup.steam_api_menu))
async def steam_api_menu(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()

    if txt == "назад":
        await state.clear()
        return await message.answer("Возврат в меню.", reply_markup=main_menu)

    if txt == "ввести/обновить ключ":
        await state.set_state(DataBackup.steam_api_wait_key)
        return await message.answer(
            "Отправьте новый STEAM API ключ одним сообщением.",
            reply_markup=cancel_kb
        )

    if txt == "удалить ключ":
        set_steam_api_key(None)
        await state.clear()
        return await message.answer("STEAM API ключ удалён из базы.", reply_markup=main_menu)

    current_key = resolve_steam_api_key()
    status_text = "установлен" if current_key else "не установлен"
    return await message.answer(
        f"STEAM API ключ: {status_text}.",
        reply_markup=steam_api_kb()
    )


@dp.message(StateFilter(DataBackup.steam_api_wait_key))
async def steam_api_wait_key(message: types.Message, state: FSMContext):
    key = (message.text or "").strip()

    if key.lower() == "отмена":
        await state.set_state(DataBackup.steam_api_menu)
        return await message.answer("Ввод ключа отменён.", reply_markup=steam_api_kb())

    if not key:
        return await message.answer("Ключ не может быть пустым.", reply_markup=cancel_kb)

    set_steam_api_key(key)
    sync_error = None
    try:
        await sync_steam_presence()
    except Exception as e:
        sync_error = str(e)
    await state.set_state(DataBackup.steam_api_menu)
    text = "STEAM API ключ сохранён и активирован."
    if sync_error:
        text += f"\nПервичное обновление Steam-статусов не удалось: {sync_error}"
    else:
        text += "\nSteam-статусы обновлены."
    await message.answer(text, reply_markup=steam_api_kb())


@dp.message(StateFilter(DataBackup.funpay_menu))
async def funpay_data_menu(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()

    if txt == "назад":
        await state.clear()
        return await message.answer("Возврат в меню.", reply_markup=main_menu)

    if txt == "ввести golden key" or txt == "изменить golden key":
        await state.update_data(funpay_return_state="data")
        await state.set_state(DataBackup.funpay_wait_key)
        return await message.answer(
            "Отправьте FunPay Golden Key одним сообщением.",
            reply_markup=cancel_kb
        )

    if txt == "ввести user-agent" or txt == "изменить user-agent":
        await state.update_data(funpay_return_state="data")
        await state.set_state(DataBackup.funpay_wait_user_agent)
        return await message.answer(
            "Отправьте FunPay User-Agent одним сообщением.",
            reply_markup=cancel_kb
        )

    return await message.answer("Выберите действие из меню FunPay.", reply_markup=funpay_api_kb())


@dp.message(StateFilter(DataBackup.funpay_wait_key))
async def funpay_wait_key(message: types.Message, state: FSMContext):
    key = (message.text or "").strip()
    data = await state.get_data()
    return_state = data.get("funpay_return_state") or "funpay"

    if key.lower() == "отмена":
        if return_state == "data":
            await state.set_state(DataBackup.funpay_menu)
            return await message.answer("Ввод ключа отменён.", reply_markup=funpay_api_kb())
        await state.set_state(FunPayMenu.menu)
        return await message.answer("Ввод ключа отменён.", reply_markup=funpay_settings_kb())

    if not key:
        return await message.answer("Ключ не может быть пустым.", reply_markup=cancel_kb)

    set_funpay_golden_key(key)
    if return_state == "data":
        await state.set_state(DataBackup.funpay_menu)
        await message.answer("FunPay Golden Key сохранён.", reply_markup=funpay_api_kb())
    else:
        await state.set_state(FunPayMenu.menu)
        await message.answer("FunPay Golden Key сохранён.", reply_markup=funpay_settings_kb())


@dp.message(StateFilter(DataBackup.funpay_wait_user_agent))
async def funpay_wait_user_agent(message: types.Message, state: FSMContext):
    value = (message.text or "").strip()
    data = await state.get_data()
    return_state = data.get("funpay_return_state") or "funpay"

    if value.lower() == "отмена":
        if return_state == "data":
            await state.set_state(DataBackup.funpay_menu)
            return await message.answer("Ввод User-Agent отменён.", reply_markup=funpay_api_kb())
        await state.set_state(FunPayMenu.menu)
        return await message.answer("Ввод User-Agent отменён.", reply_markup=funpay_settings_kb())

    if not value:
        return await message.answer("User-Agent не может быть пустым.", reply_markup=cancel_kb)

    set_funpay_user_agent(value)
    if return_state == "data":
        await state.set_state(DataBackup.funpay_menu)
        await message.answer("FunPay User-Agent сохранён.", reply_markup=funpay_api_kb())
    else:
        await state.set_state(FunPayMenu.menu)
        await message.answer("FunPay User-Agent сохранён.", reply_markup=funpay_settings_kb())


@dp.message(StateFilter(EditAccount.choose_field))
async def edit_choose_field(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()
    if txt == "назад":
        data = await state.get_data()
        aid = data.get("selected_id")
        if not aid:
            await state.clear()
            return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

        row = get_account_by_id(aid)
        if not row:
            await state.clear()
            return await message.answer("Ошибка: аккаунт не найден в базе.", reply_markup=main_menu)

        await state.set_state(AccountDetails.view_action)
        return await message.answer(await build_account_details_text(row), reply_markup=detail_actions_kb())

    field_map = {
        "steam логин": ("steam_login", "Steam логин", False),
        "steam пароль": ("steam_password", "Steam пароль", False),
        "steamid64": ("steam_steamid64", "SteamID64", True),
        "заметка": ("account_note", "Заметка", True),
        "email": ("email", "Email", True),
        "пароль email": ("email_password", "Пароль email", True),
        "faceit ссылка": ("faceit_url", "Faceit ссылка", True),
        "faceit email": ("faceit_email", "Faceit email", True),
        "пароль faceit": ("faceit_password", "Пароль Faceit", True),
        "faceit 2fa secret": ("faceit_2fa_secret", "Faceit 2FA secret", True),
        "steam shared secret": ("steam_shared_secret", "Steam shared secret", True),
        "steam identity secret": ("steam_identity_secret", "Steam identity secret", True),
    }

    if txt == "загрузить mafile":
        await state.set_state(EditAccount.wait_mafile)
        return await message.answer(
            "Отправьте maFile документом в формате JSON. Бот сам извлечёт Steam Guard и трейд-данные.",
            reply_markup=cancel_kb
        )

    field = field_map.get(txt)
    if field is None:
        return await message.answer("Выберите поле из списка.", reply_markup=edit_fields_kb())

    field_name, label, can_clear = field
    await state.update_data(edit_field=field_name, edit_label=label, edit_can_clear=can_clear)
    await state.set_state(EditAccount.enter_value)
    await message.answer(
        f"Введите новое значение для «{label}».\n"
        + ("Для очистки можно отправить «-»." if can_clear else ""),
        reply_markup=cancel_kb
    )


@dp.message(StateFilter(EditAccount.enter_value))
async def edit_enter_value(message: types.Message, state: FSMContext):
    data = await state.get_data()
    aid = data.get("selected_id")
    field = data.get("edit_field")
    label = data.get("edit_label", "поле")
    can_clear = bool(data.get("edit_can_clear"))
    value = (message.text or "").strip()

    if not aid or not field:
        await state.clear()
        return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

    if value.lower() == "отмена":
        await state.clear()
        return await message.answer("Редактирование отменено.", reply_markup=main_menu)

    if can_clear and value in {"-", "нет", "пусто", "none"}:
        new_value = None
    else:
        if not value:
            return await message.answer("Значение не может быть пустым.", reply_markup=cancel_kb)
        new_value = value

    if new_value is not None and field in {"steam_shared_secret", "steam_identity_secret"}:
        normalized_secret = normalize_steam_secret(new_value)
        if not normalized_secret:
            return await message.answer("Не удалось распознать secret. Проверьте формат значения.", reply_markup=cancel_kb)
        new_value = normalized_secret
    elif field == "account_note" and new_value is not None:
        new_value = new_value.strip()

    if field == "steam_login":
        cursor.execute("SELECT 1 FROM accounts WHERE steam_login = ? AND id <> ?", (new_value, aid))
        if cursor.fetchone():
            return await message.answer("Такой Steam логин уже существует.", reply_markup=cancel_kb)

    if new_value is not None and field == "steam_steamid64":
        if not str(new_value).isdigit():
            return await message.answer("SteamID64 должен состоять только из цифр.", reply_markup=cancel_kb)

    stored_value = encrypt(new_value) if field in {"steam_password", "email_password", "faceit_password", "faceit_2fa_secret", "steam_shared_secret", "steam_identity_secret"} and new_value is not None else new_value

    try:
        cursor.execute(f"UPDATE accounts SET {field} = ? WHERE id = ?", (stored_value, aid))
        if cursor.rowcount == 0:
            conn.rollback()
            await state.clear()
            return await message.answer("Аккаунт не найден или уже удалён.", reply_markup=main_menu)
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        return await message.answer("Не удалось сохранить изменения: проверьте уникальность логина.", reply_markup=cancel_kb)
    except Exception as e:
        conn.rollback()
        logging.error(f"edit error: {e}")
        return await message.answer("Ошибка сохранения изменений.", reply_markup=cancel_kb)

    if field == "steam_steamid64" and resolve_steam_api_key():
        try:
            await sync_steam_presence()
        except Exception as e:
            logging.error(f"steam presence refresh after steamid edit: {e}")

    row = get_account_by_id(aid)
    if not row:
        await state.clear()
        return await message.answer("Аккаунт обновлён, но не найден для повторного просмотра.", reply_markup=main_menu)

    await state.update_data(selected_login=row[0])
    await state.set_state(AccountDetails.view_action)
    await message.answer(f"Поле «{label}» обновлено.", reply_markup=detail_actions_kb())
    await message.answer(await build_account_details_text(row), reply_markup=detail_actions_kb())

@dp.message(F.text == "📊 Статус")
async def show_status(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS: return
    clean_invalid_dates()
    clean_expired_faceit_blocks()
    clean_expired_steam_blocks()

    cursor.execute(
        """
        SELECT COUNT(*)
          FROM accounts
         WHERE status='free'
           AND NOT (COALESCE(steam_blocked, 0) = 1 AND COALESCE(faceit_blocked, 0) = 1)
        """
    )
    rentable_accounts = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM accounts WHERE status='busy'")
    busy = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM accounts WHERE COALESCE(faceit_blocked, 0) = 1")
    blocked_faceit = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM accounts WHERE COALESCE(steam_blocked, 0) = 1")
    blocked_steam = cursor.fetchone()[0]

    await state.set_state(StatusMenu.menu)
    await message.answer(
        f"Свободных к сдаче: {rentable_accounts}\n"
        f"Занятых: {busy}\n"
        f"Блокировок Faceit: {blocked_faceit}\n"
        f"Блокировок Steam: {blocked_steam}",
        reply_markup=status_menu_kb()
    )


@dp.message(StateFilter(StatusMenu.menu))
async def status_menu_actions(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()

    if txt == "назад":
        await state.clear()
        return await message.answer("Возврат в меню.", reply_markup=main_menu)

    if txt == "статистика аренд":
        clean_invalid_dates()
        text = get_rent_statistics_text()
        return await message.answer(text, reply_markup=status_menu_kb())

    if txt == "проверка блокировок faceit":
        clean_expired_faceit_blocks()
        clean_expired_steam_blocks()
        result = await sync_faceit_bans(send_notifications=True)

        blocked_accounts = result.get("active_blocks", [])
        errors = result.get("errors", [])
        if not blocked_accounts:
            if errors:
                return await message.answer(
                    "⚠️ Проверка блокировок Faceit не завершилась полностью:\n"
                    + "\n".join(errors[:10]),
                    reply_markup=status_menu_kb()
                )
            return await message.answer(
                "✅ Все аккаунты без активных блокировок Faceit.",
                reply_markup=status_menu_kb()
            )

        lines = [
            f"🔒 Найдено блокировок Faceit: {len(blocked_accounts)}",
            ""
        ]
        for block in blocked_accounts:
            ends_at = block.get("ends_at")
            ends_text = ends_at.astimezone().strftime("%d.%m.%Y %H:%M") if ends_at and ends_at.tzinfo else (ends_at.strftime("%d.%m.%Y %H:%M") if ends_at else "неизвестно")
            lines.extend([
                f"Аккаунт: {block.get('login')}",
                f"Ник: {block.get('nickname')}",
                f"Тип: {block.get('type')}",
                f"Причина: {block.get('reason')}",
                f"Срок блокировки: {format_remaining_time(ends_at)}",
                f"До окончания: {ends_text}",
                "",
            ])

        if errors:
            lines.extend([
                "⚠️ Не удалось проверить часть аккаунтов:",
                *errors[:10],
            ])

        return await message.answer("\n".join(lines).rstrip(), reply_markup=status_menu_kb())

    return await message.answer("Выберите действие из меню статуса.", reply_markup=status_menu_kb())


# ────────────────────────────────────────────────
#  FunPay
# ────────────────────────────────────────────────


def funpay_status_text() -> str:
    golden_key = resolve_funpay_golden_key()
    user_agent = resolve_funpay_user_agent()
    auto_enabled = get_funpay_auto_raise_enabled()
    auto_raise = "включён" if auto_enabled else "выключен"
    next_raise = get_funpay_next_auto_raise_in() if auto_enabled and golden_key else "не запланирован"
    return (
        f"FunPayAPI: {'установлена' if FunPayAccount else 'не установлена'}\n"
        f"FunPay Golden Key: {'установлен' if golden_key else 'не установлен'}\n"
        f"FunPay User-Agent: {'установлен' if user_agent else 'не установлен'}\n"
        f"FunPay слушатель чата: {'активен' if FUNPAY_LISTENER_THREAD_STARTED else 'не активен'}\n"
        f"Автоподъём лотов: {auto_raise}\n"
        f"Следующий автоподъём: {next_raise}"
    )


@dp.message(F.text == "🎯 FunPay")
async def funpay_root(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS:
        return

    await state.clear()
    await state.set_state(FunPayMenu.menu)
    await message.answer(funpay_status_text(), reply_markup=funpay_settings_kb())


@dp.message(StateFilter(FunPayMenu.menu))
async def funpay_menu_actions(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()

    if txt == "назад":
        await state.clear()
        return await message.answer("Возврат в меню.", reply_markup=main_menu)

    if txt in {"баланс funpay", "баланс"}:
        result = await funpay_get_balance()
        if result.get("error"):
            return await message.answer(
                f"Не удалось получить баланс FunPay: {result['error']}",
                reply_markup=funpay_settings_kb()
            )

        balance = result["balance"]
        username = result.get("username") or "-"
        text = (
            f"FunPay аккаунт: {username}\n"
            f"RUB: всего {balance.total_rub:.2f}, доступно {balance.available_rub:.2f}\n"
            f"USD: всего {balance.total_usd:.2f}, доступно {balance.available_usd:.2f}\n"
            f"EUR: всего {balance.total_eur:.2f}, доступно {balance.available_eur:.2f}"
        )
        if result.get("fallback_used"):
            text += f"\nБаланс получен через fallback lot_id={result.get('fallback_lot_id')}"
        return await message.answer(text, reply_markup=funpay_settings_kb())

    if txt.startswith("автоподъём") or txt.startswith("автоподъем"):
        new_value = funpay_toggle_auto_raise()
        status = "включён" if new_value else "выключен"
        extra = ""
        if new_value:
            extra = f"\nСледующий автоподъём через: {get_funpay_next_auto_raise_in()}"
        return await message.answer(
            f"Автоподъём лотов {status}.{extra}",
            reply_markup=funpay_settings_kb()
        )

    if txt in {"изменить golden key", "ввести golden key"}:
        await state.update_data(funpay_return_state="funpay")
        await state.set_state(DataBackup.funpay_wait_key)
        return await message.answer(
            "Отправьте FunPay Golden Key одним сообщением.",
            reply_markup=cancel_kb
        )

    if txt in {"изменить user-agent", "ввести user-agent"}:
        await state.update_data(funpay_return_state="funpay")
        await state.set_state(DataBackup.funpay_wait_user_agent)
        return await message.answer(
            "Отправьте FunPay User-Agent одним сообщением.",
            reply_markup=cancel_kb
        )

    return await message.answer(funpay_status_text(), reply_markup=funpay_settings_kb())

# ────────────────────────────────────────────────
#  Сдача в аренду
# ────────────────────────────────────────────────

@dp.message(F.text == "🎮 Сдать")
async def rent_start(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS: return
    clean_invalid_dates()
    clean_expired_faceit_blocks()
    clean_expired_steam_blocks()

    rows = get_rentable_accounts()
    if not rows:
        return await message.answer("Нет доступных аккаунтов для сдачи.", reply_markup=main_menu)

    rows_data = []
    lines = []
    keyboard_rows = []

    for aid, login, faceit_url, faceit_email, faceit_password, faceit_blocked, steam_blocked in rows:
        package = determine_rent_package(
            faceit_url,
            faceit_email,
            faceit_password,
            bool(faceit_blocked),
            bool(steam_blocked),
        )
        if package is None:
            continue
        rows_data.append({
            "id": aid,
            "login": login,
            "faceit_url": faceit_url,
            "faceit_email": faceit_email,
            "faceit_password": faceit_password,
            "faceit_blocked": faceit_blocked,
            "steam_blocked": steam_blocked,
            "rent_package": package,
        })
        lines.append(f"• {login} — {rent_package_label(package)}")
        keyboard_rows.append([KeyboardButton(text=login)])

    kb = ReplyKeyboardMarkup(
        keyboard=keyboard_rows + [[KeyboardButton(text="Отмена")]],
        resize_keyboard=True
    )
    await state.set_state(RentAccount.select_account)
    await state.update_data(accounts=rows_data)
    await message.answer(
        "\n".join(lines) + "\n\nВыберите аккаунт:",
        reply_markup=kb
    )

@dp.message(StateFilter(RentAccount.select_account))
async def rent_select_account(message: types.Message, state: FSMContext):
    login = (message.text or "").strip()
    if login.lower() in {"отмена", "назад"}:
        await state.clear()
        return await message.answer("Сдача отменена.", reply_markup=main_menu)

    data = await state.get_data()
    acc = next((r for r in data.get("accounts", []) if r.get("login") == login), None)

    if acc is None:
        return await message.answer("Аккаунт не найден в списке доступных", reply_markup=main_menu)

    await state.update_data(selected_id=acc["id"], selected_login=login, rent_package=acc.get("rent_package", "steam"))

    await state.set_state(RentAccount.select_time)
    await message.answer("На сколько времени?", reply_markup=rent_time_kb())

@dp.message(StateFilter(RentAccount.select_time))
async def rent_confirm_time(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()
    if txt == "отмена":
        await state.clear()
        return await message.answer("Сдача отменена.", reply_markup=main_menu)

    delta = parse_extend_delta(txt)
    if delta is None:
        return await message.answer("Выберите время из списка", reply_markup=rent_time_kb())

    data = await state.get_data()
    aid = data["selected_id"]
    login = data["selected_login"]
    rent_package = data.get("rent_package", "steam")

    start_at = datetime.now()
    end = start_at + delta

    await state.update_data(
        selected_id=aid,
        selected_login=login,
        rent_package=rent_package,
        rent_started_at=start_at.isoformat(),
        rent_end=end.isoformat(),
    )
    await state.set_state(RentAccount.enter_order)
    return await message.answer(
        "Введите номер заказа FunPay или ссылку вида https://funpay.com/orders/YAT27MC9/\n"
        "Если заказа нет, нажмите «Пропустить».",
        reply_markup=skip_or_cancel_kb
    )


@dp.message(StateFilter(RentAccount.enter_order))
async def rent_enter_order(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip()
    if txt.lower() == "отмена":
        await state.clear()
        return await message.answer("Сдача отменена.", reply_markup=main_menu)
    if txt.lower() == "пропустить":
        txt = "-"

    data = await state.get_data()
    aid = data.get("selected_id")
    login = data.get("selected_login")
    rent_package = data.get("rent_package", "steam")
    start_at_raw = data.get("rent_started_at")
    end_raw = data.get("rent_end")

    if not aid or not login or not start_at_raw or not end_raw:
        await state.clear()
        return await message.answer("Не удалось восстановить данные сдачи.", reply_markup=main_menu)

    try:
        start_at = datetime.fromisoformat(start_at_raw)
        end = datetime.fromisoformat(end_raw)
    except Exception:
        await state.clear()
        return await message.answer("Некорректные даты сдачи.", reply_markup=main_menu)

    order_id, order_url = parse_funpay_order_ref(txt)
    if txt and txt.lower() not in {"-", "нет", "пусто", "none", "пропустить"} and not order_id:
        return await message.answer(
            "Не удалось распознать номер заказа. Отправьте ссылку формата https://funpay.com/orders/YAT27MC9/ или сам номер заказа.",
            reply_markup=cancel_kb
        )

    try:
        cursor.execute(
            "UPDATE accounts SET status='busy', rent_end=?, rent_reminder_5m_sent_at=NULL, rent_overdue_notified_at=NULL WHERE id=? AND status='free'",
            (end.isoformat(), aid)
        )
        if cursor.rowcount == 0:
            conn.rollback()
            await state.clear()
            return await message.answer("Аккаунт уже занят или удалён", reply_markup=main_menu)

        clear_funpay_order_context(aid)
        if order_id:
            set_funpay_order_context(aid, order_id, order_url)

        add_rent_history_entry(aid, login, rent_package, start_at, end)
        conn.commit()
    except Exception as e:
        conn.rollback()
        logging.error(f"rent error: {e}")
        await state.clear()
        return await message.answer("Ошибка при сдаче", reply_markup=main_menu)

    await message.answer(
        f"Аккаунт **{login}** сдан до {end.strftime('%d.%m %H:%M')}",
        reply_markup=main_menu
    )

    cursor.execute(
        """
        SELECT steam_login, steam_password, faceit_url, faceit_email, faceit_password, COALESCE(faceit_blocked, 0)
          FROM accounts
         WHERE id = ?
        """,
        (aid,)
    )
    row = cursor.fetchone()
    if row:
        s_login, s_pw_enc, f_url, f_email, f_pw_enc, faceit_blocked = row
        s_pw = decrypt(s_pw_enc)
        buyer_text_lines = [
            "Данные для покупателя:",
            f"Steam логин: {s_login}",
            f"Steam пароль: {s_pw}",
        ]
        buyer_copy_lines = [
            f"Steam логин: {s_login}",
            f"Steam пароль: {s_pw}",
        ]
        order_info = {"is_faceit": False}
        if order_id:
            try:
                order_info = await asyncio.to_thread(_funpay_find_order_record_sync, order_id)
            except Exception as e:
                logging.error(f"funpay order lookup error: {e}")
        order_found = bool(
            order_info.get("buyer_username")
            or order_info.get("description")
            or order_info.get("status")
            or order_info.get("price")
        )
        is_faceit_order = bool(order_info.get("is_faceit")) if order_found else (rent_package == "steam_faceit")
        if is_faceit_order and not bool(faceit_blocked) and (f_url or f_email or f_pw_enc):
            faceit_email = f_email or "-"
            faceit_password = decrypt(f_pw_enc) if f_pw_enc else "-"
            buyer_text_lines.extend([
                "",
                f"Faceit email: {faceit_email}",
                f"Faceit пароль: {faceit_password}",
            ])
            buyer_copy_lines.extend([
                f"Faceit email: {faceit_email}",
                f"Faceit пароль: {faceit_password}",
            ])

        if order_id:
            buyer_text_lines.extend([
                "",
                f"FunPay заказ: {order_id}",
                f"Ссылка: {order_url or 'неизвестно'}",
            ])

        await message.answer(
            "\n".join(buyer_text_lines),
            reply_markup=copy_buffer_kb("\n".join(buyer_copy_lines), "Скопировать в буфер")
        )

        if order_id:
            account_snapshot = get_account_by_id(aid)
            fallback_chat_id = account_snapshot[45] if account_snapshot and len(account_snapshot) > 45 else None
            fallback_buyer_username = account_snapshot[44] if account_snapshot and len(account_snapshot) > 44 else None
            faceit_email = f_email or None
            faceit_password = decrypt(f_pw_enc) if f_pw_enc else None
            try:
                init_result = await asyncio.to_thread(
                    _funpay_send_initial_order_message_sync,
                    order_id,
                    s_login,
                    s_pw,
                    faceit_email,
                    faceit_password,
                    is_faceit_order and not bool(faceit_blocked),
                    aid,
                    fallback_chat_id,
                    fallback_buyer_username,
                )
                if init_result.get("error"):
                    logging.error(f"funpay initial order message error: {init_result['error']}")
                    await message.answer(
                        f"⚠️ Не удалось отправить стартовые данные в чат заказа FunPay: {init_result['error']}",
                        reply_markup=main_menu
                    )
                else:
                    cursor.execute(
                        """
                        UPDATE accounts
                           SET funpay_order_chat_id = COALESCE(?, funpay_order_chat_id),
                               funpay_order_buyer = COALESCE(?, funpay_order_buyer),
                               funpay_order_status = COALESCE(?, funpay_order_status),
                               funpay_order_price = COALESCE(?, funpay_order_price),
                               funpay_order_last_sync_at = ?
                         WHERE id = ?
                        """,
                        (
                            str(init_result.get("chat_id")) if init_result.get("chat_id") is not None else None,
                            init_result.get("buyer_username"),
                            init_result.get("order_status"),
                            str(init_result.get("order_price")) if init_result.get("order_price") is not None else None,
                            datetime.now(timezone.utc).isoformat(),
                            aid,
                        ),
                    )
                    conn.commit()
            except Exception as e:
                logging.error(f"funpay initial order message send error: {e}")

    await state.clear()

# ────────────────────────────────────────────────
#  Освобождение
# ────────────────────────────────────────────────

@dp.message(F.text == "✅ Освободить")
async def free_start(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS: return
    clean_invalid_dates()

    cursor.execute("SELECT id, steam_login FROM accounts WHERE status='busy' ORDER BY steam_login")
    rows = cursor.fetchall()
    if not rows:
        return await message.answer("Нет занятых аккаунтов", reply_markup=main_menu)

    kb = ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=login)] for _, login in rows] + [[KeyboardButton(text="Отмена")]],
        resize_keyboard=True
    )
    await state.set_state(FreeAccount.select_account)
    await state.update_data(accounts=rows)
    await message.answer("Выберите аккаунт для освобождения:", reply_markup=kb)

@dp.message(StateFilter(FreeAccount.select_account))
async def free_select(message: types.Message, state: FSMContext):
    login = message.text.strip()
    data = await state.get_data()
    aid = next((a for a, l in data.get("accounts", []) if l == login), None)

    if aid is None:
        return await message.answer("Аккаунт не найден в списке занятых", reply_markup=main_menu)

    try:
        cursor.execute("UPDATE accounts SET status='free', rent_end=NULL WHERE id=?", (aid,))
        close_open_rent_history(aid, datetime.now(), "manual_free")
        clear_funpay_order_context(aid)
        conn.commit()
        await message.answer(f"Аккаунт {login} освобождён", reply_markup=main_menu)
    except Exception as e:
        conn.rollback()
        logging.error(f"free error: {e}")
        await message.answer("Ошибка освобождения", reply_markup=main_menu)

    await state.clear()

# ────────────────────────────────────────────────
#  Продление
# ────────────────────────────────────────────────

@dp.message(F.text == "⏱ Продлить")
async def extend_start(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS: return
    clean_invalid_dates()

    cursor.execute("SELECT id, steam_login, rent_end FROM accounts WHERE status='busy' ORDER BY steam_login")
    rows = cursor.fetchall()
    if not rows:
        return await message.answer("Нет занятых аккаунтов", reply_markup=main_menu)

    kb = ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=login)] for _, login, _ in rows] + [[KeyboardButton(text="Отмена")]],
        resize_keyboard=True
    )
    await state.set_state(ExtendAccount.select_account)
    await state.update_data(accounts=rows)
    await message.answer("Выберите аккаунт для продления:", reply_markup=kb)

@dp.message(StateFilter(ExtendAccount.select_account))
async def extend_select(message: types.Message, state: FSMContext):
    login = message.text.strip()
    data = await state.get_data()
    row = next((r for r in data.get("accounts", []) if r[1] == login), None)

    if row is None:
        return await message.answer("Аккаунт не найден в списке занятых", reply_markup=main_menu)

    aid, _, current_end = row
    await state.update_data(selected_id=aid, selected_login=login, current_end=current_end)

    times_kb = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="30 минут"), KeyboardButton(text="+1 час"), KeyboardButton(text="+2 часа")],
            [KeyboardButton(text="+3 часа"), KeyboardButton(text="+6 часов"), KeyboardButton(text="+12 часов")],
            [KeyboardButton(text="+24 часа")],
            [KeyboardButton(text="Отмена")]
        ],
        resize_keyboard=True
    )
    await state.set_state(ExtendAccount.select_time)
    await message.answer("На сколько продлить?", reply_markup=times_kb)

@dp.message(StateFilter(ExtendAccount.select_time))
async def extend_confirm(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()
    if txt == "отмена":
        await state.clear()
        return await message.answer("Продление отменено", reply_markup=main_menu)

    delta = parse_extend_delta(txt)
    if delta is None or delta < timedelta(minutes=30):
        return await message.answer("Выберите время из списка", reply_markup=main_menu)

    data = await state.get_data()
    aid = data["selected_id"]
    login = data["selected_login"]
    cur_end_str = data.get("current_end")

    try:
        cur_end = datetime.fromisoformat(cur_end_str) if cur_end_str else datetime.now()
    except:
        cur_end = datetime.now()

    new_end = cur_end + delta

    try:
        cursor.execute(
            """
            UPDATE accounts
               SET rent_end = ?,
                   rent_reminder_5m_sent_at = NULL,
                   rent_overdue_notified_at = NULL
             WHERE id = ? AND status = 'busy'
            """,
            (new_end.isoformat(), aid)
        )
        if cursor.rowcount == 0:
            conn.rollback()
            await message.answer("Аккаунт уже свободен или удалён", reply_markup=main_menu)
        else:
            update_open_rent_history_planned_end(aid, new_end)
            conn.commit()
            await message.answer(
                f"Аккаунт **{login}** продлён до {new_end.strftime('%d.%m %H:%M')}",
                reply_markup=main_menu
            )
    except Exception as e:
        conn.rollback()
        logging.error(f"extend error: {e}")
        await message.answer("Ошибка продления", reply_markup=main_menu)

    await state.clear()

# ────────────────────────────────────────────────
#  Фоновая проверка окончания аренды
# ────────────────────────────────────────────────

async def checker_loop():
    last_faceit_scan = 0.0
    last_steam_presence_scan = 0.0
    global FUNPAY_AUTO_RAISE_LAST_RUN
    while True:
        try:
            if DB_MAINTENANCE:
                await asyncio.sleep(5)
                continue
            seen_rent_reminder_orders: set[str] = set()
            seen_overdue_orders: set[str] = set()
            clean_invalid_dates()
            clean_expired_faceit_blocks()
            clean_expired_steam_blocks()
            cursor.execute(
                """
                SELECT id,
                       steam_login,
                       rent_end,
                       COALESCE(rent_reminder_5m_sent_at, ''),
                       COALESCE(rent_overdue_notified_at, ''),
                       funpay_order_id,
                       funpay_order_chat_id,
                       funpay_order_buyer,
                       funpay_order_status,
                       steam_presence_state,
                       steam_presence_game
                  FROM accounts
                 WHERE status='busy'
                """
            )
            for row in cursor.fetchall():
                try:
                    end = datetime.fromisoformat(row[2])
                    left = (end - datetime.now()).total_seconds()
                    reminder_sent_at = row[3] if len(row) > 3 else ""
                    overdue_sent_at = row[4] if len(row) > 4 else ""
                    funpay_order_id = row[5] if len(row) > 5 else None
                    funpay_chat_id = row[6] if len(row) > 6 else None
                    funpay_buyer = row[7] if len(row) > 7 else None
                    funpay_order_status = row[8] if len(row) > 8 else None
                    steam_presence_state = row[9] if len(row) > 9 else None
                    steam_presence_game = row[10] if len(row) > 10 else None

                    order_scope_reminder = bool(funpay_order_id and funpay_order_id not in seen_rent_reminder_orders)
                    if 240 < left < 300 and not reminder_sent_at and order_scope_reminder:
                        order_accounts = 1
                        if funpay_order_id:
                            cursor.execute(
                                """
                                SELECT COUNT(*)
                                  FROM accounts
                                 WHERE status = 'busy'
                                   AND funpay_order_id = ?
                                """,
                                (funpay_order_id,),
                            )
                            count_row = cursor.fetchone()
                            order_accounts = int(count_row[0] or 1) if count_row else 1
                        reminder_text = (
                            f"⚠️ {row[1]} — до конца аренды осталось около 5 минут. "
                            "Пожалуйста, продлите аренду, если планируете продолжать."
                        )
                        if funpay_order_id:
                            reminder_text += f"\nFunPay заказ: {funpay_order_id}"
                            if order_accounts > 1:
                                reminder_text += f" ({order_accounts} аккаунта)"
                        for admin_id in ADMIN_IDS:
                            await bot.send_message(admin_id, reminder_text)
                        reminder_stamp = datetime.now(timezone.utc).isoformat()
                        if funpay_order_id:
                            mark_funpay_order_notification_for_busy_accounts(
                                funpay_order_id,
                                "rent_reminder_5m_sent_at",
                                reminder_stamp,
                            )
                            seen_rent_reminder_orders.add(funpay_order_id)
                        else:
                            cursor.execute(
                                "UPDATE accounts SET rent_reminder_5m_sent_at = ? WHERE id = ?",
                                (reminder_stamp, row[0]),
                            )
                        conn.commit()
                        if funpay_chat_id:
                            try:
                                await asyncio.to_thread(
                                    _funpay_send_chat_message_sync,
                                    funpay_chat_id,
                                    "⚠️ До конца аренды осталось около 5 минут. Если планируете продолжать, пожалуйста, продлите аренду."
                                )
                            except Exception as e:
                                logging.error(f"funpay reminder send error: {e}")

                    if left <= 0:
                        presence_label = format_steam_presence_label(steam_presence_state, steam_presence_game)
                        is_in_game = presence_label.startswith("в игре")
                        order_closed = is_funpay_order_closed(funpay_order_status)
                        order_scope_overdue = bool(funpay_order_id and funpay_order_id not in seen_overdue_orders)

                        if not overdue_sent_at and order_scope_overdue:
                            final_order_text = (
                                "✅ Время аренды закончилось. Спасибо за обращение! "
                                "Будем рады видеть вас снова."
                                if order_closed
                                else "⚠️ Время аренды закончилось. Пожалуйста, закройте заказ и оставьте отзыв. "
                                     "Спасибо за сотрудничество!"
                            )

                            if funpay_chat_id:
                                try:
                                    await asyncio.to_thread(
                                        _funpay_send_chat_message_sync,
                                        funpay_chat_id,
                                        final_order_text,
                                    )
                                except Exception as e:
                                    logging.error(f"funpay overdue send error: {e}")
                            overdue_stamp = datetime.now(timezone.utc).isoformat()
                            if funpay_order_id:
                                mark_funpay_order_notification_for_busy_accounts(
                                    funpay_order_id,
                                    "rent_overdue_notified_at",
                                    overdue_stamp,
                                )
                                seen_overdue_orders.add(funpay_order_id)

                        if is_in_game:
                            if not overdue_sent_at and order_scope_overdue:
                                warning_text = (
                                    f"⚠️ Время аренды для {row[1]} закончилось, "
                                    f"но аккаунт всё ещё в игре ({presence_label}). "
                                    "Пожалуйста, продлите аренду или завершите сессию."
                                )
                                if funpay_order_id:
                                    warning_text += f"\nFunPay заказ: {funpay_order_id}"
                                for admin_id in ADMIN_IDS:
                                    await bot.send_message(admin_id, warning_text)
                                if not funpay_order_id:
                                    cursor.execute(
                                        "UPDATE accounts SET rent_overdue_notified_at = ? WHERE id = ?",
                                        (datetime.now(timezone.utc).isoformat(), row[0]),
                                    )
                                conn.commit()
                        else:
                            if not overdue_sent_at:
                                if not funpay_order_id:
                                    cursor.execute(
                                        "UPDATE accounts SET rent_overdue_notified_at = ? WHERE id = ?",
                                        (datetime.now(timezone.utc).isoformat(), row[0]),
                                    )
                                conn.commit()
                            cursor.execute("UPDATE accounts SET status='free', rent_end=NULL WHERE id=?", (row[0],))
                            close_open_rent_history(row[0], datetime.now(), "auto_free")
                            clear_funpay_order_context(row[0])
                            conn.commit()
                            for admin_id in ADMIN_IDS:
                                await bot.send_message(admin_id, f"✅ {row[1]} освобождён автоматически")
                except:
                    pass

            now_ts = asyncio.get_running_loop().time()
            if now_ts - last_faceit_scan >= 300:
                scan_result = await sync_faceit_bans(send_notifications=True)
                for notification in scan_result.get("notifications", []):
                    for admin_id in ADMIN_IDS:
                        await bot.send_message(admin_id, notification)
                last_faceit_scan = now_ts

            if now_ts - last_steam_presence_scan >= 180:
                try:
                    await sync_steam_presence()
                except Exception as e:
                    logging.error(f"steam_presence_sync: {e}")
                last_steam_presence_scan = now_ts

        except Exception as e:
            logging.error(f"checker_loop: {e}")
        await asyncio.sleep(30)

# ────────────────────────────────────────────────
#  FunPay service wiring
# ────────────────────────────────────────────────

_BOT_RESOLVE_FUNPAY_GOLDEN_KEY = resolve_funpay_golden_key
_BOT_RESOLVE_FUNPAY_USER_AGENT = resolve_funpay_user_agent
_BOT_GET_FUNPAY_OP_LOCK = get_funpay_op_lock

from services.funpay_manager import (
    FunPayRuntime,
    configure as configure_funpay_manager,
    run_funpay_worker,
    funpay_get_balance,
    funpay_raise_all_lots,
    funpay_toggle_auto_raise,
    get_funpay_next_auto_raise_in,
    resolve_funpay_golden_key,
    resolve_funpay_user_agent,
    _funpay_build_account_sync,
    _funpay_send_chat_message_sync,
    _funpay_find_order_record_sync,
    _funpay_send_initial_order_message_sync,
    _funpay_send_code_to_order_sync,
    start_funpay_listener,
    funpay_ensure_available,
    get_funpay_op_lock,
)

# ────────────────────────────────────────────────
#  Запуск
# ────────────────────────────────────────────────

async def main():
    global FACEIT_API_KEY, MAIN_LOOP
    ensure_faceit_url_column()
    ensure_rent_history_table()
    ensure_faceit_block_columns()
    ensure_steam_block_columns()
    ensure_faceit_2fa_column()
    ensure_steam_shared_secret_column()
    ensure_steam_trade_columns()
    ensure_steam_presence_columns()
    ensure_account_note_columns()
    ensure_funpay_order_columns()
    migrate_encryption()
    FACEIT_API_KEY = resolve_faceit_api_key()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    log_runtime_config()
    MAIN_LOOP = asyncio.get_running_loop()
    configure_funpay_manager(
        FunPayRuntime(
            conn=conn,
            cursor=cursor,
            resolve_funpay_golden_key=_BOT_RESOLVE_FUNPAY_GOLDEN_KEY,
            resolve_funpay_user_agent=_BOT_RESOLVE_FUNPAY_USER_AGENT,
            get_funpay_op_lock=_BOT_GET_FUNPAY_OP_LOCK,
            decrypt=decrypt,
            generate_steam_guard_code=generate_steam_guard_code,
            generate_totp_code=generate_totp_code,
            set_funpay_order_context=set_funpay_order_context,
            clear_funpay_order_context=clear_funpay_order_context,
            mark_funpay_order_notification_for_busy_accounts=mark_funpay_order_notification_for_busy_accounts,
            normalize_db_text=normalize_db_text,
            is_funpay_order_closed=is_funpay_order_closed,
            get_account_by_funpay_order_id=get_account_by_funpay_order_id,
            get_account_by_id=get_account_by_id,
            add_rent_history_entry=add_rent_history_entry,
            close_open_rent_history=close_open_rent_history,
        )
    )
    asyncio.create_task(checker_loop())
    asyncio.create_task(run_funpay_worker())
    print("Бот запущен")
    await dp.start_polling(bot, allowed_updates=["message"])

if __name__ == "__main__":
    asyncio.run(main())
