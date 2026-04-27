import asyncio
import sqlite3
import logging
import os
import shutil
import tempfile
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, unquote, parse_qs
import base64
import hashlib
import hmac
import struct
import time

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
    from FunPayAPI import enums as FunPayEnums
except Exception:
    FunPayAccount = None
    FunPayEnums = None

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


def get_funpay_auto_raise_enabled() -> bool:
    value = (get_setting_raw("funpay_auto_raise_enabled") or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def set_funpay_auto_raise_enabled(enabled: bool) -> None:
    set_setting_raw("funpay_auto_raise_enabled", "1" if enabled else "0")


def funpay_toggle_auto_raise() -> bool:
    new_value = not get_funpay_auto_raise_enabled()
    set_funpay_auto_raise_enabled(new_value)
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
FUNPAY_AUTO_RAISE_LAST_RUN = 0.0
FUNPAY_AUTO_RAISE_INTERVAL_SECONDS = 3600

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
    cursor.execute("SELECT id, steam_password, email_password, faceit_password, faceit_2fa_secret, steam_shared_secret FROM accounts")
    updated = False
    for row in cursor.fetchall():
        aid, sp, ep, fp, secret, steam_secret = row
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

class ExtendAccount(StatesGroup):
    select_account = State()
    select_time    = State()

class FreeAccount(StatesGroup):
    select_account = State()

class AccountDetails(StatesGroup):
    select_account = State()
    view_action = State()

class EditAccount(StatesGroup):
    choose_field = State()
    enter_value = State()

class DeleteAccount(StatesGroup):
    confirm = State()

class BlockAccount(StatesGroup):
    menu = State()

class DataBackup(StatesGroup):
    choose_action = State()
    restore_wait_file = State()
    faceit_api_menu = State()
    faceit_api_wait_key = State()
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


def clean_expired_faceit_blocks():
    try:
        cursor.execute(
            """
            SELECT id, faceit_block_ends_at
              FROM accounts
             WHERE faceit_blocked = 1
               AND faceit_block_ends_at IS NOT NULL
            """
        )
        expired_ids = []
        for aid, ends_at_raw in cursor.fetchall():
            ends_at = parse_iso_datetime(ends_at_raw)
            if ends_at is None:
                continue
            local_now = datetime.now(ends_at.tzinfo) if ends_at.tzinfo else datetime.now()
            if ends_at <= local_now:
                expired_ids.append(aid)

        for aid in expired_ids:
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
        if expired_ids:
            conn.commit()
    except Exception as e:
        logging.error(f"clean_expired_faceit_blocks error: {e}")


def clean_expired_steam_blocks():
    try:
        cursor.execute(
            """
            SELECT id, steam_block_ends_at
              FROM accounts
             WHERE steam_blocked = 1
               AND steam_block_ends_at IS NOT NULL
            """
        )
        expired_ids = []
        for aid, ends_at_raw in cursor.fetchall():
            ends_at = parse_iso_datetime(ends_at_raw)
            if ends_at is None:
                continue
            local_now = datetime.now(ends_at.tzinfo) if ends_at.tzinfo else datetime.now()
            if ends_at <= local_now:
                expired_ids.append(aid)

        for aid in expired_ids:
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
               steam_shared_secret
          FROM accounts
         WHERE id = ?
        """,
        (aid,),
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


def parse_faceit_ban_end(item: dict) -> datetime | None:
    for key in ("ends_at", "banEnd", "ban_end", "endsAt"):
        dt = parse_iso_datetime(item.get(key))
        if dt is not None:
            return dt
    return None


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


def _funpay_raise_all_lots_sync(golden_key: str, user_agent: str | None = None) -> dict:
    acc = _funpay_build_account_sync(golden_key, user_agent)
    categories = acc.get_sorted_categories() or {}

    raised = []
    errors = []
    for category_id, category in categories.items():
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
        except Exception as e:
            errors.append(f"{getattr(category, 'name', category_id)}: {e}")

    return {
        "username": getattr(acc, "username", None),
        "id": getattr(acc, "id", None),
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
    golden_key = resolve_funpay_golden_key()
    if not golden_key:
        return {"error": "FunPay golden key не задан"}

    user_agent = resolve_funpay_user_agent()
    async with get_funpay_op_lock():
        try:
            return await asyncio.to_thread(_funpay_raise_all_lots_sync, golden_key, user_agent)
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


def determine_rent_package(faceit_url: str | None, faceit_email: str | None, faceit_password: str | None, faceit_blocked: bool) -> str:
    has_faceit = any(
        value and str(value).strip()
        for value in (faceit_url, faceit_email, faceit_password)
    )

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

    details_lines = [
        f"Данные аккаунта: {s_login}",
        f"Статус: {st}",
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
            [KeyboardButton(text="Блокировка Faceit"), KeyboardButton(text="Блокировка Steam")],
            [KeyboardButton(text="История аренд")],
            [KeyboardButton(text="Редактировать"), KeyboardButton(text="Удалить")],
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
            [KeyboardButton(text="FACEIT API")],
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
            [KeyboardButton(text="Steam shared secret")],
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
        SELECT id, steam_login, status, rent_end, faceit_blocked, faceit_block_ends_at, steam_blocked, steam_block_ends_at
          FROM accounts
         ORDER BY steam_login
        """
    )
    rows = cursor.fetchall()

    if not rows:
        return await message.answer("Аккаунтов нет", reply_markup=main_menu)

    lines = []
    rows_data = []
    for aid, login, st, end, faceit_blocked, faceit_block_end, steam_blocked, steam_block_end in rows:
        rows_data.append({
            "id": aid,
            "login": login,
            "status": st,
            "end": end,
            "faceit_blocked": faceit_blocked,
            "faceit_block_end": faceit_block_end,
            "steam_blocked": steam_blocked,
            "steam_block_end": steam_block_end,
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
    faceit_2fa_secret = row[-2] if row and len(row) >= 2 else None
    steam_shared_secret = row[-1] if row else None

    if txt == "назад":
        await state.clear()
        return await render_accounts_list(message, state)

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
        "email": ("email", "Email", True),
        "пароль email": ("email_password", "Пароль email", True),
        "faceit ссылка": ("faceit_url", "Faceit ссылка", True),
        "faceit email": ("faceit_email", "Faceit email", True),
        "пароль faceit": ("faceit_password", "Пароль Faceit", True),
        "faceit 2fa secret": ("faceit_2fa_secret", "Faceit 2FA secret", True),
        "steam shared secret": ("steam_shared_secret", "Steam shared secret", True),
    }
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

    if field == "steam_login":
        cursor.execute("SELECT 1 FROM accounts WHERE steam_login = ? AND id <> ?", (new_value, aid))
        if cursor.fetchone():
            return await message.answer("Такой Steam логин уже существует.", reply_markup=cancel_kb)

    stored_value = encrypt(new_value) if field in {"steam_password", "email_password", "faceit_password", "faceit_2fa_secret", "steam_shared_secret"} and new_value is not None else new_value

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
    auto_raise = "включён" if get_funpay_auto_raise_enabled() else "выключен"
    return (
        f"FunPayAPI: {'установлена' if FunPayAccount else 'не установлена'}\n"
        f"FunPay Golden Key: {'установлен' if golden_key else 'не установлен'}\n"
        f"FunPay User-Agent: {'установлен' if user_agent else 'не установлен'}\n"
        f"Автоподъём лотов: {auto_raise}"
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
        new_value = await funpay_toggle_auto_raise()
        status = "включён" if new_value else "выключен"
        return await message.answer(
            f"Автоподъём лотов {status}.",
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
        package = determine_rent_package(faceit_url, faceit_email, faceit_password, bool(faceit_blocked))
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

    try:
        cursor.execute(
            "UPDATE accounts SET status='busy', rent_end=? WHERE id=? AND status='free'",
            (end.isoformat(), aid)
        )
        if cursor.rowcount == 0:
            conn.rollback()
            await message.answer("Аккаунт уже занят или удалён", reply_markup=main_menu)
        else:
            add_rent_history_entry(aid, login, rent_package, start_at, end)
            conn.commit()
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
                should_send_faceit = rent_package == "steam_faceit" and not bool(faceit_blocked)
                if should_send_faceit and (f_url or f_email or f_pw_enc):
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

                await message.answer(
                    "\n".join(buyer_text_lines),
                    reply_markup=copy_buffer_kb("\n".join(buyer_copy_lines), "Скопировать в буфер")
                )
    except Exception as e:
        conn.rollback()
        logging.error(f"rent error: {e}")
        await message.answer("Ошибка при сдаче", reply_markup=main_menu)

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
            "UPDATE accounts SET rent_end = ? WHERE id = ? AND status = 'busy'",
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
    global FUNPAY_AUTO_RAISE_LAST_RUN
    while True:
        try:
            if DB_MAINTENANCE:
                await asyncio.sleep(5)
                continue
            clean_invalid_dates()
            clean_expired_faceit_blocks()
            clean_expired_steam_blocks()
            cursor.execute("SELECT id, steam_login, rent_end FROM accounts WHERE status='busy'")
            for row in cursor.fetchall():
                try:
                    end = datetime.fromisoformat(row[2])
                    left = (end - datetime.now()).total_seconds()
                    if 240 < left < 300:
                        for admin_id in ADMIN_IDS:
                            await bot.send_message(admin_id, f"⚠️ {row[1]} — ~5 минут до конца")
                    if left <= 0:
                        cursor.execute("UPDATE accounts SET status='free', rent_end=NULL WHERE id=?", (row[0],))
                        close_open_rent_history(row[0], datetime.now(), "auto_free")
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

            if get_funpay_auto_raise_enabled():
                golden_key = resolve_funpay_golden_key()
                if golden_key and now_ts - FUNPAY_AUTO_RAISE_LAST_RUN >= FUNPAY_AUTO_RAISE_INTERVAL_SECONDS:
                    raise_result = await funpay_raise_all_lots()
                    if raise_result.get("error"):
                        logging.error("FunPay auto raise error: %s", raise_result["error"])
                        for admin_id in ADMIN_IDS:
                            await bot.send_message(
                                admin_id,
                                "⚠️ Автоподъем лотов FunPay завершился с ошибкой:\n"
                                f"{raise_result['error']}"
                            )
                    else:
                        next_in = format_interval_seconds(FUNPAY_AUTO_RAISE_INTERVAL_SECONDS)
                        raised_count = len(raise_result.get("raised", []))
                        errors_count = len(raise_result.get("errors", []))
                        logging.info(
                            "FunPay auto raise completed: raised=%d errors=%d",
                            raised_count,
                            errors_count,
                        )
                        for admin_id in ADMIN_IDS:
                            await bot.send_message(
                                admin_id,
                                "✅ Произошел автоподъем лотов FunPay.\n"
                                f"Поднято категорий: {raised_count}\n"
                                f"Ошибок: {errors_count}\n"
                                f"Следующий автоподъем через: {next_in}"
                            )
                    FUNPAY_AUTO_RAISE_LAST_RUN = now_ts
        except Exception as e:
            logging.error(f"checker_loop: {e}")
        await asyncio.sleep(30)

# ────────────────────────────────────────────────
#  Запуск
# ────────────────────────────────────────────────

async def main():
    global FACEIT_API_KEY
    ensure_faceit_url_column()
    ensure_rent_history_table()
    ensure_faceit_block_columns()
    ensure_steam_block_columns()
    ensure_faceit_2fa_column()
    ensure_steam_shared_secret_column()
    migrate_encryption()
    FACEIT_API_KEY = resolve_faceit_api_key()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    log_runtime_config()
    asyncio.create_task(checker_loop())
    print("Бот запущен")
    await dp.start_polling(bot, allowed_updates=["message"])

if __name__ == "__main__":
    asyncio.run(main())
