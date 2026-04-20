import asyncio
import sqlite3
import logging
import os
import shutil
import tempfile
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
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton, FSInputFile
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.context import FSMContext

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

# ────────────────────────────────────────────────
#  База данных
# ────────────────────────────────────────────────

conn = sqlite3.connect("accounts.db", check_same_thread=False)
cursor = conn.cursor()
DB_MAINTENANCE = False

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

def ensure_faceit_url_column():
    cursor.execute("PRAGMA table_info(accounts)")
    columns = {row[1] for row in cursor.fetchall()}
    if "faceit_url" not in columns:
        cursor.execute("ALTER TABLE accounts ADD COLUMN faceit_url TEXT")
        conn.commit()

def migrate_encryption():
    cursor.execute("SELECT id, steam_password, email_password, faceit_password, faceit_2fa_secret FROM accounts")
    updated = False
    for row in cursor.fetchall():
        aid, sp, ep, fp, secret = row
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

class DataBackup(StatesGroup):
    choose_action = State()
    restore_wait_file = State()
    faceit_api_menu = State()
    faceit_api_wait_key = State()


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
        [KeyboardButton(text="⏱ Продлить"),    KeyboardButton(text="✅ Освободить")],
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
                       faceit_block_last_checked_at = NULL
                 WHERE id = ?
                """,
                (aid,),
            )
        if expired_ids:
            conn.commit()
    except Exception as e:
        logging.error(f"clean_expired_faceit_blocks error: {e}")


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
               faceit_2fa_secret
          FROM accounts
         WHERE id = ?
        """,
        (aid,),
    )
    return cursor.fetchone()


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


async def fetch_faceit_active_ban(faceit_url: str | None) -> dict:
    nickname = extract_faceit_nickname(faceit_url)
    if not nickname:
        return {"nickname": None, "player_id": None, "ban": None, "error": None}

    player_id, error = await resolve_faceit_player_id(faceit_url)
    if not player_id:
        return {"nickname": nickname, "player_id": None, "ban": None, "error": error or "Не удалось определить player_id"}

    faceit_api_key = resolve_faceit_api_key()
    if not faceit_api_key:
        return {"nickname": nickname, "player_id": player_id, "ban": None, "error": "FACEIT_API_KEY не задан"}

    url = f"https://open.faceit.com/data/v4/players/{player_id}/bans"
    headers = {"Authorization": f"Bearer {faceit_api_key}"}
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
    cursor.execute(
        """
        SELECT id, steam_login, faceit_url, faceit_blocked, faceit_block_ends_at, faceit_ban_signature
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

    for aid, steam_login, faceit_url, faceit_blocked, faceit_block_ends_at, faceit_ban_signature in rows:
        result = await fetch_faceit_active_ban(faceit_url)
        error = result.get("error")
        ban = result.get("ban")
        now = datetime.now(timezone.utc)

        if error:
            errors.append(f"{steam_login}: {error}")
            continue

        if ban is None:
            if faceit_blocked:
                cursor.execute(
                    """
                    UPDATE accounts
                       SET faceit_blocked = 0,
                           faceit_block_ends_at = NULL,
                           faceit_block_reason = NULL,
                           faceit_block_type = NULL,
                           faceit_block_game = NULL,
                           faceit_ban_signature = NULL,
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


async def build_account_details_text(row) -> str:
    s_login, s_pw_enc, email, e_pw_enc, f_url, f_email, f_pw_enc, st, rent_end, *rest = row
    s_pw = decrypt(s_pw_enc)
    e_pw = decrypt(e_pw_enc)
    f_pw = decrypt(f_pw_enc) if f_pw_enc is not None else None
    faceit_blocked = bool(rest[0]) if len(rest) > 0 and rest[0] is not None else False
    faceit_block_ends_at = rest[1] if len(rest) > 1 else None
    faceit_block_reason = rest[2] if len(rest) > 2 else None
    faceit_block_type = rest[3] if len(rest) > 3 else None
    faceit_2fa_secret = rest[7] if len(rest) > 7 else None

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

    block_dt = parse_iso_datetime(faceit_block_ends_at)
    if faceit_blocked and block_dt:
        details_lines.extend([
            "",
            "Faceit блокировка:",
            "  Статус: активна",
            f"  Тип: {faceit_block_type or '-'}",
            f"  Причина: {faceit_block_reason or '-'}",
            f"  До конца блокировки: {format_remaining_time(block_dt)}",
        ])
    elif faceit_blocked:
        details_lines.extend([
            "",
            "Faceit блокировка:",
            "  Статус: активна",
            f"  Тип: {faceit_block_type or '-'}",
            f"  Причина: {faceit_block_reason or '-'}",
            "  До конца блокировки: неизвестно",
        ])

    if st == "busy" and rent_end and not faceit_blocked:
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
            [KeyboardButton(text="Редактировать"), KeyboardButton(text="2FA код")],
            [KeyboardButton(text="Удалить")],
            [KeyboardButton(text="Назад")],
        ],
        resize_keyboard=True
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


def edit_fields_kb() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="Steam логин"), KeyboardButton(text="Steam пароль")],
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

    await render_accounts_list(message, state)


async def render_accounts_list(message: types.Message, state: FSMContext):
    await state.clear()
    cursor.execute(
        """
        SELECT id, steam_login, status, rent_end, faceit_blocked, faceit_block_ends_at
          FROM accounts
         ORDER BY steam_login
        """
    )
    rows = cursor.fetchall()

    if not rows:
        return await message.answer("Аккаунтов нет", reply_markup=main_menu)

    lines = []
    rows_data = []
    for aid, login, st, end, blocked, block_end in rows:
        rows_data.append({"id": aid, "login": login, "status": st, "end": end, "blocked": blocked, "block_end": block_end})
        if blocked:
            block_dt = parse_iso_datetime(block_end)
            if block_dt:
                lines.append(f"🔒 {login} — {format_remaining_time(block_dt)} до конца блокировки")
            else:
                lines.append(f"🔒 {login} — блокировка Faceit")
        elif st == "free":
            lines.append(f"🟢 {login}")
        else:
            try:
                dt = datetime.fromisoformat(end)
                mins = max(0, int((dt - datetime.now()).total_seconds() / 60))
                lines.append(f"🔴 {login} — {mins} мин")
            except:
                lines.append(f"🟢 {login} (ошибка даты)")

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

    if txt == "назад":
        await state.clear()
        return await render_accounts_list(message, state)

    if txt == "2fa код":
        if not row:
            await state.clear()
            return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

        secret = row[-1]
        if not secret:
            return await message.answer(
                "Для этого аккаунта не сохранён Faceit 2FA secret.\n"
                "Сначала добавьте его в поле «Faceit 2FA secret».",
                reply_markup=detail_actions_kb()
            )

        try:
            code, seconds_left = generate_totp_code(decrypt(secret))
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

        return await message.answer("Нажмите «Редактировать», «Удалить» или «Назад».", reply_markup=detail_actions_kb())

    if not aid:
        await state.clear()
        return await message.answer("Аккаунт не найден.", reply_markup=main_menu)

    await state.set_state(EditAccount.choose_field)
    await message.answer("Что изменить?", reply_markup=edit_fields_kb())


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

    stored_value = encrypt(new_value) if field in {"steam_password", "email_password", "faceit_password", "faceit_2fa_secret"} and new_value is not None else new_value

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

    cursor.execute("SELECT COUNT(*) FROM accounts WHERE status='free' AND COALESCE(faceit_blocked, 0) = 0")
    free = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM accounts WHERE status='busy'")
    busy = cursor.fetchone()[0]
    cursor.execute(
        """
        SELECT COUNT(*)
          FROM accounts
         WHERE status='free'
           AND COALESCE(faceit_blocked, 0) = 0
           AND (
                (faceit_url IS NOT NULL AND faceit_url != '')
                OR (faceit_email IS NOT NULL AND faceit_email != '')
                OR (faceit_password IS NOT NULL AND faceit_password != '')
           )
        """
    )
    free_faceit = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM accounts WHERE COALESCE(faceit_blocked, 0) = 1")
    blocked_faceit = cursor.fetchone()[0]

    await state.set_state(StatusMenu.menu)
    await message.answer(
        f"Свободных: {free}\n"
        f"Занятых: {busy}\n"
        f"Свободных с Faceit: {free_faceit}\n"
        f"Блокировок Faceit: {blocked_faceit}",
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
#  Сдача в аренду
# ────────────────────────────────────────────────

@dp.message(F.text == "🎮 Сдать")
async def rent_start(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS: return
    clean_invalid_dates()
    clean_expired_faceit_blocks()

    cursor.execute(
        """
        SELECT id, steam_login
          FROM accounts
         WHERE status='free'
           AND COALESCE(faceit_blocked, 0) = 0
         ORDER BY steam_login
        """
    )
    rows = cursor.fetchall()
    if not rows:
        return await message.answer("Нет свободных аккаунтов", reply_markup=main_menu)

    kb = ReplyKeyboardMarkup(
        keyboard=[[KeyboardButton(text=login)] for _, login in rows] + [[KeyboardButton(text="Отмена")]],
        resize_keyboard=True
    )
    await state.set_state(RentAccount.select_account)
    await state.update_data(accounts=rows)
    await message.answer("Выберите аккаунт:", reply_markup=kb)

@dp.message(StateFilter(RentAccount.select_account))
async def rent_select_account(message: types.Message, state: FSMContext):
    login = message.text.strip()
    data = await state.get_data()
    acc = next((aid for aid, l in data.get("accounts", []) if l == login), None)

    if acc is None:
        return await message.answer("Аккаунт не найден в списке свободных", reply_markup=main_menu)

    await state.update_data(selected_id=acc, selected_login=login)

    times_kb = ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="30 минут"), KeyboardButton(text="1 час"), KeyboardButton(text="2 часа")],
            [KeyboardButton(text="3 часа"), KeyboardButton(text="6 часов"), KeyboardButton(text="12 часов")],
            [KeyboardButton(text="24 часа")],
            [KeyboardButton(text="Отмена")]
        ],
        resize_keyboard=True
    )
    await state.set_state(RentAccount.select_time)
    await message.answer("На сколько времени?", reply_markup=times_kb)

@dp.message(StateFilter(RentAccount.select_time))
async def rent_confirm_time(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()
    if txt == "отмена":
        await state.clear()
        return await message.answer("Сдача отменена", reply_markup=main_menu)

    delta = parse_extend_delta(txt)
    if delta is None:
        return await message.answer("Выберите время из списка", reply_markup=main_menu)

    data = await state.get_data()
    aid = data["selected_id"]
    login = data["selected_login"]

    end = datetime.now() + delta

    try:
        cursor.execute(
            "UPDATE accounts SET status='busy', rent_end=? WHERE id=? AND status='free'",
            (end.isoformat(), aid)
        )
        if cursor.rowcount == 0:
            conn.rollback()
            await message.answer("Аккаунт уже занят или удалён", reply_markup=main_menu)
        else:
            conn.commit()
            await message.answer(
                f"Аккаунт **{login}** сдан до {end.strftime('%d.%m %H:%M')}",
                reply_markup=main_menu
            )

            cursor.execute(
                """
                SELECT steam_login, steam_password, faceit_email, faceit_password
                  FROM accounts
                 WHERE id = ?
                """,
                (aid,)
            )
            row = cursor.fetchone()
            if row:
                s_login, s_pw_enc, f_email, f_pw_enc = row
                s_pw = decrypt(s_pw_enc)
                faceit_text = ""
                if f_email or f_pw_enc:
                    faceit_text = (
                        f"\nFaceit email: {f_email or '-'}"
                        f"\nFaceit пароль: {decrypt(f_pw_enc) if f_pw_enc else '-'}"
                    )

                await message.answer(
                    "Данные для покупателя:\n"
                    f"Steam логин: {s_login}\n"
                    f"Steam пароль: {s_pw}"
                    f"{faceit_text}"
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
    while True:
        try:
            if DB_MAINTENANCE:
                await asyncio.sleep(5)
                continue
            clean_invalid_dates()
            clean_expired_faceit_blocks()
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
        except Exception as e:
            logging.error(f"checker_loop: {e}")
        await asyncio.sleep(30)

# ────────────────────────────────────────────────
#  Запуск
# ────────────────────────────────────────────────

async def main():
    global FACEIT_API_KEY
    ensure_faceit_url_column()
    ensure_faceit_block_columns()
    ensure_faceit_2fa_column()
    migrate_encryption()
    FACEIT_API_KEY = resolve_faceit_api_key()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    log_runtime_config()
    asyncio.create_task(checker_loop())
    print("Бот запущен")
    await dp.start_polling(bot, allowed_updates=["message"])

if __name__ == "__main__":
    asyncio.run(main())
