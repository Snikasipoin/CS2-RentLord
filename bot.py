import asyncio
import sqlite3
import logging
import os
import shutil
import tempfile
from datetime import datetime, timedelta
from urllib.parse import urlparse, unquote

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
FACEIT_API_KEY_SOURCE = "runtime env" if FACEIT_API_KEY_RUNTIME else ("data env file" if FACEIT_API_KEY else "missing")


def log_runtime_config():
    faceit_key = FACEIT_API_KEY
    data_env_exists = os.path.exists(DATA_ENV_PATH)
    if faceit_key:
        logging.info("FACEIT_API_KEY loaded: yes, length=%d, source=%s", len(faceit_key), FACEIT_API_KEY_SOURCE)
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
    status          TEXT DEFAULT 'free',
    rent_end        TEXT
)
""")
conn.commit()

def ensure_faceit_url_column():
    cursor.execute("PRAGMA table_info(accounts)")
    columns = {row[1] for row in cursor.fetchall()}
    if "faceit_url" not in columns:
        cursor.execute("ALTER TABLE accounts ADD COLUMN faceit_url TEXT")
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


def get_account_by_id(aid: int):
    cursor.execute(
        """
        SELECT steam_login, steam_password, email, email_password, faceit_url, faceit_email, faceit_password, status, rent_end
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
        return {"nickname": None, "elo": None, "level": None, "error": None}

    if not FACEIT_API_KEY:
        return {"nickname": nickname, "elo": None, "level": None, "error": "FACEIT_API_KEY не задан"}

    url = "https://open.faceit.com/data/v4/players"
    headers = {"Authorization": f"Bearer {FACEIT_API_KEY}"}
    timeout = aiohttp.ClientTimeout(total=15)

    async def fetch_for_game(game_name: str) -> tuple[dict | None, str | None]:
        params = {"nickname": nickname, "game": game_name}
        try:
            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                async with session.get(url, params=params) as response:
                    if response.status != 200:
                        return None, f"HTTP {response.status}"
                    data = await response.json()
        except Exception as e:
            return None, str(e)

        games = data.get("games") or {}
        return (games.get("cs2") or games.get("csgo") or {}), None

    game, error = await fetch_for_game("cs2")
    if not game:
        fallback_game, fallback_error = await fetch_for_game("csgo")
        if fallback_game:
            game = fallback_game
            error = None
        else:
            error = fallback_error or error

    game = game or {}
    elo = game.get("faceit_elo")
    level = game.get("skill_level")

    return {
        "nickname": nickname,
        "elo": elo,
        "level": level,
        "error": error,
    }


async def build_account_details_text(row) -> str:
    s_login, s_pw_enc, email, e_pw_enc, f_url, f_email, f_pw_enc, st, rent_end = row
    s_pw = decrypt(s_pw_enc)
    e_pw = decrypt(e_pw_enc)
    f_pw = decrypt(f_pw_enc) if f_pw_enc is not None else None

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

    if f_url or f_email or f_pw_enc:
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
            [KeyboardButton(text="Редактировать"), KeyboardButton(text="Удалить")],
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
            [KeyboardButton(text="Пароль Faceit")],
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

    await render_accounts_list(message, state)


async def render_accounts_list(message: types.Message, state: FSMContext):
    await state.clear()
    cursor.execute("SELECT id, steam_login, status, rent_end FROM accounts ORDER BY steam_login")
    rows = cursor.fetchall()

    if not rows:
        return await message.answer("Аккаунтов нет", reply_markup=main_menu)

    lines = []
    rows_data = []
    for aid, login, st, end in rows:
        rows_data.append({"id": aid, "login": login, "status": st, "end": end})
        if st == "free":
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

    if txt == "назад":
        await state.clear()
        return await render_accounts_list(message, state)

    if txt != "редактировать":
        if txt == "удалить":
            row = get_account_by_id(aid) if aid else None
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

    stored_value = encrypt(new_value) if field in {"steam_password", "email_password", "faceit_password"} and new_value is not None else new_value

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

# ────────────────────────────────────────────────
#  Статус
# ────────────────────────────────────────────────

@dp.message(F.text == "📊 Статус")
async def show_status(message: types.Message):
    if message.from_user.id not in ADMIN_IDS: return
    clean_invalid_dates()
    cursor.execute("SELECT COUNT(*) FROM accounts WHERE status='free'")
    free = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM accounts WHERE status='busy'")
    busy = cursor.fetchone()[0]
    cursor.execute(
        """
        SELECT COUNT(*)
          FROM accounts
         WHERE status='free'
           AND (
                (faceit_url IS NOT NULL AND faceit_url != '')
                OR (faceit_email IS NOT NULL AND faceit_email != '')
                OR (faceit_password IS NOT NULL AND faceit_password != '')
           )
        """
    )
    free_faceit = cursor.fetchone()[0]
    await message.answer(
        f"Свободных: {free}\n"
        f"Занятых: {busy}\n"
        f"Свободных с Faceit: {free_faceit}",
        reply_markup=main_menu
    )

# ────────────────────────────────────────────────
#  Сдача в аренду
# ────────────────────────────────────────────────

@dp.message(F.text == "🎮 Сдать")
async def rent_start(message: types.Message, state: FSMContext):
    if message.from_user.id not in ADMIN_IDS: return
    clean_invalid_dates()

    cursor.execute("SELECT id, steam_login FROM accounts WHERE status='free' ORDER BY steam_login")
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
    while True:
        try:
            if DB_MAINTENANCE:
                await asyncio.sleep(5)
                continue
            clean_invalid_dates()
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
        except Exception as e:
            logging.error(f"checker_loop: {e}")
        await asyncio.sleep(30)

# ────────────────────────────────────────────────
#  Запуск
# ────────────────────────────────────────────────

async def main():
    ensure_faceit_url_column()
    migrate_encryption()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    log_runtime_config()
    asyncio.create_task(checker_loop())
    print("Бот запущен")
    await dp.start_polling(bot, allowed_updates=["message"])

if __name__ == "__main__":
    asyncio.run(main())
