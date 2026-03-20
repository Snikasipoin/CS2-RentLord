import asyncio
import sqlite3
import logging
import os
from datetime import datetime, timedelta

from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken

from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command, StateFilter
from aiogram.types import ReplyKeyboardMarkup, KeyboardButton
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.context import FSMContext

# ────────────────────────────────────────────────
#  Настройки и шифрование
# ────────────────────────────────────────────────

load_dotenv()

TOKEN = os.getenv("BOT_TOKEN")
ADMIN_ID_RAW = os.getenv("ADMIN_ID") or ""
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

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

# ────────────────────────────────────────────────
#  База данных
# ────────────────────────────────────────────────

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
        [KeyboardButton(text="⏱ Продлить"),    KeyboardButton(text="✅ Освободить")]
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
        await state.set_state(AddAccount.faceit_email)
        await message.answer("Email Faceit:", reply_markup=cancel_kb)
    elif txt == "нет":
        await state.update_data(faceit_email=None, faceit_password=None)
        await show_confirm_add(message, state)
    else:
        await message.answer("Ответьте «да» или «нет».", reply_markup=cancel_kb)

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
        f"Faceit: {d.get('faceit_email') or 'Нет'}"
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
        return await message.answer("Ошибка: аккаунт не найден в базе.", reply_markup=main_menu)

    s_login, s_pw_enc, email, e_pw_enc, f_email, f_pw_enc, st, rent_end = row
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

    if f_email:
        details_lines.extend([
            "",
            "Faceit:",
            f"  Email: {f_email}",
            f"  Пароль: {f_pw or '-'}",
        ])

    # Пара строк про аренду — удобно, но не обязательно
    if st == "busy" and rent_end:
        try:
            dt = datetime.fromisoformat(rent_end)
            mins = max(0, int((dt - datetime.now()).total_seconds() / 60))
            details_lines.extend(["", f"До конца аренды: ~{mins} мин"])
        except Exception:
            pass

    await state.clear()
    await message.answer("\n".join(details_lines), reply_markup=main_menu)

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
    await message.answer(f"Свободных: {free}\nЗанятых: {busy}", reply_markup=main_menu)

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
            [KeyboardButton(text="1 час"), KeyboardButton(text="2 часа"), KeyboardButton(text="3 часа")],
            [KeyboardButton(text="6 часов"), KeyboardButton(text="12 часов"), KeyboardButton(text="24 часа")],
            [KeyboardButton(text="Отмена")]
        ],
        resize_keyboard=True
    )
    await state.set_state(RentAccount.select_time)
    await message.answer("На сколько часов?", reply_markup=times_kb)

@dp.message(StateFilter(RentAccount.select_time))
async def rent_confirm_time(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip().lower()
    if txt == "отмена":
        await state.clear()
        return await message.answer("Сдача отменена", reply_markup=main_menu)

    if not any(txt.startswith(str(h)) for h in (1,2,3,6,12,24)):
        return await message.answer("Выберите время из списка", reply_markup=main_menu)

    hours = int(txt.split()[0])
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
            await message.answer("Аккаунт уже занят или удалён", reply_markup=main_menu)
        else:
            conn.commit()
            await message.answer(
                f"Аккаунт **{login}** сдан до {end.strftime('%d.%m %H:%M')}",
                reply_markup=main_menu
            )

            # Отправляем администратору только Steam логин/пароль для покупателя
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
                    "Данные для покупателя:\n"
                    f"Steam логин: {s_login}\n"
                    f"Steam пароль: {s_pw}"
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
            [KeyboardButton(text="+1 час"), KeyboardButton(text="+2 часа"), KeyboardButton(text="+3 часа")],
            [KeyboardButton(text="+6 часов"), KeyboardButton(text="+12 часов"), KeyboardButton(text="+24 часа")],
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

    if not txt.startswith("+") or not any(txt[1:].startswith(str(h)) for h in (1,2,3,6,12,24)):
        return await message.answer("Выберите время из списка", reply_markup=main_menu)

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
    migrate_encryption()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.create_task(checker_loop())
    print("Бот запущен")
    await dp.start_polling(bot, allowed_updates=["message"])

if __name__ == "__main__":
    asyncio.run(main())