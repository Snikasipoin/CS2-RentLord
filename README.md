# CS2 Account Rent Bot
### Professional Telegram automation for CS2 account rental management

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)]()
[![aiogram](https://img.shields.io/badge/aiogram-v3-green.svg)]()
[![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey.svg)]()
[![Status](https://img.shields.io/badge/Status-Production-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-orange.svg)]()

---

# Описание проекта

**CS2 Account Rent Bot** — это профессиональный Telegram бот для автоматизации аренды Steam аккаунтов (CS2) с системой получения Steam Guard и Faceit кодов напрямую из почты.

Проект решает основные проблемы ручного управления аккаунтами:

• Потерянные Steam Guard коды  
• Путаница со свободными аккаунтами  
• Ошибки при аренде  
• Ручной контроль времени  
• Постоянные проверки почты  

Бот полностью автоматизирует процесс управления арендой.

---

# Основной функционал

## Управление аккаунтами

Бот позволяет:

• Добавлять неограниченное количество аккаунтов  
• Хранить Steam данные  
• Хранить email данные  
• Видеть статус аккаунта  
• Отслеживать занятые аккаунты  
• Смотреть оставшееся время аренды  

Статусы аккаунтов:

FREE — свободен  
WAITING CODE — ожидание Steam Guard  
RENTED — сдан  

---

## Умная система аренды

Процесс аренды реализован профессионально:

Выбор аккаунта  
→ Выбор времени  
→ Выбор способа получения кода  
→ Активация аренды  

Доступные варианты:

Request Steam Code  
Code entered manually  
Get Faceit Code  

Это исключает ошибки при выдаче аккаунтов.

---

## Автоматическое получение Steam Guard

Бот умеет:

• Подключаться к почте через IMAP  
• Искать письма Steam  
• Извлекать код подтверждения  
• Отправлять код в Telegram  
• Автоматически запускать аренду  

Поддерживаемые почты:

• Outlook
• Firstmail
• Gmail
• Proton (Bridge)
• Любые IMAP сервисы

Функции:

• Проверка только новых писем  
• Таймаут ожидания  
• Обработка ошибок  
• Асинхронная работа  
• Retry логика  

---

## Поддержка Faceit

Если аккаунт с Faceit:

Можно отдельно получить код.

Функции:

• Получение Faceit кода  
• Извлечение 6 digit кодов  
• Не влияет на статус аренды  
• Можно получать в любой момент  

---

## Уведомления

Бот автоматически:

• Уведомляет за 5 минут до окончания аренды  
• Показывает оставшееся время  
• Предупреждает если нет свободных аккаунтов  
• Показывает активные аренды  

---

## Автоматизация

Бот убирает ручную работу:

Не нужно проверять почту  
Не нужно следить за временем  
Не нужно искать коды  
Не нужно проверять свободные аккаунты  

Все управление происходит внутри Telegram.

---

# Преимущества проекта

Почему это лучше ручного управления:

• Полная автоматизация Steam Guard  
• Быстрое получение кодов  
• Отсутствие конфликтов аккаунтов  
• Масштабируемость  
• Чистая архитектура  
• Асинхронная работа  
• Минимум ручных действий  
• Production подход  

---

# Архитектура проекта

Проект построен по service-based архитектуре.

Структура:
bot/

handlers/
rent_handlers.py
account_handlers.py

services/
steam_guard_service.py
faceit_service.py
imap_service.py

database/
models.py
db.py

scheduler/
rent_scheduler.py

utils/
crypto.py
helpers.py

bot.py
config.py


---

# Технический стек

Python 3.10+

aiogram v3

SQLite

Asyncio

IMAP automation

FSM state machine

Service architecture

---

# Workflow аренды

Стандартный поток:

FREE  
→ WAITING CODE  
→ RENTED  

или:

FREE  
→ RENTED (manual)

Это предотвращает:

• двойную аренду  
• ошибки  
• race conditions  

---

# Безопасность

Проект учитывает безопасность:

• Email пароли шифруются  
• Нет утечек в логах  
• Асинхронные подключения  
• Таймауты  
• Контроль ошибок  
• Нет хранения кодов  

---

# Производительность

Бот рассчитан на:

10–200 аккаунтов без проблем.

При оптимизации:

500+ аккаунтов.

За счет:

Async IMAP  
Non blocking handlers  
FSM логики  

---

# Установка

Клонировать проект:


git clone https://github.com/yourname/cs2-rent-bot


Перейти в папку:


cd cs2-rent-bot


Установить зависимости:


pip install -r requirements.txt


Создать .env:


BOT_TOKEN=
ADMIN_ID=
FACEIT_API_KEY=

FACEIT_API_KEY нужен для того, чтобы бот мог подтягивать текущий FACEIT Elo по ссылке профиля.

Если хостинг не прокидывает переменные окружения в runtime, можно создать файл `/app/data/.env` с содержимым:

```env
FACEIT_API_KEY=ваш_ключ
```

Бот прочитает его при старте и покажет в логах источник ключа.


Запустить:


python bot.py


---

# Настройка аккаунтов

Пример:


Steam login: login
Steam password: password

Email: email@example.com

Email password: emailpass


IMAP должен быть включен.

---

# Roadmap (V2)

Планируемые улучшения:

• Multi admin system  
• Web панель  
• Статистика доходности  
• Группы аккаунтов  
• Auto rent extension  
• Mail connection pool  
• Faceit auto detect  
• Account tags  
• Profit analytics  

---

# Возможные улучшения V3

• Redis кеш  
• PostgreSQL  
• Web dashboard  
• REST API  
• Docker deployment  
• Horizontal scaling  

---

# Философия проекта

Проект создавался с принципами:

Automation first  
Clean architecture  
No spaghetti code  
Production mindset  
Scalability ready  

---

# Для кого проект

Подойдет если:

Вы сдаете Steam аккаунты  
У вас много аккаунтов  
Вы устали от ручного контроля  
Хотите автоматизацию  

---

# Disclaimer

Этот проект является инструментом автоматизации.

Пользователь несет ответственность за соблюдение правил Steam, Faceit и других сервисов.

---

# Автор

Private automation project.

---

# License

MIT License

Можно свободно изменять и дорабатывать.
