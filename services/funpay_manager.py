from __future__ import annotations

import asyncio
import inspect
import logging
import os
import random
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable

try:
    from FunPayAPI import Account as FunPayAccount
    from FunPayAPI import Runner as FunPayRunner
    from FunPayAPI import enums as FunPayEnums
except Exception:
    FunPayAccount = None
    FunPayRunner = None
    FunPayEnums = None

try:
    from funpaybotengine import Bot as FunPayEngineBot
    from funpaybotengine import Dispatcher as FunPayEngineDispatcher
except Exception:
    FunPayEngineBot = None
    FunPayEngineDispatcher = None


@dataclass
class FunPayRuntime:
    conn: Any
    cursor: Any
    resolve_funpay_golden_key: Callable[[], str]
    resolve_funpay_user_agent: Callable[[], str]
    get_funpay_op_lock: Callable[[], asyncio.Lock]
    decrypt: Callable[[str | None], str | None]
    generate_steam_guard_code: Callable[[str], tuple[str, int]]
    generate_totp_code: Callable[[str], tuple[str, int]]
    set_funpay_order_context: Callable[..., None]
    clear_funpay_order_context: Callable[[int], None]
    mark_funpay_order_notification_for_busy_accounts: Callable[[str | None, str, str], None]
    normalize_db_text: Callable[[Any], str | None]
    is_funpay_order_closed: Callable[[Any], bool]
    get_account_by_funpay_order_id: Callable[[str], Any]
    get_account_by_id: Callable[[int], Any]
    add_rent_history_entry: Callable[..., None]
    close_open_rent_history: Callable[..., None]


@dataclass
class FunPayJob:
    label: str
    sync_fn: Callable
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    future: asyncio.Future


_CTX: FunPayRuntime | None = None
_FUNPAY_LISTENER_THREAD_STARTED = False
_FUNPAY_LISTENER_THREAD: threading.Thread | None = None
_FUNPAY_IO_QUEUE: asyncio.Queue[FunPayJob] | None = None
_FUNPAY_IO_WORKER_STARTED = False
_FUNPAY_AUTO_RAISE_LAST_RUN = 0.0
_FUNPAY_AUTO_RAISE_NEXT_RUN_TS = 0.0
_FUNPAY_SESSION_REFRESH_NEXT_RUN_TS = 0.0
_FUNPAY_AUTO_RAISE_ROTATION_OFFSET = 0
_FUNPAY_AUTO_RAISE_INTERVAL_SECONDS = 3600
_FUNPAY_AUTO_RAISE_JITTER_SECONDS = 900
_FUNPAY_AUTO_RAISE_ERROR_BACKOFF_MIN_SECONDS = 1200
_FUNPAY_AUTO_RAISE_ERROR_BACKOFF_MAX_SECONDS = 2700
_FUNPAY_AUTO_RAISE_WARMUP_MIN_SECONDS = 480
_FUNPAY_AUTO_RAISE_WARMUP_MAX_SECONDS = 1500
_FUNPAY_SESSION_REFRESH_INTERVAL_SECONDS = 3600
_FUNPAY_SESSION_REFRESH_JITTER_SECONDS = 300
_FUNPAY_SESSION_REFRESH_ERROR_BACKOFF_MIN_SECONDS = 900
_FUNPAY_SESSION_REFRESH_ERROR_BACKOFF_MAX_SECONDS = 1800
_FUNPAY_AUTO_RAISE_MAX_CATEGORIES_PER_RUN = 3
_FUNPAY_AUTO_RAISE_REQUEST_PAUSE_MIN_SECONDS = 2.0
_FUNPAY_AUTO_RAISE_REQUEST_PAUSE_MAX_SECONDS = 6.0
_FUNPAY_ORDER_CACHE: dict[str, tuple[float, dict]] = {}
_FUNPAY_ORDER_CACHE_TTL_SECONDS = 180.0
_FUNPAY_ACCOUNT_CACHE: dict[tuple[str, str], tuple[float, Any]] = {}
_FUNPAY_ACCOUNT_CACHE_TTL_SECONDS = 3600.0
_FUNPAY_ACCOUNT_CACHE_LOCK = threading.Lock()
_FUNPAY_IO_LOCK = threading.RLock()
_FUNPAY_LAST_SEND_TS = 0.0
_FUNPAY_MIN_SEND_INTERVAL_SECONDS = 3.0
_FUNPAY_GLOBAL_COOLDOWN_UNTIL_TS = 0.0
_FUNPAY_GLOBAL_COOLDOWN_REASON = ""
_FUNPAY_LISTENER_REQUESTS_DELAY_SECONDS = 8
_FUNPAY_BACKEND_MODE = (os.getenv("FUNPAY_BACKEND") or "auto").strip().lower()


def configure(runtime: FunPayRuntime) -> None:
    global _CTX
    _CTX = runtime


def _ctx() -> FunPayRuntime:
    if _CTX is None:
        raise RuntimeError("FunPay runtime is not configured")
    return _CTX


def _funpay_serialized_sync(fn: Callable) -> Callable:
    @wraps(fn)
    def wrapper(*args, **kwargs):
        with _FUNPAY_IO_LOCK:
            return fn(*args, **kwargs)

    return wrapper


def _funpay_get_io_queue() -> asyncio.Queue[FunPayJob]:
    global _FUNPAY_IO_QUEUE
    if _FUNPAY_IO_QUEUE is None:
        _FUNPAY_IO_QUEUE = asyncio.Queue()
    return _FUNPAY_IO_QUEUE


async def _funpay_submit_io_job(label: str, sync_fn: Callable, *args, **kwargs):
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    queue = _funpay_get_io_queue()
    await queue.put(
        FunPayJob(
            label=label,
            sync_fn=sync_fn,
            args=tuple(args),
            kwargs=dict(kwargs),
            future=future,
        )
    )
    return await future


def resolve_funpay_golden_key() -> str:
    return _ctx().resolve_funpay_golden_key()


def resolve_funpay_user_agent() -> str:
    return _ctx().resolve_funpay_user_agent()


def get_funpay_op_lock() -> asyncio.Lock:
    return _ctx().get_funpay_op_lock()


def funpay_ensure_available() -> None:
    if FunPayAccount is None:
        raise RuntimeError("Библиотека FunPayAPI не установлена. Установите пакет `FunPayAPI`.")


def get_funpay_next_auto_raise_in() -> str:
    if _FUNPAY_AUTO_RAISE_NEXT_RUN_TS <= 0:
        return "не запланирован"
    try:
        now_ts = asyncio.get_running_loop().time()
    except RuntimeError:
        now_ts = time.monotonic()
    left = max(0, int(_FUNPAY_AUTO_RAISE_NEXT_RUN_TS - now_ts))
    return format_interval_seconds(left)


def _schedule_next_funpay_auto_raise(now_ts: float, mode: str = "normal") -> int:
    global _FUNPAY_AUTO_RAISE_NEXT_RUN_TS

    if mode == "warmup":
        delay = random.randint(_FUNPAY_AUTO_RAISE_WARMUP_MIN_SECONDS, _FUNPAY_AUTO_RAISE_WARMUP_MAX_SECONDS)
    elif mode == "error":
        delay = random.randint(_FUNPAY_AUTO_RAISE_ERROR_BACKOFF_MIN_SECONDS, _FUNPAY_AUTO_RAISE_ERROR_BACKOFF_MAX_SECONDS)
    else:
        raw_delay = _FUNPAY_AUTO_RAISE_INTERVAL_SECONDS + random.randint(-_FUNPAY_AUTO_RAISE_JITTER_SECONDS, _FUNPAY_AUTO_RAISE_JITTER_SECONDS)
        delay = max(1800, raw_delay)

    _FUNPAY_AUTO_RAISE_NEXT_RUN_TS = now_ts + delay
    return delay


def _clear_funpay_auto_raise_schedule() -> None:
    global _FUNPAY_AUTO_RAISE_NEXT_RUN_TS, _FUNPAY_AUTO_RAISE_ROTATION_OFFSET
    _FUNPAY_AUTO_RAISE_NEXT_RUN_TS = 0.0
    _FUNPAY_AUTO_RAISE_ROTATION_OFFSET = 0


def _schedule_next_funpay_session_refresh(now_ts: float, mode: str = "normal") -> int:
    global _FUNPAY_SESSION_REFRESH_NEXT_RUN_TS

    if mode == "warmup":
        delay = random.randint(
            max(120, _FUNPAY_SESSION_REFRESH_INTERVAL_SECONDS // 6),
            max(180, _FUNPAY_SESSION_REFRESH_INTERVAL_SECONDS // 2),
        )
    elif mode == "error":
        delay = random.randint(
            _FUNPAY_SESSION_REFRESH_ERROR_BACKOFF_MIN_SECONDS,
            _FUNPAY_SESSION_REFRESH_ERROR_BACKOFF_MAX_SECONDS,
        )
    else:
        raw_delay = _FUNPAY_SESSION_REFRESH_INTERVAL_SECONDS + random.randint(
            -_FUNPAY_SESSION_REFRESH_JITTER_SECONDS,
            _FUNPAY_SESSION_REFRESH_JITTER_SECONDS,
        )
        delay = max(1800, raw_delay)

    _FUNPAY_SESSION_REFRESH_NEXT_RUN_TS = now_ts + delay
    return delay


def _clear_funpay_session_refresh_schedule() -> None:
    global _FUNPAY_SESSION_REFRESH_NEXT_RUN_TS
    _FUNPAY_SESSION_REFRESH_NEXT_RUN_TS = 0.0


def _funpay_set_global_cooldown(seconds: float, reason: str) -> None:
    global _FUNPAY_GLOBAL_COOLDOWN_UNTIL_TS, _FUNPAY_GLOBAL_COOLDOWN_REASON
    now_ts = time.monotonic()
    cooldown_seconds = max(0.0, float(seconds))
    target_ts = now_ts + cooldown_seconds
    if target_ts <= _FUNPAY_GLOBAL_COOLDOWN_UNTIL_TS:
        return
    _FUNPAY_GLOBAL_COOLDOWN_UNTIL_TS = target_ts
    _FUNPAY_GLOBAL_COOLDOWN_REASON = reason
    logging.warning("FunPay global cooldown set for %.1fs (%s)", cooldown_seconds, reason)


def _funpay_wait_for_global_cooldown_sync(context: str) -> None:
    remaining = _FUNPAY_GLOBAL_COOLDOWN_UNTIL_TS - time.monotonic()
    if remaining <= 0:
        return
    logging.info(
        "FunPay global cooldown active before %s (%s), sleeping %.1fs",
        context,
        _FUNPAY_GLOBAL_COOLDOWN_REASON or "unknown",
        remaining,
    )
    time.sleep(remaining)


def funpay_toggle_auto_raise() -> bool:
    global _FUNPAY_AUTO_RAISE_LAST_RUN
    cursor = _ctx().conn.cursor()
    value = cursor.execute(
        "SELECT value FROM settings WHERE key = ?",
        ("funpay_auto_raise_enabled",),
    ).fetchone()
    enabled = bool(value and str(value[0]).strip().lower() in {"1", "true", "yes", "on"})
    new_value = not enabled
    cursor.execute(
        """
        INSERT INTO settings(key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
        """,
        ("funpay_auto_raise_enabled", "1" if new_value else "0"),
    )
    _ctx().conn.commit()
    now_ts = asyncio.get_running_loop().time()
    if new_value:
        _schedule_next_funpay_auto_raise(now_ts, "warmup")
    else:
        _clear_funpay_auto_raise_schedule()
    _FUNPAY_AUTO_RAISE_LAST_RUN = 0.0
    logging.info("FunPay auto raise toggled to %s", new_value)
    return new_value


def get_funpay_auto_raise_enabled() -> bool:
    cursor = _ctx().conn.cursor()
    row = cursor.execute(
        "SELECT value FROM settings WHERE key = ?",
        ("funpay_auto_raise_enabled",),
    ).fetchone()
    return bool(row and str(row[0]).strip().lower() in {"1", "true", "yes", "on"})


def _funpay_build_account_sync(golden_key: str, user_agent: str | None = None):
    funpay_ensure_available()
    return FunPayAccount(golden_key, user_agent=user_agent or None)


@_funpay_serialized_sync
def _funpay_build_loaded_account_sync(golden_key: str, user_agent: str | None = None, force_refresh: bool = False):
    with _FUNPAY_IO_LOCK:
        cache_key = (str(golden_key or "").strip(), (user_agent or "").strip())
        now_ts = time.monotonic()
        with _FUNPAY_ACCOUNT_CACHE_LOCK:
            cached = _FUNPAY_ACCOUNT_CACHE.get(cache_key)
            if cached is not None and not force_refresh:
                cached_at, cached_acc = cached
                if (now_ts - cached_at) <= _FUNPAY_ACCOUNT_CACHE_TTL_SECONDS:
                    return cached_acc
                _FUNPAY_ACCOUNT_CACHE.pop(cache_key, None)
            elif force_refresh:
                _FUNPAY_ACCOUNT_CACHE.pop(cache_key, None)

        acc = _funpay_build_account_sync(golden_key, user_agent)
        if hasattr(acc, "get"):
            _funpay_call_with_retry_sync(acc.get, retries=2, delay_seconds=2.0)

        with _FUNPAY_ACCOUNT_CACHE_LOCK:
            _FUNPAY_ACCOUNT_CACHE[cache_key] = (time.monotonic(), acc)
        return acc


def _funpay_is_rate_limit_error(exc: Exception) -> bool:
    text = str(exc)
    return "429" in text or "Too Many Requests" in text


def _funpay_truncate(text: str | None, limit: int = 500) -> str:
    if not text:
        return ""
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + "…[truncated]"


def _funpay_describe_response_error(exc: Exception) -> str:
    """Читаемое описание ошибки FunPay с телом ОТВЕТА сервера.

    Библиотека FunPayAPI в __str__ исключений печатает тело ЗАПРОСА, а тело
    ответа FunPay добавляет только при log_response=True (для обычного HTTP
    400 это False). Из-за этого реальная причина 400 («чат закрыт» и т.п.)
    в логах не видна. Здесь мы вытаскиваем статус, error_message и тело
    ответа напрямую из response-объекта исключения.
    """
    response = getattr(exc, "response", None)
    if response is None:
        return str(exc)

    parts: list[str] = []
    request = getattr(response, "request", None)
    method = getattr(request, "method", None) or "?"
    url = getattr(response, "url", None) or getattr(request, "url", None) or "?"
    status = getattr(exc, "status_code", None) or getattr(response, "status_code", None) or "?"

    error_message = getattr(exc, "error_message", None)
    if error_message:
        parts.append(f"FunPay error_message: {error_message!r}")

    parts.append(f"HTTP {status} {method} {url}")

    # Тело ответа — главная цель: здесь FunPay пишет причину отказа.
    body_text = ""
    content = getattr(response, "content", None)
    if content:
        try:
            if isinstance(content, bytes):
                body_text = content.decode("utf-8", errors="replace")
            else:
                body_text = str(content)
        except Exception:
            body_text = repr(content)
    if body_text:
        parts.append(f"Response body: {_funpay_truncate(body_text, 500)}")

    return " | ".join(parts)


def _funpay_call_with_retry_sync(fn: Callable, *args, retries: int = 2, delay_seconds: float = 1.5, **kwargs):
    last_error: Exception | None = None
    attempt_total = max(1, int(retries))
    for attempt in range(attempt_total):
        try:
            _funpay_wait_for_global_cooldown_sync(getattr(fn, "__name__", "funpay_call"))
            return fn(*args, **kwargs)
        except Exception as e:
            last_error = e
            if not _funpay_is_rate_limit_error(e) or attempt >= attempt_total - 1:
                if _funpay_is_rate_limit_error(e):
                    cooldown_seconds = max(45.0, delay_seconds * (attempt + 1) * 4.0) + random.uniform(5.0, 20.0)
                    _funpay_set_global_cooldown(cooldown_seconds, f"rate_limit:{getattr(fn, '__name__', 'funpay_call')}")
                raise
            wait_seconds = delay_seconds * (attempt + 1)
            logging.warning("FunPay rate limit detected, retrying in %.1fs: %s", wait_seconds, _funpay_describe_response_error(e))
            _funpay_set_global_cooldown(wait_seconds + random.uniform(5.0, 15.0), f"retry:{getattr(fn, '__name__', 'funpay_call')}")
            time.sleep(wait_seconds)
    if last_error is not None:
        raise last_error
    raise RuntimeError("FunPay retry helper failed unexpectedly")


def _funpay_cache_order(order_id: str, order_data: dict) -> None:
    normalized_id = str(order_id or "").strip().upper()
    if not normalized_id:
        return
    _FUNPAY_ORDER_CACHE[normalized_id] = (time.monotonic(), dict(order_data))


def _funpay_get_cached_order(order_id: str) -> dict | None:
    normalized_id = str(order_id or "").strip().upper()
    if not normalized_id:
        return None
    cached = _FUNPAY_ORDER_CACHE.get(normalized_id)
    if not cached:
        return None
    cached_at, payload = cached
    if (time.monotonic() - cached_at) > _FUNPAY_ORDER_CACHE_TTL_SECONDS:
        _FUNPAY_ORDER_CACHE.pop(normalized_id, None)
        return None
    return dict(payload)


def _funpay_extract_chat_id(chat_obj: Any) -> int | str | None:
    if chat_obj is None:
        return None
    if isinstance(chat_obj, (int, str)):
        raw = str(chat_obj).strip()
        return int(raw) if raw.isdigit() else raw or None
    for attr_name in ("id", "chat_id", "dialog_id"):
        value = getattr(chat_obj, attr_name, None)
        if value is None:
            continue
        raw = str(value).strip()
        if not raw:
            continue
        return int(raw) if raw.isdigit() else raw
    return None


def _funpay_resolve_send_targets_sync(acc, chat_id: int | str, buyer_username: str | None = None) -> list[Any]:
    targets: list[Any] = []

    if buyer_username:
        warm_target = _funpay_resolve_chat_object_by_buyer_name(acc, buyer_username)
        if warm_target is not None:
            targets.append(warm_target)

    if chat_id is not None and hasattr(acc, "get_chat"):
        try:
            chat_obj = acc.get_chat(chat_id)
            if chat_obj is not None:
                targets.append(chat_obj)
        except Exception as e:
            logging.debug("FunPay get_chat warmup failed for %s: %s", chat_id, e)

    if chat_id is not None and chat_id not in targets:
        targets.append(chat_id)

    return targets


def _funpay_sanitize_message_text(message_text: str | None) -> str:
    text = (message_text or "")
    for ch in ("\ufeff", "\u2064", "\u200b", "\u200c", "\u200d"):
        text = text.replace(ch, "")
    return text.strip()


def _funpay_backend_mode() -> str:
    return _FUNPAY_BACKEND_MODE


def _funpay_engine_backend_enabled() -> bool:
    if FunPayEngineBot is None:
        return False
    return _funpay_backend_mode() in {"auto", "engine", "funpaybotengine"}


async def _funpay_maybe_await(value):
    if inspect.isawaitable(value):
        return await value
    return value


async def _funpay_call_candidate_method(obj, method_names: tuple[str, ...], *args, **kwargs):
    if obj is None:
        raise AttributeError("FunPay object is missing")
    last_error: Exception | None = None
    for method_name in method_names:
        method = getattr(obj, method_name, None)
        if method is None:
            continue
        try:
            return await _funpay_maybe_await(method(*args, **kwargs))
        except Exception as e:
            last_error = e
    if last_error is not None:
        raise last_error
    raise AttributeError(f"None of FunPay methods exist: {', '.join(method_names)}")


async def _funpay_engine_build_bot_async(user_agent: str | None = None):
    if not _funpay_engine_backend_enabled():
        raise RuntimeError("FunPayBotEngine backend is disabled or unavailable")

    golden_key = resolve_funpay_golden_key()
    if not golden_key:
        raise RuntimeError("FunPay golden key не задан")

    kwargs = {"golden_key": golden_key}
    if user_agent:
        kwargs["user_agent"] = user_agent

    try:
        return FunPayEngineBot(**kwargs)
    except TypeError:
        kwargs.pop("user_agent", None)
        return FunPayEngineBot(**kwargs)


async def _funpay_engine_resolve_order_record_async(order_id: str, user_agent: str | None = None) -> dict:
    bot = await _funpay_engine_build_bot_async(user_agent)
    normalized_id = str(order_id or "").strip().upper()
    if not normalized_id:
        return {"error": "Пустой order_id"}

    candidate_method_sets = (
        ("get_order", "getOrder", "get_order_page", "getOrderPage"),
        ("getNewOrders", "getLastOrders"),
        ("getDialogs",),
    )

    debug: dict[str, Any] = {"matched": False, "backend": "funpaybotengine"}
    available_methods = [name for name in (
        "get_order",
        "getOrder",
        "get_order_page",
        "getOrderPage",
        "get_chat_by_name",
        "get_chat_page",
        "get_chat_history",
        "getDialogs",
        "getNewOrders",
        "getLastOrders",
    ) if hasattr(bot, name)]

    for method_names in candidate_method_sets:
        for method_name in method_names:
            method = getattr(bot, method_name, None)
            if method is None:
                continue
            try:
                if method_name in {"getNewOrders", "getLastOrders", "getDialogs"}:
                    payload = await _funpay_maybe_await(method())
                else:
                    payload = await _funpay_maybe_await(method(normalized_id))
            except Exception as e:
                debug.setdefault("lookup_errors", []).append(f"{method_name}:{e}")
                continue

            if not payload:
                continue

            if isinstance(payload, (list, tuple)):
                candidates = payload
            else:
                candidates = [payload]

            for candidate in candidates:
                current_id = str(getattr(candidate, "id", "") or "").strip().upper()
                text_parts = _funpay_collect_text_parts(
                    candidate,
                    [
                        "id",
                        "order_id",
                        "orderNumber",
                        "order_number",
                        "number",
                        "description",
                        "title",
                        "name",
                        "subject",
                        "label",
                        "text",
                        "last_message",
                        "last_text",
                        "status",
                        "state",
                        "price",
                        "sum",
                        "url",
                        "link",
                        "href",
                        "order",
                        "chat",
                        "dialog",
                        "dialog_page",
                        "page",
                        "data",
                        "result",
                        "item",
                        "items",
                        "message",
                        "messages",
                        "user",
                        "buyer_obj",
                        "seller",
                        "chat_id",
                        "dialog_id",
                        "buyer_username",
                        "buyer",
                    ],
                )
                if current_id != normalized_id and not _funpay_candidate_matches_order_id(candidate, normalized_id, text_parts):
                    continue
                buyer_username = getattr(candidate, "buyer_username", None) or getattr(candidate, "buyer", None)
                chat_id = getattr(candidate, "chat_id", None) or getattr(candidate, "dialog_id", None)
                chat_target = candidate if hasattr(candidate, "send_message") else None
                if chat_id is None:
                    chat_obj = getattr(candidate, "chat", None) or getattr(candidate, "dialog", None) or getattr(candidate, "chat_page", None)
                    if chat_target is None and chat_obj is not None:
                        chat_target = chat_obj
                    chat_id = getattr(chat_obj, "id", None) if chat_obj is not None else None
                if chat_target is None and chat_id is None:
                    resolved_chat_target = await _funpay_engine_resolve_chat_target_from_order_async(candidate)
                    if resolved_chat_target is not None:
                        chat_target = resolved_chat_target
                        chat_id = _funpay_extract_chat_id(chat_target)
                order_status = getattr(candidate, "status", None) or getattr(candidate, "state", None)
                order_price = getattr(candidate, "price", None) or getattr(candidate, "sum", None)
                result = {
                    "id": current_id or normalized_id,
                    "description": " | ".join(text_parts),
                    "buyer_username": buyer_username,
                    "chat_id": chat_id,
                    "chat_target": chat_target,
                    "status": _ctx().normalize_db_text(order_status),
                    "price": _ctx().normalize_db_text(order_price),
                    "is_faceit": _funpay_detect_faceit_from_text(text_parts),
                    "debug": {
                        "matched": True,
                        "source": f"funpaybotengine:{method_name}",
                        "available_methods": available_methods,
                        "text_parts": text_parts[:10],
                    },
                }
                return result

    chat_page_method_names = ("get_chat_page", "get_chat_history", "get_chat")
    for method_name in chat_page_method_names:
        method = getattr(bot, method_name, None)
        if method is None:
            continue
        try:
            chat_payload = await _funpay_maybe_await(method(normalized_id))
        except TypeError:
            try:
                chat_payload = await _funpay_maybe_await(method())
            except Exception as e:
                debug.setdefault("chat_lookup_errors", []).append(f"{method_name}:{e}")
                continue
        except Exception as e:
            debug.setdefault("chat_lookup_errors", []).append(f"{method_name}:{e}")
            continue

        if not chat_payload:
            continue

        chat_target = chat_payload
        chat_id = _funpay_extract_chat_id(chat_payload)
        text_parts = _funpay_collect_text_parts(
            chat_payload,
            [
                "id",
                "chat_id",
                "dialog_id",
                "order_id",
                "orderNumber",
                "order_number",
                "number",
                "description",
                "title",
                "name",
                "subject",
                "text",
                "last_message",
                "last_text",
                "order",
                "chat",
                "dialog",
                "dialog_page",
                "page",
                "data",
                "result",
                "item",
                "items",
                "message",
                "messages",
                "buyer_username",
                "buyer",
                "username",
                "user",
                "seller",
            ],
        )
        result = {
            "id": normalized_id,
            "description": " | ".join(text_parts),
            "buyer_username": getattr(chat_payload, "buyer_username", None) or getattr(chat_payload, "buyer", None),
            "chat_id": chat_id,
            "chat_target": chat_target,
            "status": _ctx().normalize_db_text(getattr(chat_payload, "status", None) or getattr(chat_payload, "state", None)),
            "price": _ctx().normalize_db_text(getattr(chat_payload, "price", None) or getattr(chat_payload, "sum", None)),
            "is_faceit": _funpay_detect_faceit_from_text(text_parts),
            "debug": {
                "matched": True,
                "source": f"chat_lookup:{method_name}",
                "available_methods": available_methods,
                "text_parts": text_parts[:10],
            },
        }
        return result

    return {
        "id": normalized_id,
        "description": "",
        "buyer_username": None,
        "chat_id": None,
        "chat_target": None,
        "status": None,
        "price": None,
        "is_faceit": False,
        "debug": {
            "matched": False,
            "backend": "funpaybotengine",
            "available_methods": available_methods,
            "lookup_errors": debug.get("lookup_errors", []),
        },
    }


async def _funpay_engine_resolve_chat_id_async(bot, buyer_username: str | None) -> int | str | None:
    buyer_username = (buyer_username or "").strip()
    if not buyer_username:
        return None
    for method_name in ("get_chat_by_name", "get_chat_page", "get_chat_history"):
        method = getattr(bot, method_name, None)
        if method is None:
            continue
        try:
            try:
                payload = await _funpay_maybe_await(method(buyer_username, True))
            except TypeError:
                payload = await _funpay_maybe_await(method(buyer_username))
        except Exception:
            continue
        chat_id = _funpay_extract_chat_id(payload)
        if chat_id is not None:
            return chat_id
    return None


async def _funpay_engine_resolve_chat_target_from_order_async(order_obj) -> Any | None:
    if order_obj is None:
        return None
    if hasattr(order_obj, "send_message"):
        return order_obj

    for method_name in ("get_chat_page", "get_chat_history", "get_chat"):
        method = getattr(order_obj, method_name, None)
        if method is None:
            continue
        try:
            target = await _funpay_maybe_await(method())
        except TypeError:
            try:
                target = await _funpay_maybe_await(method(order_obj))
            except Exception:
                continue
        except Exception:
            continue
        if target is not None:
            return target
    return None


async def _funpay_engine_resolve_chat_target_async(bot, chat_id: int | str | None, buyer_username: str | None = None):
    if buyer_username:
        for method_name in ("get_chat_by_name", "get_chat_page", "get_chat_history"):
            method = getattr(bot, method_name, None)
            if method is None:
                continue
            try:
                try:
                    target = await _funpay_maybe_await(method(buyer_username, True))
                except TypeError:
                    target = await _funpay_maybe_await(method(buyer_username))
                if target is not None:
                    return target
            except Exception:
                continue

    if chat_id is not None:
        for method_name in ("get_chat_page", "get_chat_history", "get_chat"):
            method = getattr(bot, method_name, None)
            if method is None:
                continue
            try:
                target = await _funpay_maybe_await(method(chat_id))
                if target is not None:
                    return target
            except Exception:
                continue
    return None


async def _funpay_engine_send_message_async(
    bot,
    chat_id: int | str | None,
    message_text: str,
    *,
    buyer_username: str | None = None,
    context: str,
    allow_buyer_lookup: bool = False,
) -> None:
    message_text = _funpay_sanitize_message_text(message_text)
    target = None
    if chat_id is not None:
        target = await _funpay_engine_resolve_chat_target_async(bot, chat_id, None)
    if target is None and allow_buyer_lookup:
        target = await _funpay_engine_resolve_chat_target_async(bot, None, buyer_username)
    candidate_targets = [target, chat_id]
    if allow_buyer_lookup and buyer_username:
        candidate_targets.append(buyer_username)
    send_method_names = ("send_message", "send", "message")

    for candidate in candidate_targets:
        if candidate is None:
            continue
        if hasattr(candidate, "send_message"):
            try:
                await _funpay_maybe_await(candidate.send_message(message_text))
                return
            except Exception as e:
                if "NoneType" in str(e) and "text" in str(e):
                    logging.warning("FunPay %s sent, but engine raised harmless error: %s", context, e)
                    return
        for method_name in send_method_names:
            method = getattr(bot, method_name, None)
            if method is None:
                continue
            try:
                await _funpay_maybe_await(method(candidate, message_text))
                return
            except Exception as e:
                if "NoneType" in str(e) and "text" in str(e):
                    logging.warning("FunPay %s sent, but engine raised harmless error: %s", context, e)
                    return
    raise RuntimeError(f"Не удалось отправить сообщение через FunPayBotEngine: {context}")


async def _funpay_engine_send_message_to_target_async(target, message_text: str, *, context: str) -> None:
    message_text = _funpay_sanitize_message_text(message_text)
    if target is None:
        raise RuntimeError(f"No FunPay target available for {context}")

    if hasattr(target, "send_message"):
        try:
            await _funpay_maybe_await(target.send_message(message_text))
            return
        except Exception as e:
            if "NoneType" in str(e) and "text" in str(e):
                logging.warning("FunPay %s sent, but engine raised harmless error: %s", context, e)
                return
            raise

    raise RuntimeError(f"Target does not support send_message for {context}")


def _funpay_resolve_chat_by_buyer_name(acc, buyer_username: str | None) -> int | str | None:
    buyer_username = (buyer_username or "").strip()
    if not buyer_username:
        return None

    method = getattr(acc, "get_chat_by_name", None)
    if method is None:
        return None

    try:
        chat_obj = method(buyer_username, True)
    except TypeError:
        try:
            chat_obj = method(buyer_username)
        except Exception as e:
            logging.error("FunPay chat resolve error by buyer name (%s): %s", buyer_username, e)
            return None
    except Exception as e:
        logging.error("FunPay chat resolve error by buyer name (%s): %s", buyer_username, e)
        return None
    chat_id = _funpay_extract_chat_id(chat_obj)
    if chat_id is not None:
        return chat_id
    return None


def _funpay_resolve_chat_object_by_buyer_name(acc, buyer_username: str | None):
    buyer_username = (buyer_username or "").strip()
    if not buyer_username:
        return None

    method = getattr(acc, "get_chat_by_name", None)
    if method is None:
        return None

    try:
        try:
            return method(buyer_username, True)
        except TypeError:
            return method(buyer_username)
    except Exception as e:
        logging.debug("FunPay chat object resolve failed by buyer name (%s): %s", buyer_username, e)
        return None


def _funpay_send_message_with_retry_sync(
    acc,
    chat_id: int | str,
    message_text: str,
    *,
    context: str,
    buyer_username: str | None = None,
) -> None:
    with _FUNPAY_IO_LOCK:
        attempts = 3
        message_text = _funpay_sanitize_message_text(message_text)
        targets = _funpay_resolve_send_targets_sync(acc, chat_id, buyer_username)
        for attempt in range(attempts):
            try:
                _funpay_wait_for_global_cooldown_sync(f"send:{context}")
                global _FUNPAY_LAST_SEND_TS
                now_ts = time.monotonic()
                min_gap = _FUNPAY_MIN_SEND_INTERVAL_SECONDS
                if _FUNPAY_LAST_SEND_TS > 0:
                    elapsed = now_ts - _FUNPAY_LAST_SEND_TS
                    if elapsed < min_gap:
                        sleep_for = min_gap - elapsed
                        time.sleep(sleep_for)
                last_error: Exception | None = None
                for target in targets:
                    try:
                        send_method = getattr(target, "send_message", None)
                        if callable(send_method):
                            send_method(message_text)
                        else:
                            acc.send_message(target, message_text)
                        _FUNPAY_LAST_SEND_TS = time.monotonic()
                        return
                    except Exception as send_error:
                        last_error = send_error
                        err_text = str(send_error)
                        if "NoneType" in err_text and "text" in err_text:
                            logging.warning("FunPay %s sent, but library raised harmless error: %s", context, err_text)
                            _FUNPAY_LAST_SEND_TS = time.monotonic()
                            return
                if last_error is None:
                    raise RuntimeError(f"FunPay send failed for {context}: no send targets available")
                raise last_error
            except Exception as e:
                err_text = _funpay_describe_response_error(e)
                if "NoneType" in str(e) and "text" in str(e):
                    logging.warning("FunPay %s sent, but library raised harmless error: %s", context, err_text)
                    _FUNPAY_LAST_SEND_TS = time.monotonic()
                    return
                transient_runner_error = "https://funpay.com/runner/" in err_text and ("400" in err_text or "Ошибка запроса" in err_text)
                if (_funpay_is_rate_limit_error(e) or transient_runner_error) and attempt < attempts - 1:
                    wait_seconds = 3.0 + attempt * 4.0
                    logging.warning(
                        "FunPay send retry for %s in %.1fs: %s",
                        context,
                        wait_seconds,
                        err_text,
                    )
                    _funpay_set_global_cooldown(wait_seconds + random.uniform(6.0, 15.0), f"send:{context}")
                    time.sleep(wait_seconds)
                    if buyer_username:
                        targets = _funpay_resolve_send_targets_sync(acc, chat_id, buyer_username)
                    continue
                if _funpay_is_rate_limit_error(e):
                    _funpay_set_global_cooldown(75.0 + random.uniform(0.0, 30.0), f"send:{context}")
                raise


def _funpay_collect_text_parts(obj, field_names: list[str], *, _depth: int = 0) -> list[str]:
    parts: list[str] = []
    for field_name in field_names:
        value = getattr(obj, field_name, None)
        if value is None and isinstance(obj, dict):
            value = obj.get(field_name)
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            nested_parts = []
            for item in value:
                if item is None:
                    continue
                nested_parts.append(str(item))
                if _depth < 1 and not isinstance(item, (str, bytes, int, float, bool)):
                    nested_parts.extend(_funpay_collect_text_parts(item, field_names, _depth=_depth + 1))
            value = " ".join(nested_parts)
        if isinstance(value, dict):
            dict_parts = [f"{k}:{v}" for k, v in value.items() if v is not None]
            if _depth < 1:
                for nested_value in value.values():
                    if nested_value is None or isinstance(nested_value, (str, bytes, int, float, bool)):
                        continue
                    dict_parts.extend(_funpay_collect_text_parts(nested_value, field_names, _depth=_depth + 1))
            value = " ".join(dict_parts)
        text = str(value).strip()
        if text:
            parts.append(text)
    return parts


def _funpay_candidate_matches_order_id(candidate, normalized_id: str, text_parts: list[str]) -> bool:
    if not normalized_id:
        return False

    text_blob = " | ".join(text_parts).upper()
    if normalized_id in text_blob:
        return True

    for attr_name in ("id", "order_id", "orderNumber", "order_number", "number", "url", "link", "href"):
        value = getattr(candidate, attr_name, None)
        if value is None and isinstance(candidate, dict):
            value = candidate.get(attr_name)
        if value is None:
            continue
        if normalized_id == str(value).strip().upper():
            return True
        if normalized_id in str(value).strip().upper():
            return True

    return False


def _funpay_detect_faceit_from_text(parts: list[str]) -> bool:
    joined = " ".join(parts).lower()
    if not joined:
        return False
    return any(token in joined for token in ("faceit", "фейсит", "фэйсит"))


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


@_funpay_serialized_sync
def _funpay_find_order_record_sync(order_id: str, user_agent: str | None = None) -> dict:
    golden_key = resolve_funpay_golden_key()
    if not golden_key:
        return {"error": "FunPay golden key не задан"}

    normalized_id = str(order_id or "").strip().upper()
    if not normalized_id:
        return {"error": "Пустой order_id"}

    cached_order = _funpay_get_cached_order(normalized_id)
    if cached_order is not None:
        return cached_order

    acc = _funpay_build_loaded_account_sync(golden_key, user_agent or resolve_funpay_user_agent())

    available_methods = [name for name in ("getNewOrders", "getLastOrders", "getDialogs") if hasattr(acc, name)]
    direct_lookup_errors: list[str] = []
    for method_name in ("get_order", "getOrder"):
        method = getattr(acc, method_name, None)
        if method is None:
            continue
        try:
            direct_order = None
            lookup_args = [
                (normalized_id,),
                (normalized_id.lower(),),
                (f"https://funpay.com/orders/{normalized_id}/",),
            ]
            if method_name in {"get_order", "getOrder"}:
                lookup_args.append(tuple())
            last_direct_error: Exception | None = None
            for lookup_arg in lookup_args:
                try:
                    direct_order = _funpay_call_with_retry_sync(method, *lookup_arg, retries=2, delay_seconds=5.0)
                    if direct_order:
                        break
                except Exception as inner_error:
                    last_direct_error = inner_error
                    continue
            if direct_order is None and last_direct_error is not None:
                raise last_direct_error
            if direct_order:
                text_parts = _funpay_collect_text_parts(
                    direct_order,
                    [
                        "id",
                        "order_id",
                        "orderNumber",
                        "order_number",
                        "number",
                        "description",
                        "title",
                        "name",
                        "subject",
                        "label",
                        "text",
                        "status",
                        "state",
                        "price",
                        "sum",
                        "url",
                        "link",
                        "href",
                        "order",
                        "chat",
                        "dialog",
                        "dialog_page",
                        "page",
                        "data",
                        "result",
                        "item",
                        "items",
                        "message",
                        "messages",
                        "user",
                        "buyer_obj",
                        "seller",
                        "chat_id",
                        "dialog_id",
                        "buyer_username",
                        "buyer",
                    ],
                )
                description = " | ".join(text_parts)
                buyer_username = getattr(direct_order, "buyer_username", None) or getattr(direct_order, "buyer", None)
                chat_id = getattr(direct_order, "chat_id", None) or getattr(direct_order, "dialog_id", None)
                if chat_id is None:
                    chat_obj = getattr(direct_order, "chat", None) or getattr(direct_order, "dialog", None)
                    chat_id = getattr(chat_obj, "id", None) if chat_obj is not None else None
                order_status = getattr(direct_order, "status", None) or getattr(direct_order, "state", None)
                order_price = getattr(direct_order, "price", None) or getattr(direct_order, "sum", None)
                result = {
                    "id": normalized_id,
                    "description": description,
                    "buyer_username": buyer_username,
                    "chat_id": chat_id,
                    "status": _ctx().normalize_db_text(order_status),
                    "price": _ctx().normalize_db_text(order_price),
                    "is_faceit": _funpay_detect_faceit_from_text(text_parts),
                    "debug": {
                        "matched": True,
                        "source": f"direct_lookup:{method_name}",
                        "available_methods": available_methods,
                        "text_parts": text_parts[:10],
                    },
                }
                _funpay_cache_order(normalized_id, result)
                return result
        except Exception as e:
            logging.error("FunPay direct order lookup error (%s): %s", method_name, _funpay_describe_response_error(e))
            direct_lookup_errors.append(f"{method_name}:{e}")

    candidates: list[object] = []
    lookup_sources: list[str] = []
    lookup_errors: list[str] = []
    for getter_name in ("getNewOrders", "getLastOrders"):
        getter = getattr(acc, getter_name, None)
        if getter is None:
            continue
        try:
            items = _funpay_call_with_retry_sync(getter, retries=2, delay_seconds=5.0) or []
            candidates.extend(items)
            lookup_sources.append(f"{getter_name}:{len(items)}")
        except Exception as e:
            logging.error("FunPay order lookup error (%s): %s", getter_name, _funpay_describe_response_error(e))
            lookup_errors.append(f"{getter_name}:{e}")

    for order in candidates:
        current_id = str(getattr(order, "id", "") or "").strip().upper()
        if current_id != normalized_id:
            continue
        text_parts = _funpay_collect_text_parts(
            order,
            [
                "id",
                "order_id",
                "orderNumber",
                "order_number",
                "number",
                "description",
                "title",
                "name",
                "subject",
                "label",
                "text",
                "status",
                "state",
                "price",
                "sum",
                "url",
                "link",
                "href",
                "order",
                "chat",
                "dialog",
                "dialog_page",
                "page",
                "data",
                "result",
                "item",
                "items",
                "message",
                "messages",
                "user",
                "buyer_obj",
                "seller",
                "chat_id",
                "dialog_id",
                "buyer_username",
                "buyer",
            ],
        )
        description = " | ".join(text_parts)
        buyer_username = getattr(order, "buyer_username", None) or getattr(order, "buyer", None)
        chat_id = getattr(order, "chat_id", None) or getattr(order, "dialog_id", None)
        if chat_id is None:
            chat_obj = getattr(order, "chat", None) or getattr(order, "dialog", None)
            chat_id = getattr(chat_obj, "id", None) if chat_obj is not None else None
        order_status = getattr(order, "status", None) or getattr(order, "state", None)
        order_price = getattr(order, "price", None) or getattr(order, "sum", None)
        result = {
            "id": current_id,
            "description": description,
            "buyer_username": buyer_username,
            "chat_id": chat_id,
            "status": _ctx().normalize_db_text(order_status),
            "price": _ctx().normalize_db_text(order_price),
            "is_faceit": _funpay_detect_faceit_from_text(text_parts),
            "debug": {
                "matched": True,
                "source": "orders_lookup",
                "available_methods": available_methods,
                "text_parts": text_parts[:10],
            },
        }
        _funpay_cache_order(current_id, result)
        return result

    dialog_candidates: list[object] = []
    try:
        dialogs = getattr(acc, "getDialogs", None)
        if dialogs is not None:
            items = _funpay_call_with_retry_sync(dialogs, retries=2, delay_seconds=5.0) or []
            dialog_candidates.extend(items)
            lookup_sources.append(f"getDialogs:{len(items)}")
    except Exception as e:
        logging.error("FunPay dialog lookup error: %s", _funpay_describe_response_error(e))
        lookup_errors.append(f"getDialogs:{e}")

    for dialog in dialog_candidates:
        dialog_text_parts = _funpay_collect_text_parts(
            dialog,
            [
                "id",
                "chat_id",
                "dialog_id",
                "order_id",
                "orderNumber",
                "order_number",
                "number",
                "description",
                "title",
                "name",
                "subject",
                "text",
                "last_message",
                "last_text",
                "order",
                "chat",
                "dialog",
                "dialog_page",
                "page",
                "data",
                "result",
                "item",
                "items",
                "message",
                "messages",
                "buyer_username",
                "buyer",
                "username",
                "user",
                "seller",
            ],
        )
        dialog_text = " | ".join(dialog_text_parts)
        if normalized_id not in dialog_text.upper():
            continue
        dialog_id = getattr(dialog, "id", None) or getattr(dialog, "chat_id", None) or getattr(dialog, "dialog_id", None)
        dialog_user = getattr(dialog, "username", None) or getattr(dialog, "buyer_username", None) or getattr(dialog, "user", None)
        if dialog_user is None:
            dialog_user_obj = getattr(dialog, "user", None)
            dialog_user = getattr(dialog_user_obj, "name", None) or getattr(dialog_user_obj, "username", None)
        result = {
            "id": normalized_id,
            "description": dialog_text,
            "buyer_username": dialog_user,
            "chat_id": dialog_id,
            "status": _ctx().normalize_db_text(getattr(dialog, "status", None)),
            "price": _ctx().normalize_db_text(getattr(dialog, "price", None)),
            "is_faceit": _funpay_detect_faceit_from_text(dialog_text_parts),
            "debug": {
                "matched": True,
                "source": "dialogs_lookup",
                "available_methods": available_methods,
                "text_parts": dialog_text_parts[:10],
            },
        }
        _funpay_cache_order(normalized_id, result)
        return result

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
            "candidate_ids": [str(getattr(item, "id", "") or "").strip().upper() for item in candidates[:10]],
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


@_funpay_serialized_sync
def _funpay_send_chat_message_sync(chat_id: int | str, message_text: str, user_agent: str | None = None) -> None:
    golden_key = resolve_funpay_golden_key()
    if not golden_key:
        raise RuntimeError("FunPay golden key не задан")

    acc = _funpay_build_loaded_account_sync(golden_key, user_agent or resolve_funpay_user_agent())
    try:
        _funpay_send_message_with_retry_sync(acc, chat_id, message_text, context="chat message")
    except Exception as e:
        raise


@_funpay_serialized_sync
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

    acc = _funpay_build_loaded_account_sync(golden_key, user_agent or resolve_funpay_user_agent())
    order = _funpay_find_order_record_sync(order_id, user_agent)
    if order.get("error"):
        return order

    buyer_username = order.get("buyer_username") or fallback_buyer_username
    chat_id = order.get("chat_id") or fallback_chat_id
    if chat_id is None and buyer_username:
        try:
            chat_id = _funpay_resolve_chat_by_buyer_name(acc, buyer_username)
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
            _ctx().set_funpay_order_context(
                persist_account_id,
                order.get("id") or str(order_id).strip().upper(),
                f"https://funpay.com/orders/{str(order.get('id') or str(order_id).strip().upper())}/",
                buyer_username,
                chat_id,
                order.get("status"),
                order.get("price"),
            )
            _ctx().conn.commit()
        except Exception as e:
            logging.error("FunPay order context persist error: %s", e)

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
        order_text_lines.extend(["", f"Faceit email: {faceit_email_display}", f"Faceit пароль: {faceit_password_display}"])
        order_copy_lines.extend([f"Faceit email: {faceit_email_display}", f"Faceit пароль: {faceit_password_display}"])

    try:
        _funpay_send_message_with_retry_sync(
            acc,
            chat_id,
            "\n".join(order_text_lines),
            context="initial order message",
            buyer_username=buyer_username,
        )
    except Exception as e:
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


@_funpay_serialized_sync
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

    acc = _funpay_build_loaded_account_sync(golden_key, user_agent or resolve_funpay_user_agent())
    order = _funpay_find_order_record_sync(order_id, user_agent)
    if order.get("error"):
        return order

    if code_type == "faceit" and not order.get("is_faceit"):
        return {"error": "Этот заказ не FACEIT, код Faceit не требуется."}

    buyer_username = order.get("buyer_username") or fallback_buyer_username
    chat_id = order.get("chat_id") or fallback_chat_id
    if chat_id is None and buyer_username:
        try:
            chat_id = _funpay_resolve_chat_by_buyer_name(acc, buyer_username)
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
            _ctx().set_funpay_order_context(
                persist_account_id,
                order.get("id") or str(order_id).strip().upper(),
                f"https://funpay.com/orders/{str(order.get('id') or str(order_id).strip().upper())}/",
                buyer_username,
                chat_id,
                order.get("status"),
                order.get("price"),
            )
            _ctx().conn.commit()
        except Exception as e:
            logging.error("FunPay order context persist error (code): %s", e)

    if code_type == "steam":
        if not steam_shared_secret:
            return {"error": "Steam shared secret не задан"}
        code, _ = _ctx().generate_steam_guard_code(_ctx().decrypt(steam_shared_secret))
        message_text = f"Steam Guard код" + (f" для аккаунта {account_login}" if account_login else "") + f": {code}"
    elif code_type == "faceit":
        if not faceit_2fa_secret:
            return {"error": "Faceit 2FA secret не задан"}
        code, _ = _ctx().generate_totp_code(_ctx().decrypt(faceit_2fa_secret))
        message_text = f"Faceit код" + (f" для аккаунта {account_login}" if account_login else "") + f": {code}"
    else:
        return {"error": "Неизвестный тип кода"}

    try:
        _funpay_send_message_with_retry_sync(
            acc,
            chat_id,
            message_text,
            context="order code",
            buyer_username=buyer_username,
        )
    except Exception as e:
        return {"error": f"Не удалось отправить код в чат заказа: {e}"}
    return {"success": True, "chat_id": chat_id, "buyer_username": buyer_username, "code_type": code_type, "code": code}


def mark_funpay_order_notification_for_busy_accounts(order_id: str | None, column_name: str, value: str) -> None:
    if not order_id:
        return
    if column_name not in {"rent_reminder_5m_sent_at", "rent_overdue_notified_at"}:
        raise ValueError("Unsupported notification column")
    _ctx().cursor.execute(
        f"""
        UPDATE accounts
           SET {column_name} = ?
         WHERE status = 'busy'
           AND funpay_order_id = ?
        """,
        (value, order_id),
    )


def clear_funpay_order_context(aid: int) -> None:
    _ctx().cursor.execute(
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


@_funpay_serialized_sync
def _funpay_fetch_balance_sync(golden_key: str, user_agent: str | None = None) -> dict:
    acc = _funpay_build_loaded_account_sync(golden_key, user_agent)
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


@_funpay_serialized_sync
def _funpay_raise_all_lots_sync(
    golden_key: str,
    user_agent: str | None = None,
    max_categories_per_run: int | None = None,
    rotation_offset: int = 0,
    pause_min_seconds: float = 0.0,
    pause_max_seconds: float = 0.0,
) -> dict:
    acc = _funpay_build_loaded_account_sync(golden_key, user_agent)
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
    try:
        return await _funpay_submit_io_job("funpay_get_balance", _funpay_fetch_balance_sync, golden_key, user_agent)
    except Exception as e:
        return {"error": str(e)}


async def funpay_raise_all_lots() -> dict:
    global _FUNPAY_AUTO_RAISE_ROTATION_OFFSET
    golden_key = resolve_funpay_golden_key()
    if not golden_key:
        return {"error": "FunPay golden key не задан"}

    user_agent = resolve_funpay_user_agent()
    try:
        result = await _funpay_submit_io_job(
            "funpay_raise_all_lots",
            _funpay_raise_all_lots_sync,
            golden_key,
            user_agent,
            _FUNPAY_AUTO_RAISE_MAX_CATEGORIES_PER_RUN,
            _FUNPAY_AUTO_RAISE_ROTATION_OFFSET,
            _FUNPAY_AUTO_RAISE_REQUEST_PAUSE_MIN_SECONDS,
            _FUNPAY_AUTO_RAISE_REQUEST_PAUSE_MAX_SECONDS,
        )
        total_categories = int(result.get("total_categories") or 0)
        selected_categories = int(result.get("selected_categories") or 0)
        if total_categories > 0 and selected_categories > 0:
            _FUNPAY_AUTO_RAISE_ROTATION_OFFSET = (
                _FUNPAY_AUTO_RAISE_ROTATION_OFFSET + selected_categories
            ) % total_categories
        return result
    except Exception as e:
        return {"error": str(e)}


def _funpay_register_new_order(loop: asyncio.AbstractEventLoop, order_id: str, order_url: str | None, buyer_username: str | None, chat_id: int | str | None, status: str | None, price: str | None) -> None:
    cursor = _ctx().cursor
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
    _ctx().set_funpay_order_context(aid, order_id, order_url, buyer_username, chat_id, status, price)
    _ctx().conn.commit()


async def _funpay_handle_chat_message(chat_id: int | None, author_id: int | None, text: str | None) -> None:
    if chat_id is None:
        return
    normalized = (text or "").strip().lower()
    if normalized not in {"/code", "/steam", "/faceit", "код", "code", "steam code", "steam", "faceit code", "faceit"}:
        return
    logging.info("FunPay incoming chat message: chat_id=%s author_id=%s text=%r", chat_id, author_id, text)
    cursor = _ctx().cursor
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
        order_info = await asyncio.to_thread(_funpay_find_order_record_sync, order_id)
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
            code, _seconds_left = _ctx().generate_steam_guard_code(_ctx().decrypt(steam_shared_secret))
        else:
            code, _seconds_left = _ctx().generate_totp_code(_ctx().decrypt(faceit_2fa_secret))
    except Exception as e:
        logging.error("funpay code generation error: %s", e)
        return
    try:
        label = "Steam Guard" if code_type == "steam" else "Faceit"
        await funpay_send_chat_message(chat_id, f"{label} код: {code}")
        cursor.execute(
            "UPDATE accounts SET funpay_order_last_code_sent_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), row[0]),
        )
        _ctx().conn.commit()
    except Exception as e:
        logging.error("funpay code send error: %s", _funpay_describe_response_error(e))


async def funpay_send_chat_message(chat_id: int | str, message_text: str, user_agent: str | None = None) -> None:
    golden_key = resolve_funpay_golden_key()
    if not golden_key:
        raise RuntimeError("FunPay golden key не задан")
    if _funpay_engine_backend_enabled():
        try:
            bot = await _funpay_engine_build_bot_async(user_agent)
            await _funpay_engine_send_message_async(bot, chat_id, message_text, context="chat message")
            return
        except Exception as e:
            logging.warning("FunPayBotEngine chat send fallback to FunPayAPI: %s", _funpay_describe_response_error(e))
    await _funpay_submit_io_job("funpay_send_chat_message", _funpay_send_chat_message_sync, chat_id, message_text, user_agent)


async def funpay_send_initial_order_message(
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
    if _funpay_engine_backend_enabled():
        try:
            bot = await _funpay_engine_build_bot_async(user_agent)
            order = await _funpay_engine_resolve_order_record_async(order_id, user_agent)
            if order.get("error"):
                raise RuntimeError(order["error"])

            buyer_username = order.get("buyer_username") or fallback_buyer_username
            chat_id = order.get("chat_id") or fallback_chat_id
            chat_target = order.get("chat_target")
            if chat_id is None and chat_target is not None:
                chat_id = _funpay_extract_chat_id(chat_target)
            if chat_target is None and chat_id is None:
                raise RuntimeError(
                    "Не удалось определить чат заказа\n"
                    + _funpay_format_order_debug_text(
                        "initial_order_message",
                        order,
                        fallback_chat_id=fallback_chat_id,
                        fallback_buyer_username=fallback_buyer_username,
                        include_faceit=bool(order.get("is_faceit") and include_faceit),
                    )
                )

            if persist_account_id is not None:
                try:
                    _ctx().set_funpay_order_context(
                        persist_account_id,
                        order.get("id") or str(order_id).strip().upper(),
                        f"https://funpay.com/orders/{str(order.get('id') or str(order_id).strip().upper())}/",
                        buyer_username,
                        chat_id,
                        order.get("status"),
                        order.get("price"),
                    )
                    _ctx().conn.commit()
                except Exception as e:
                    logging.error("FunPay order context persist error: %s", e)

            is_faceit_order = bool(order.get("is_faceit"))
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

            if chat_target is not None:
                await _funpay_engine_send_message_to_target_async(
                    chat_target,
                    "\n".join(order_text_lines),
                    context="initial order message",
                )
            else:
                await _funpay_engine_send_message_async(
                    bot,
                    chat_id,
                    "\n".join(order_text_lines),
                    buyer_username=None,
                    context="initial order message",
                    allow_buyer_lookup=False,
                )
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
        except Exception as e:
            logging.error("FunPayBotEngine initial order error: %s", _funpay_describe_response_error(e))
            return {"error": f"FunPayBotEngine initial order error: {_funpay_describe_response_error(e)}"}
    return await _funpay_submit_io_job(
        "funpay_send_initial_order_message",
        _funpay_send_initial_order_message_sync,
        order_id,
        steam_login,
        steam_password,
        faceit_email,
        faceit_password,
        include_faceit,
        persist_account_id,
        fallback_chat_id,
        fallback_buyer_username,
        user_agent,
    )


async def funpay_send_code_to_order(
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
    if _funpay_engine_backend_enabled():
        try:
            bot = await _funpay_engine_build_bot_async(user_agent)
            order = await _funpay_engine_resolve_order_record_async(order_id, user_agent)
            if order.get("error"):
                raise RuntimeError(order["error"])

            if code_type == "faceit" and not order.get("is_faceit"):
                return {"error": "Этот заказ не FACEIT, код Faceit не требуется."}

            buyer_username = order.get("buyer_username") or fallback_buyer_username
            chat_id = order.get("chat_id") or fallback_chat_id
            chat_target = order.get("chat_target")
            if chat_id is None and chat_target is not None:
                chat_id = _funpay_extract_chat_id(chat_target)
            if chat_target is None and chat_id is None:
                raise RuntimeError(
                    "Не удалось определить чат заказа\n"
                    + _funpay_format_order_debug_text(
                        "send_order_code",
                        order,
                        fallback_chat_id=fallback_chat_id,
                        fallback_buyer_username=fallback_buyer_username,
                        extra_error=f"code_type={code_type}",
                    )
                )

            if persist_account_id is not None:
                try:
                    _ctx().set_funpay_order_context(
                        persist_account_id,
                        order.get("id") or str(order_id).strip().upper(),
                        f"https://funpay.com/orders/{str(order.get('id') or str(order_id).strip().upper())}/",
                        buyer_username,
                        chat_id,
                        order.get("status"),
                        order.get("price"),
                    )
                    _ctx().conn.commit()
                except Exception as e:
                    logging.error("FunPay order context persist error (code): %s", e)

            if code_type == "steam":
                if not steam_shared_secret:
                    return {"error": "Steam shared secret не задан"}
                code, _seconds_left = _ctx().generate_steam_guard_code(_ctx().decrypt(steam_shared_secret))
                message_text = f"Steam Guard код" + (f" для аккаунта {account_login}" if account_login else "") + f": {code}"
            elif code_type == "faceit":
                if not faceit_2fa_secret:
                    return {"error": "Faceit 2FA secret не задан"}
                code, _seconds_left = _ctx().generate_totp_code(_ctx().decrypt(faceit_2fa_secret))
                message_text = f"Faceit код" + (f" для аккаунта {account_login}" if account_login else "") + f": {code}"
            else:
                return {"error": "Неизвестный тип кода"}

            if chat_target is not None:
                await _funpay_engine_send_message_to_target_async(
                    chat_target,
                    message_text,
                    context="order code",
                )
            else:
                await _funpay_engine_send_message_async(
                    bot,
                    chat_id,
                    message_text,
                    buyer_username=None,
                    context="order code",
                    allow_buyer_lookup=False,
                )
            return {"success": True, "chat_id": chat_id, "buyer_username": buyer_username, "code_type": code_type, "code": code}
        except Exception as e:
            logging.error("FunPayBotEngine code send error: %s", _funpay_describe_response_error(e))
            return {"error": f"FunPayBotEngine code send error: {_funpay_describe_response_error(e)}"}
    return await _funpay_submit_io_job(
        "funpay_send_code_to_order",
        _funpay_send_code_to_order_sync,
        order_id,
        code_type,
        account_login,
        steam_shared_secret,
        faceit_2fa_secret,
        persist_account_id,
        fallback_chat_id,
        fallback_buyer_username,
        user_agent,
    )


async def run_funpay_io_worker() -> None:
    global _FUNPAY_IO_WORKER_STARTED
    if _FUNPAY_IO_WORKER_STARTED:
        return
    _FUNPAY_IO_WORKER_STARTED = True
    queue = _funpay_get_io_queue()
    logging.info("FunPay IO worker started")
    while True:
        job = await queue.get()
        try:
            logging.info("FunPay job started: %s", job.label)
            try:
                result = await asyncio.to_thread(job.sync_fn, *job.args, **job.kwargs)
                if not job.future.cancelled():
                    job.future.set_result(result)
                logging.info("FunPay job finished: %s", job.label)
                await asyncio.sleep(5)
            except Exception as e:
                if not job.future.cancelled():
                    job.future.set_exception(e)
                logging.error("FunPay job failed: %s: %s", job.label, _funpay_describe_response_error(e))
        except Exception as e:
            logging.exception("FunPay IO worker loop error: %s", e)
        finally:
            queue.task_done()


def _funpay_listener_thread(loop: asyncio.AbstractEventLoop) -> None:
    global _FUNPAY_LISTENER_THREAD_STARTED
    if FunPayRunner is None:
        logging.warning("FunPayRunner not available; FunPay listener disabled")
        return
    golden_key = resolve_funpay_golden_key()
    if not golden_key:
        logging.warning("FunPay golden key not set; FunPay listener disabled")
        return
    try:
        acc = _funpay_build_loaded_account_sync(golden_key, resolve_funpay_user_agent())
        runner = FunPayRunner(acc)
    except Exception as e:
        logging.error("FunPay listener init error: %s", e)
        return
    _FUNPAY_LISTENER_THREAD_STARTED = True
    logging.info("FunPay listener started")
    try:
        for event in runner.listen(requests_delay=_FUNPAY_LISTENER_REQUESTS_DELAY_SECONDS):
            try:
                event_type = getattr(event, "type", None) or getattr(event, "event_type", None)
                if event_type == getattr(FunPayEnums.EventTypes, "NEW_ORDER", None):
                    order = getattr(event, "order", None) or getattr(event, "data", None) or event
                    order_id = str(getattr(order, "id", "") or "").strip().upper()
                    buyer_username = getattr(order, "buyer_username", None) or getattr(order, "buyer", None)
                    chat_id = getattr(order, "chat_id", None) or getattr(order, "dialog_id", None)
                    if chat_id is None:
                        chat_obj = getattr(order, "chat", None) or getattr(order, "dialog", None)
                        chat_id = getattr(chat_obj, "id", None) if chat_obj is not None else None
                    if chat_id is None and buyer_username:
                        chat_id = _funpay_resolve_chat_by_buyer_name(acc, buyer_username)
                    order_url = f"https://funpay.com/orders/{order_id}/" if order_id else None
                    order_status = getattr(order, "status", None) or getattr(order, "state", None)
                    order_price = getattr(order, "price", None) or getattr(order, "sum", None)
                    try:
                        _funpay_register_new_order(loop, order_id, order_url, buyer_username, chat_id, order_status, order_price)
                    except Exception as e:
                        logging.error("FunPay new order sync error: %s", e)
                elif event_type == getattr(FunPayEnums.EventTypes, "NEW_MESSAGE", None):
                    chat_id = getattr(event, "chat_id", None)
                    author_id = getattr(event, "author_id", None)
                    text = getattr(event, "text", None)
                    asyncio.run_coroutine_threadsafe(_funpay_handle_chat_message(chat_id, author_id, text), loop)
            except Exception as e:
                logging.error("FunPay listener event error: %s", e)
    except Exception as e:
        logging.error("FunPay listener stopped: %s", e)


def start_funpay_listener(loop: asyncio.AbstractEventLoop) -> None:
    global _FUNPAY_LISTENER_THREAD
    if _FUNPAY_LISTENER_THREAD_STARTED:
        return
    if FunPayRunner is None:
        logging.warning("FunPay listener not started: FunPayRunner unavailable")
        return
    thread = threading.Thread(target=_funpay_listener_thread, args=(loop,), daemon=True, name="funpay-listener")
    thread.start()
    _FUNPAY_LISTENER_THREAD = thread


async def run_funpay_worker() -> None:
    logging.info("FunPay polling worker started")
    while True:
        try:
            golden_key = resolve_funpay_golden_key()
            if golden_key:
                now_ts = asyncio.get_running_loop().time()
                if _FUNPAY_SESSION_REFRESH_NEXT_RUN_TS <= 0:
                    _schedule_next_funpay_session_refresh(now_ts, "warmup")
                if now_ts >= _FUNPAY_SESSION_REFRESH_NEXT_RUN_TS:
                    user_agent = resolve_funpay_user_agent()
                    try:
                        await asyncio.to_thread(
                            _funpay_build_loaded_account_sync,
                            golden_key,
                            user_agent,
                            True,
                        )
                        logging.info("FunPay session refreshed")
                        _schedule_next_funpay_session_refresh(now_ts, "normal")
                    except Exception as e:
                        logging.warning("FunPay session refresh error: %s", _funpay_describe_response_error(e))
                        _schedule_next_funpay_session_refresh(now_ts, "error")
                if get_funpay_auto_raise_enabled():
                    if _FUNPAY_AUTO_RAISE_NEXT_RUN_TS <= 0:
                        _schedule_next_funpay_auto_raise(now_ts, "warmup")
                    if now_ts >= _FUNPAY_AUTO_RAISE_NEXT_RUN_TS:
                        raise_result = await funpay_raise_all_lots()
                        if raise_result.get("error"):
                            logging.error("FunPay auto raise error: %s", raise_result["error"])
                            _schedule_next_funpay_auto_raise(now_ts, "error")
                        else:
                            logging.info("FunPay auto raise completed: raised=%s errors=%s selected=%s total=%s",
                                         raise_result.get("raised"),
                                         raise_result.get("errors"),
                                         raise_result.get("selected_categories"),
                                         raise_result.get("total_categories"))
                            _schedule_next_funpay_auto_raise(now_ts, "normal")
            else:
                _clear_funpay_auto_raise_schedule()
                _clear_funpay_session_refresh_schedule()
        except Exception as e:
            logging.exception("FunPay worker error: %s", e)
        await asyncio.sleep(10)


def format_interval_seconds(seconds: int) -> str:
    seconds = max(0, int(seconds))
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}ч {minutes}м"
    if minutes:
        return f"{minutes}м {sec}с"
    return f"{sec}с"
