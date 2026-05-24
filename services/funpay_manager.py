from __future__ import annotations

import asyncio
import logging
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


_CTX: FunPayRuntime | None = None
_FUNPAY_LISTENER_THREAD_STARTED = False
_FUNPAY_LISTENER_THREAD: threading.Thread | None = None
_FUNPAY_AUTO_RAISE_LAST_RUN = 0.0
_FUNPAY_AUTO_RAISE_NEXT_RUN_TS = 0.0
_FUNPAY_AUTO_RAISE_ROTATION_OFFSET = 0
_FUNPAY_AUTO_RAISE_INTERVAL_SECONDS = 3600
_FUNPAY_AUTO_RAISE_JITTER_SECONDS = 900
_FUNPAY_AUTO_RAISE_ERROR_BACKOFF_MIN_SECONDS = 1200
_FUNPAY_AUTO_RAISE_ERROR_BACKOFF_MAX_SECONDS = 2700
_FUNPAY_AUTO_RAISE_WARMUP_MIN_SECONDS = 480
_FUNPAY_AUTO_RAISE_WARMUP_MAX_SECONDS = 1500
_FUNPAY_AUTO_RAISE_MAX_CATEGORIES_PER_RUN = 3
_FUNPAY_AUTO_RAISE_REQUEST_PAUSE_MIN_SECONDS = 2.0
_FUNPAY_AUTO_RAISE_REQUEST_PAUSE_MAX_SECONDS = 6.0
_FUNPAY_ORDER_CACHE: dict[str, tuple[float, dict]] = {}
_FUNPAY_ORDER_CACHE_TTL_SECONDS = 180.0
_FUNPAY_ACCOUNT_CACHE: dict[tuple[str, str], tuple[float, Any]] = {}
_FUNPAY_ACCOUNT_CACHE_TTL_SECONDS = 300.0
_FUNPAY_ACCOUNT_CACHE_LOCK = threading.Lock()
_FUNPAY_IO_LOCK = threading.RLock()
_FUNPAY_LAST_SEND_TS = 0.0
_FUNPAY_MIN_SEND_INTERVAL_SECONDS = 3.0


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
def _funpay_build_loaded_account_sync(golden_key: str, user_agent: str | None = None):
    with _FUNPAY_IO_LOCK:
        cache_key = (str(golden_key or "").strip(), (user_agent or "").strip())
        now_ts = time.monotonic()
        with _FUNPAY_ACCOUNT_CACHE_LOCK:
            cached = _FUNPAY_ACCOUNT_CACHE.get(cache_key)
            if cached is not None:
                cached_at, cached_acc = cached
                if (now_ts - cached_at) <= _FUNPAY_ACCOUNT_CACHE_TTL_SECONDS:
                    return cached_acc
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


def _funpay_call_with_retry_sync(fn: Callable, *args, retries: int = 2, delay_seconds: float = 1.5, **kwargs):
    last_error: Exception | None = None
    attempt_total = max(1, int(retries))
    for attempt in range(attempt_total):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            last_error = e
            if not _funpay_is_rate_limit_error(e) or attempt >= attempt_total - 1:
                raise
            wait_seconds = delay_seconds * (attempt + 1)
            logging.warning("FunPay rate limit detected, retrying in %.1fs: %s", wait_seconds, e)
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


def _funpay_send_message_with_retry_sync(acc, chat_id: int | str, message_text: str, *, context: str) -> None:
    with _FUNPAY_IO_LOCK:
        attempts = 2
        for attempt in range(attempts):
            try:
                global _FUNPAY_LAST_SEND_TS
                now_ts = time.monotonic()
                min_gap = _FUNPAY_MIN_SEND_INTERVAL_SECONDS
                if _FUNPAY_LAST_SEND_TS > 0:
                    elapsed = now_ts - _FUNPAY_LAST_SEND_TS
                    if elapsed < min_gap:
                        sleep_for = min_gap - elapsed
                        time.sleep(sleep_for)
                acc.send_message(chat_id, message_text)
                _FUNPAY_LAST_SEND_TS = time.monotonic()
                return
            except Exception as e:
                err_text = str(e)
                if "NoneType" in err_text and "text" in err_text:
                    logging.warning("FunPay %s sent, but library raised harmless error: %s", context, err_text)
                    _FUNPAY_LAST_SEND_TS = time.monotonic()
                    return
                if _funpay_is_rate_limit_error(e) and attempt < attempts - 1:
                    wait_seconds = 5.0 + attempt * 3.0
                    logging.warning("FunPay rate limit detected while sending %s, retrying in %.1fs: %s", context, wait_seconds, err_text)
                    time.sleep(wait_seconds)
                    continue
                raise


def _funpay_collect_text_parts(obj, field_names: list[str]) -> list[str]:
    parts: list[str] = []
    for field_name in field_names:
        value = getattr(obj, field_name, None)
        if value is None:
            continue
        if isinstance(value, (list, tuple, set)):
            value = " ".join(str(item) for item in value if item is not None)
        if isinstance(value, dict):
            value = " ".join(f"{k}:{v}" for k, v in value.items() if v is not None)
        text = str(value).strip()
        if text:
            parts.append(text)
    return parts


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
            direct_order = method(normalized_id)
            if direct_order:
                text_parts = _funpay_collect_text_parts(direct_order, ["description", "title", "name", "subject", "label", "text"])
                description = " | ".join(text_parts)
                buyer_username = getattr(direct_order, "buyer_username", None) or getattr(direct_order, "buyer", None)
                chat_id = getattr(direct_order, "chat_id", None) or getattr(direct_order, "dialog_id", None)
                if chat_id is None:
                    chat_obj = getattr(direct_order, "chat", None) or getattr(direct_order, "dialog", None)
                    chat_id = getattr(chat_obj, "id", None) if chat_obj is not None else None
                if chat_id is None and buyer_username:
                    chat_id = _funpay_resolve_chat_by_buyer_name(acc, buyer_username)
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
            logging.error("FunPay direct order lookup error (%s): %s", method_name, e)
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
            logging.error("FunPay order lookup error (%s): %s", getter_name, e)
            lookup_errors.append(f"{getter_name}:{e}")

    for order in candidates:
        current_id = str(getattr(order, "id", "") or "").strip().upper()
        if current_id != normalized_id:
            continue
        text_parts = _funpay_collect_text_parts(order, ["description", "title", "name", "subject", "label", "text"])
        description = " | ".join(text_parts)
        buyer_username = getattr(order, "buyer_username", None) or getattr(order, "buyer", None)
        chat_id = getattr(order, "chat_id", None) or getattr(order, "dialog_id", None)
        if chat_id is None:
            chat_obj = getattr(order, "chat", None) or getattr(order, "dialog", None)
            chat_id = getattr(chat_obj, "id", None) if chat_obj is not None else None
        if chat_id is None and buyer_username:
            chat_id = _funpay_resolve_chat_by_buyer_name(acc, buyer_username)
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
            items = dialogs() or []
            dialog_candidates.extend(items)
            lookup_sources.append(f"getDialogs:{len(items)}")
    except Exception as e:
        logging.error("FunPay dialog lookup error: %s", e)
        lookup_errors.append(f"getDialogs:{e}")

    for dialog in dialog_candidates:
        dialog_text_parts = _funpay_collect_text_parts(dialog, ["description", "title", "name", "subject", "text", "last_message", "last_text"])
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
        _funpay_send_message_with_retry_sync(acc, chat_id, "\n".join(order_text_lines), context="initial order message")
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
        _funpay_send_message_with_retry_sync(acc, chat_id, message_text, context="order code")
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


@_funpay_serialized_sync
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
    global _FUNPAY_AUTO_RAISE_ROTATION_OFFSET
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
        await asyncio.to_thread(_funpay_send_chat_message_sync, chat_id, f"{label} код: {code}")
        cursor.execute(
            "UPDATE accounts SET funpay_order_last_code_sent_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), row[0]),
        )
        _ctx().conn.commit()
    except Exception as e:
        logging.error("funpay code send error: %s", e)


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
        acc = _funpay_build_account_sync(golden_key, resolve_funpay_user_agent())
        if hasattr(acc, "get"):
            try:
                acc.get()
            except Exception as e:
                logging.error("FunPay account init error: %s", e)
                return
        runner = FunPayRunner(acc)
    except Exception as e:
        logging.error("FunPay listener init error: %s", e)
        return
    _FUNPAY_LISTENER_THREAD_STARTED = True
    logging.info("FunPay listener started")
    try:
        for event in runner.listen(requests_delay=4):
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
                if get_funpay_auto_raise_enabled():
                    if _FUNPAY_AUTO_RAISE_NEXT_RUN_TS <= 0:
                        _schedule_next_funpay_auto_raise(asyncio.get_running_loop().time(), "warmup")
                    if asyncio.get_running_loop().time() >= _FUNPAY_AUTO_RAISE_NEXT_RUN_TS:
                        raise_result = await funpay_raise_all_lots()
                        if raise_result.get("error"):
                            logging.error("FunPay auto raise error: %s", raise_result["error"])
                            _schedule_next_funpay_auto_raise(asyncio.get_running_loop().time(), "error")
                        else:
                            logging.info("FunPay auto raise completed: raised=%s errors=%s selected=%s total=%s",
                                         raise_result.get("raised"),
                                         raise_result.get("errors"),
                                         raise_result.get("selected_categories"),
                                         raise_result.get("total_categories"))
                            _schedule_next_funpay_auto_raise(asyncio.get_running_loop().time(), "normal")
            else:
                _clear_funpay_auto_raise_schedule()
        except Exception as e:
            logging.exception("FunPay worker error: %s", e)
        await asyncio.sleep(5)


def format_interval_seconds(seconds: int) -> str:
    seconds = max(0, int(seconds))
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}ч {minutes}м"
    if minutes:
        return f"{minutes}м {sec}с"
    return f"{sec}с"
