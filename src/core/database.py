"""Database storage layer for Flow2API"""

import asyncio
import aiosqlite
import hashlib
import hmac
import json
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
from pathlib import Path
from .config import DEFAULT_YESCAPTCHA_TASK_TYPE, normalize_yescaptcha_task_type
from .account_audit import (
    SCHEMA_STATEMENTS as ACCOUNT_AUDIT_SCHEMA,
    INSERT_SQL as ACCOUNT_AUDIT_INSERT,
    OPERATIONS as ACCOUNT_AUDIT_OPERATIONS,
    SOURCES as ACCOUNT_AUDIT_SOURCES,
    decode_event as decode_account_audit_event,
    normalize_stored_event as normalize_stored_account_audit_event,
    sanitize_email as sanitize_audit_email,
    sanitize_serial as sanitize_audit_serial,
    audit_account_operation,
)
from .account_operation_context import operation_source
from .models import (
    Token,
    TokenStats,
    Task,
    RequestLog,
    AdminConfig,
    ProxyConfig,
    GenerationConfig,
    CacheConfig,
    Project,
    CaptchaConfig,
    DebugConfig,
    PluginConfig,
    CallLogicConfig,
    TokenRefreshConfig,
)


class Database:
    """SQLite database manager"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            # Store database in data directory
            data_dir = Path(__file__).parent.parent.parent / "data"
            data_dir.mkdir(exist_ok=True)
            db_path = str(data_dir / "flow.db")
        self.db_path = db_path
        self._write_lock = asyncio.Lock()
        self._connect_timeout = 30
        self._busy_timeout_ms = 30000

    def db_exists(self) -> bool:
        """Check if database file exists"""
        return Path(self.db_path).exists()

    async def _configure_connection(self, db):
        """Apply SQLite runtime settings for better concurrent behavior."""
        await db.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        await db.execute("PRAGMA foreign_keys = ON")

    def _current_stats_date(self) -> str:
        """Return the logical date used by daily token statistics."""
        return date.today().isoformat()

    @asynccontextmanager
    async def _connect(self, *, write: bool = False):
        """Open a configured SQLite connection and optionally serialize writes."""
        if write:
            async with self._write_lock:
                async with aiosqlite.connect(
                    self.db_path, timeout=self._connect_timeout
                ) as db:
                    await self._configure_connection(db)
                    yield db
            return

        async with aiosqlite.connect(self.db_path, timeout=self._connect_timeout) as db:
            await self._configure_connection(db)
            yield db

    async def _table_exists(self, db, table_name: str) -> bool:
        """Check if a table exists in the database"""
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        )
        result = await cursor.fetchone()
        return result is not None

    async def _column_exists(self, db, table_name: str, column_name: str) -> bool:
        """Check if a column exists in a table"""
        try:
            cursor = await db.execute(f"PRAGMA table_info({table_name})")
            columns = await cursor.fetchall()
            return any(col[1] == column_name for col in columns)
        except:
            return False

    async def _ensure_config_rows(self, db, config_dict: dict = None):
        """Ensure all config tables have their default rows

        Args:
            db: Database connection
            config_dict: Configuration dictionary from setting.toml (optional)
                        If None, use default values instead of reading from TOML.
        """
        # Ensure admin_config has a row
        cursor = await db.execute("SELECT COUNT(*) FROM admin_config")
        count = await cursor.fetchone()
        if count[0] == 0:
            admin_username = "admin"
            admin_password = "admin"
            api_key = "han1234"
            error_ban_threshold = 3

            if config_dict:
                global_config = config_dict.get("global", {})
                admin_username = global_config.get("admin_username", "admin")
                admin_password = global_config.get("admin_password", "admin")
                api_key = global_config.get("api_key", "han1234")

                admin_config = config_dict.get("admin", {})
                error_ban_threshold = admin_config.get("error_ban_threshold", 3)

            await db.execute(
                """
                INSERT INTO admin_config (id, username, password, api_key, error_ban_threshold)
                VALUES (1, ?, ?, ?, ?)
            """,
                (admin_username, admin_password, api_key, error_ban_threshold),
            )

        # Ensure proxy_config has a row
        cursor = await db.execute("SELECT COUNT(*) FROM proxy_config")
        count = await cursor.fetchone()
        if count[0] == 0:
            proxy_enabled = False
            proxy_url = None
            media_proxy_enabled = False
            media_proxy_url = None

            if config_dict:
                proxy_config = config_dict.get("proxy", {})
                proxy_enabled = proxy_config.get("proxy_enabled", False)
                proxy_url = proxy_config.get("proxy_url", "")
                proxy_url = proxy_url if proxy_url else None
                media_proxy_enabled = proxy_config.get(
                    "media_proxy_enabled",
                    proxy_config.get("image_io_proxy_enabled", False),
                )
                media_proxy_url = proxy_config.get(
                    "media_proxy_url", proxy_config.get("image_io_proxy_url", "")
                )
                media_proxy_url = media_proxy_url if media_proxy_url else None

            await db.execute(
                """
                INSERT INTO proxy_config (id, enabled, proxy_url, media_proxy_enabled, media_proxy_url)
                VALUES (1, ?, ?, ?, ?)
            """,
                (proxy_enabled, proxy_url, media_proxy_enabled, media_proxy_url),
            )

        # Ensure generation_config has a row
        cursor = await db.execute("SELECT COUNT(*) FROM generation_config")
        count = await cursor.fetchone()
        if count[0] == 0:
            image_timeout = 300
            video_timeout = 1500
            max_retries = 3

            if config_dict:
                generation_config = config_dict.get("generation", {})
                flow_config = config_dict.get("flow", {})
                image_timeout = generation_config.get("image_timeout", 300)
                video_timeout = generation_config.get("video_timeout", 1500)
                max_retries = flow_config.get("max_retries", 3)

            try:
                max_retries = max(1, int(max_retries))
            except Exception:
                max_retries = 3

            await db.execute(
                """
                INSERT INTO generation_config (id, image_timeout, video_timeout, max_retries)
                VALUES (1, ?, ?, ?)
            """,
                (image_timeout, video_timeout, max_retries),
            )

        # Ensure call_logic_config has a row
        cursor = await db.execute("SELECT COUNT(*) FROM call_logic_config")
        count = await cursor.fetchone()
        if count[0] == 0:
            call_mode = "default"
            polling_mode_enabled = False

            if config_dict:
                call_logic_config = config_dict.get("call_logic", {})
                call_mode = call_logic_config.get("call_mode", "default")
                if call_mode not in ("default", "polling"):
                    polling_mode_enabled = call_logic_config.get(
                        "polling_mode_enabled", False
                    )
                    call_mode = "polling" if polling_mode_enabled else "default"
                else:
                    polling_mode_enabled = call_mode == "polling"

            await db.execute(
                """
                INSERT INTO call_logic_config (id, call_mode, polling_mode_enabled)
                VALUES (1, ?, ?)
            """,
                (call_mode, polling_mode_enabled),
            )

        # Ensure cache_config has a row
        cursor = await db.execute("SELECT COUNT(*) FROM cache_config")
        count = await cursor.fetchone()
        if count[0] == 0:
            cache_enabled = False
            cache_timeout = 7200
            cache_base_url = None

            if config_dict:
                cache_config = config_dict.get("cache", {})
                cache_enabled = cache_config.get("enabled", False)
                cache_timeout = cache_config.get("timeout", 7200)
                cache_base_url = cache_config.get("base_url", "")
                # Convert empty string to None
                cache_base_url = cache_base_url if cache_base_url else None

            await db.execute(
                """
                INSERT INTO cache_config (id, cache_enabled, cache_timeout, cache_base_url)
                VALUES (1, ?, ?, ?)
            """,
                (cache_enabled, cache_timeout, cache_base_url),
            )

        # Ensure debug_config has a row
        cursor = await db.execute("SELECT COUNT(*) FROM debug_config")
        count = await cursor.fetchone()
        if count[0] == 0:
            debug_enabled = False
            log_requests = True
            log_responses = True
            mask_token = True

            if config_dict:
                debug_config = config_dict.get("debug", {})
                debug_enabled = debug_config.get("enabled", False)
                log_requests = debug_config.get("log_requests", True)
                log_responses = debug_config.get("log_responses", True)
                mask_token = debug_config.get("mask_token", True)

            await db.execute(
                """
                INSERT INTO debug_config (id, enabled, log_requests, log_responses, mask_token)
                VALUES (1, ?, ?, ?, ?)
            """,
                (debug_enabled, log_requests, log_responses, mask_token),
            )

        # Ensure captcha_config has a row
        cursor = await db.execute("SELECT COUNT(*) FROM captcha_config")
        count = await cursor.fetchone()
        if count[0] == 0:
            captcha_method = "yescaptcha"
            yescaptcha_api_key = ""
            yescaptcha_base_url = "https://api.yescaptcha.com"
            yescaptcha_task_type = DEFAULT_YESCAPTCHA_TASK_TYPE
            twocaptcha_api_key = ""
            twocaptcha_base_url = "https://api.2captcha.com"
            remote_browser_base_url = ""
            remote_browser_api_key = ""
            remote_browser_timeout = 60
            browser_count = 1
            personal_project_pool_size = 4
            personal_max_resident_tabs = 5
            browser_personal_fresh_restart_every_n_solves = 10
            personal_idle_tab_ttl_seconds = 600

            if config_dict:
                captcha_config = config_dict.get("captcha", {})
                captcha_method = captcha_config.get("captcha_method", "yescaptcha")
                yescaptcha_api_key = captcha_config.get("yescaptcha_api_key", "")
                yescaptcha_base_url = captcha_config.get(
                    "yescaptcha_base_url", "https://api.yescaptcha.com"
                )
                yescaptcha_task_type = normalize_yescaptcha_task_type(
                    captcha_config.get("yescaptcha_task_type")
                )
                twocaptcha_api_key = captcha_config.get("twocaptcha_api_key", "")
                twocaptcha_base_url = captcha_config.get(
                    "twocaptcha_base_url", "https://api.2captcha.com"
                )
                remote_browser_base_url = captcha_config.get(
                    "remote_browser_base_url", ""
                )
                remote_browser_api_key = captcha_config.get(
                    "remote_browser_api_key", ""
                )
                remote_browser_timeout = captcha_config.get(
                    "remote_browser_timeout", 60
                )
                browser_count = captcha_config.get("browser_count", 1)
                personal_project_pool_size = captcha_config.get(
                    "personal_project_pool_size", 4
                )
                personal_max_resident_tabs = captcha_config.get(
                    "personal_max_resident_tabs", 5
                )
                browser_personal_fresh_restart_every_n_solves = captcha_config.get(
                    "browser_personal_fresh_restart_every_n_solves", 10
                )
                personal_idle_tab_ttl_seconds = captcha_config.get(
                    "personal_idle_tab_ttl_seconds", 600
                )
            try:
                remote_browser_timeout = max(5, int(remote_browser_timeout))
            except Exception:
                remote_browser_timeout = 60
            try:
                browser_count = max(1, int(browser_count))
            except Exception:
                browser_count = 1
            try:
                personal_project_pool_size = max(
                    1, min(50, int(personal_project_pool_size))
                )
            except Exception:
                personal_project_pool_size = 4
            try:
                personal_max_resident_tabs = max(
                    1, min(50, int(personal_max_resident_tabs))
                )
            except Exception:
                personal_max_resident_tabs = 5
            try:
                browser_personal_fresh_restart_every_n_solves = max(
                    0, int(browser_personal_fresh_restart_every_n_solves)
                )
            except Exception:
                browser_personal_fresh_restart_every_n_solves = 10
            try:
                personal_idle_tab_ttl_seconds = max(
                    60, int(personal_idle_tab_ttl_seconds)
                )
            except Exception:
                personal_idle_tab_ttl_seconds = 600

            await db.execute(
                """
                INSERT INTO captcha_config (
                    id, captcha_method, yescaptcha_api_key, yescaptcha_base_url,
                    yescaptcha_task_type,
                    remote_browser_base_url, remote_browser_api_key, remote_browser_timeout,
                    browser_count, personal_project_pool_size,
                    personal_max_resident_tabs, browser_personal_fresh_restart_every_n_solves,
                    personal_idle_tab_ttl_seconds, twocaptcha_api_key, twocaptcha_base_url
                )
                VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                captcha_method,
                yescaptcha_api_key,
                yescaptcha_base_url,
                yescaptcha_task_type,
                remote_browser_base_url,
                remote_browser_api_key,
                remote_browser_timeout,
                browser_count,
                personal_project_pool_size,
                personal_max_resident_tabs,
                browser_personal_fresh_restart_every_n_solves,
                personal_idle_tab_ttl_seconds,
                twocaptcha_api_key,
                twocaptcha_base_url,
                ),
            )

        # Ensure plugin_config has a row
        cursor = await db.execute("SELECT COUNT(*) FROM plugin_config")
        count = await cursor.fetchone()
        if count[0] == 0:
            await db.execute("""
                INSERT INTO plugin_config (id, connection_token, auto_enable_on_update)
                VALUES (1, '', 1)
            """)

        # Ensure token_refresh_config has a row
        cursor = await db.execute("SELECT COUNT(*) FROM token_refresh_config")
        count = await cursor.fetchone()
        if count[0] == 0:
            await db.execute("""
                INSERT INTO token_refresh_config (id, enabled, refresh_interval_minutes)
                VALUES (1, 1, 120)
            """)

    async def check_and_migrate_db(self, config_dict: dict = None):
        """Check database integrity and perform migrations if needed

        This method is called during upgrade mode to:
        1. Create missing tables (if they don't exist)
        2. Add missing columns to existing tables
        3. Ensure all config tables have default rows

        Args:
            config_dict: Configuration dictionary from setting.toml (optional)
                        Used only to initialize missing config rows with default values.
                        Existing config rows will NOT be overwritten.
        """
        async with self._connect(write=True) as db:
            print("Checking database integrity and performing migrations...")
            await db.execute("PRAGMA journal_mode = WAL")
            await db.execute("PRAGMA synchronous = NORMAL")

            # ========== Step 1: Create missing tables ==========
            # Check and create cache_config table if missing
            if not await self._table_exists(db, "cache_config"):
                print("  ✓ Creating missing table: cache_config")
                await db.execute("""
                    CREATE TABLE cache_config (
                        id INTEGER PRIMARY KEY DEFAULT 1,
                        cache_enabled BOOLEAN DEFAULT 0,
                        cache_timeout INTEGER DEFAULT 7200,
                        cache_base_url TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

            # Check and create proxy_config table if missing
            if not await self._table_exists(db, "proxy_config"):
                print("  ✓ Creating missing table: proxy_config")
                await db.execute("""
                    CREATE TABLE proxy_config (
                        id INTEGER PRIMARY KEY DEFAULT 1,
                        enabled BOOLEAN DEFAULT 0,
                        proxy_url TEXT,
                        media_proxy_enabled BOOLEAN DEFAULT 0,
                        media_proxy_url TEXT,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

            # Check and create call_logic_config table if missing
            if not await self._table_exists(db, "call_logic_config"):
                print("  Creating missing table: call_logic_config")
                await db.execute("""
                    CREATE TABLE call_logic_config (
                        id INTEGER PRIMARY KEY DEFAULT 1,
                        call_mode TEXT DEFAULT 'default',
                        polling_mode_enabled BOOLEAN DEFAULT 0,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

            # Check and create captcha_config table if missing
            if not await self._table_exists(db, "captcha_config"):
                print("  ✓ Creating missing table: captcha_config")
                await db.execute("""
                    CREATE TABLE captcha_config (
                        id INTEGER PRIMARY KEY DEFAULT 1,
                        captcha_method TEXT DEFAULT 'yescaptcha',
                        yescaptcha_api_key TEXT DEFAULT '',
                        yescaptcha_base_url TEXT DEFAULT 'https://api.yescaptcha.com',
                        yescaptcha_task_type TEXT DEFAULT 'RecaptchaV3TaskProxylessM1S9',
                        capmonster_api_key TEXT DEFAULT '',
                        capmonster_base_url TEXT DEFAULT 'https://api.capmonster.cloud',
                        ezcaptcha_api_key TEXT DEFAULT '',
                        ezcaptcha_base_url TEXT DEFAULT 'https://api.ez-captcha.com',
                        capsolver_api_key TEXT DEFAULT '',
                        capsolver_base_url TEXT DEFAULT 'https://api.capsolver.com',
                        captcharun_api_key TEXT DEFAULT '',
                        captcharun_base_url TEXT DEFAULT 'https://api.captcha-run.com',
                        twocaptcha_api_key TEXT DEFAULT '',
                        twocaptcha_base_url TEXT DEFAULT 'https://api.2captcha.com',
                        remote_browser_base_url TEXT DEFAULT '',
                        remote_browser_api_key TEXT DEFAULT '',
                        remote_browser_timeout INTEGER DEFAULT 60,
                        website_key TEXT DEFAULT '6LdsFiUsAAAAAIjVDZcuLhaHiDn5nnHVXVRQGeMV',
                        page_action TEXT DEFAULT 'IMAGE_GENERATION',
                        browser_proxy_enabled BOOLEAN DEFAULT 0,
                        browser_proxy_url TEXT,
                        browser_count INTEGER DEFAULT 1,
                        personal_project_pool_size INTEGER DEFAULT 4,
                        personal_max_resident_tabs INTEGER DEFAULT 5,
                        browser_personal_fresh_restart_every_n_solves INTEGER DEFAULT 10,
                        personal_idle_tab_ttl_seconds INTEGER DEFAULT 600,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

            # Check and create plugin_config table if missing
            if not await self._table_exists(db, "plugin_config"):
                print("  ✓ Creating missing table: plugin_config")
                await db.execute("""
                    CREATE TABLE plugin_config (
                        id INTEGER PRIMARY KEY DEFAULT 1,
                        connection_token TEXT DEFAULT '',
                        auto_enable_on_update BOOLEAN DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

            if not await self._table_exists(db, "token_refresh_config"):
                print("  ✓ Creating missing table: token_refresh_config")
                await db.execute("""
                    CREATE TABLE token_refresh_config (
                        id INTEGER PRIMARY KEY DEFAULT 1,
                        enabled BOOLEAN DEFAULT 1,
                        refresh_interval_minutes INTEGER DEFAULT 120,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

            # ========== Step 2: Add missing columns to existing tables ==========
            # Check and add missing columns to tokens table
            if await self._table_exists(db, "tokens"):
                columns_to_add = [
                    ("at", "TEXT"),  # Access Token
                    ("at_expires", "TIMESTAMP"),  # AT expiration time
                    ("credits", "INTEGER DEFAULT 0"),  # Balance
                    ("user_paygate_tier", "TEXT"),  # User tier
                    ("current_project_id", "TEXT"),  # Current project UUID
                    ("current_project_name", "TEXT"),  # Project name
                    ("image_enabled", "BOOLEAN DEFAULT 1"),
                    ("video_enabled", "BOOLEAN DEFAULT 1"),
                    ("image_concurrency", "INTEGER DEFAULT -1"),
                    ("video_concurrency", "INTEGER DEFAULT -1"),
                    ("captcha_proxy_url", "TEXT"),  # token级打码代理
                    ("extension_route_key", "TEXT"),  # extension 模式路由键
                    ("protocol_mode", "TEXT DEFAULT 'session'"),  # ST 刷新模式
                    ("google_cookies", "TEXT DEFAULT ''"),  # 协议登录 Google Cookies
                    ("login_account", "TEXT DEFAULT ''"),  # 协议登录账号提示
                    ("login_password", "TEXT DEFAULT ''"),  # 预留
                    ("proxy_url", "TEXT DEFAULT ''"),  # 协议刷新代理
                    ("auto_refresh_enabled", "BOOLEAN DEFAULT 1"),
                    ("refresh_interval_minutes", "INTEGER DEFAULT 120"),
                    ("last_st_refresh_at", "TIMESTAMP"),
                    ("last_st_refresh_result", "TEXT DEFAULT ''"),
                    ("adspower_serial", "INTEGER"),  # AdsPower 环境序号
                    ("ban_reason", "TEXT"),  # 禁用原因
                    ("banned_at", "TIMESTAMP"),  # 禁用时间
                ]

                for col_name, col_type in columns_to_add:
                    if not await self._column_exists(db, "tokens", col_name):
                        try:
                            await db.execute(
                                f"ALTER TABLE tokens ADD COLUMN {col_name} {col_type}"
                            )
                            print(f"  ✓ Added column '{col_name}' to tokens table")
                        except Exception as e:
                            print(f"  ✗ Failed to add column '{col_name}': {e}")

            # Check and add missing columns to admin_config table
            if await self._table_exists(db, "admin_config"):
                if not await self._column_exists(
                    db, "admin_config", "error_ban_threshold"
                ):
                    try:
                        await db.execute(
                            "ALTER TABLE admin_config ADD COLUMN error_ban_threshold INTEGER DEFAULT 3"
                        )
                        print(
                            "  ✓ Added column 'error_ban_threshold' to admin_config table"
                        )
                    except Exception as e:
                        print(f"  ✗ Failed to add column 'error_ban_threshold': {e}")

            # Check and add missing columns to proxy_config table
            if await self._table_exists(db, "proxy_config"):
                proxy_columns_to_add = [
                    ("media_proxy_enabled", "BOOLEAN DEFAULT 0"),
                    ("media_proxy_url", "TEXT"),
                ]

                for col_name, col_type in proxy_columns_to_add:
                    if not await self._column_exists(db, "proxy_config", col_name):
                        try:
                            await db.execute(
                                f"ALTER TABLE proxy_config ADD COLUMN {col_name} {col_type}"
                            )
                            print(
                                f"  ✓ Added column '{col_name}' to proxy_config table"
                            )
                        except Exception as e:
                            print(f"  ✗ Failed to add column '{col_name}': {e}")

            # Check and add missing columns to generation_config table
            if await self._table_exists(db, "generation_config"):
                generation_columns_to_add = [
                    ("max_retries", "INTEGER DEFAULT 3"),
                ]

                for col_name, col_type in generation_columns_to_add:
                    if not await self._column_exists(db, "generation_config", col_name):
                        try:
                            await db.execute(
                                f"ALTER TABLE generation_config ADD COLUMN {col_name} {col_type}"
                            )
                            print(
                                f"  ✓ Added column '{col_name}' to generation_config table"
                            )
                        except Exception as e:
                            print(f"  ✗ Failed to add column '{col_name}': {e}")

            # Check and add missing columns to captcha_config table
            if await self._table_exists(db, "captcha_config"):
                captcha_columns_to_add = [
                    ("browser_proxy_enabled", "BOOLEAN DEFAULT 0"),
                    ("browser_proxy_url", "TEXT"),
                    (
                        "yescaptcha_task_type",
                        "TEXT DEFAULT 'RecaptchaV3TaskProxylessM1S9'",
                    ),
                    ("capmonster_api_key", "TEXT DEFAULT ''"),
                    (
                        "capmonster_base_url",
                        "TEXT DEFAULT 'https://api.capmonster.cloud'",
                    ),
                    ("ezcaptcha_api_key", "TEXT DEFAULT ''"),
                    ("ezcaptcha_base_url", "TEXT DEFAULT 'https://api.ez-captcha.com'"),
                    ("capsolver_api_key", "TEXT DEFAULT ''"),
                    ("capsolver_base_url", "TEXT DEFAULT 'https://api.capsolver.com'"),
                    ("twocaptcha_api_key", "TEXT DEFAULT ''"),
                    ("twocaptcha_base_url", "TEXT DEFAULT 'https://api.2captcha.com'"),
                    ("captcharun_api_key", "TEXT DEFAULT ''"),
                    (
                        "captcharun_base_url",
                        "TEXT DEFAULT 'https://api.captcha-run.com'",
                    ),
                    ("browser_count", "INTEGER DEFAULT 1"),
                    ("remote_browser_base_url", "TEXT DEFAULT ''"),
                    ("remote_browser_api_key", "TEXT DEFAULT ''"),
                    ("remote_browser_timeout", "INTEGER DEFAULT 60"),
                ]

                for col_name, col_type in captcha_columns_to_add:
                    if not await self._column_exists(db, "captcha_config", col_name):
                        try:
                            await db.execute(
                                f"ALTER TABLE captcha_config ADD COLUMN {col_name} {col_type}"
                            )
                            print(
                                f"  ✓ Added column '{col_name}' to captcha_config table"
                            )
                        except Exception as e:
                            print(f"  ✗ Failed to add column '{col_name}': {e}")

            # Check and add missing columns to token_stats table
            if await self._table_exists(db, "token_stats"):
                stats_columns_to_add = [
                    ("today_image_count", "INTEGER DEFAULT 0"),
                    ("today_video_count", "INTEGER DEFAULT 0"),
                    ("today_error_count", "INTEGER DEFAULT 0"),
                    ("today_date", "DATE"),
                    ("consecutive_error_count", "INTEGER DEFAULT 0"),  # 🆕 连续错误计数
                ]

                for col_name, col_type in stats_columns_to_add:
                    if not await self._column_exists(db, "token_stats", col_name):
                        try:
                            await db.execute(
                                f"ALTER TABLE token_stats ADD COLUMN {col_name} {col_type}"
                            )
                            print(f"  ✓ Added column '{col_name}' to token_stats table")
                        except Exception as e:
                            print(f"  ✗ Failed to add column '{col_name}': {e}")

            # Check and add missing columns to plugin_config table
            if await self._table_exists(db, "plugin_config"):
                plugin_columns_to_add = [
                    ("auto_enable_on_update", "BOOLEAN DEFAULT 1"),  # 默认开启
                ]

                for col_name, col_type in plugin_columns_to_add:
                    if not await self._column_exists(db, "plugin_config", col_name):
                        try:
                            await db.execute(
                                f"ALTER TABLE plugin_config ADD COLUMN {col_name} {col_type}"
                            )
                            print(
                                f"  ✓ Added column '{col_name}' to plugin_config table"
                            )
                        except Exception as e:
                            print(f"  ✗ Failed to add column '{col_name}': {e}")

            if await self._table_exists(db, "token_refresh_config"):
                token_refresh_columns_to_add = [
                    ("enabled", "BOOLEAN DEFAULT 1"),
                    ("refresh_interval_minutes", "INTEGER DEFAULT 120"),
                    ("updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
                ]

                for col_name, col_type in token_refresh_columns_to_add:
                    if not await self._column_exists(
                        db, "token_refresh_config", col_name
                    ):
                        try:
                            await db.execute(
                                f"ALTER TABLE token_refresh_config ADD COLUMN {col_name} {col_type}"
                            )
                            print(
                                f"  ✓ Added column '{col_name}' to token_refresh_config table"
                            )
                        except Exception as e:
                            print(f"  ✗ Failed to add column '{col_name}': {e}")

            # Check and add missing columns to captcha_config table
            if await self._table_exists(db, "captcha_config"):
                captcha_columns_to_add = [
                    ("personal_project_pool_size", "INTEGER DEFAULT 4"),
                    ("personal_max_resident_tabs", "INTEGER DEFAULT 5"),
                    (
                        "browser_personal_fresh_restart_every_n_solves",
                        "INTEGER DEFAULT 10",
                    ),
                    ("personal_idle_tab_ttl_seconds", "INTEGER DEFAULT 600"),
                ]

                for col_name, col_type in captcha_columns_to_add:
                    if not await self._column_exists(db, "captcha_config", col_name):
                        try:
                            await db.execute(
                                f"ALTER TABLE captcha_config ADD COLUMN {col_name} {col_type}"
                            )
                            print(
                                f"  ✓ Added column '{col_name}' to captcha_config table"
                            )
                        except Exception as e:
                            print(f"  ✗ Failed to add column '{col_name}': {e}")

            # ========== Step 3: Ensure all config tables have default rows ==========
            # Note: This will NOT overwrite existing config rows
            # It only ensures missing rows are created with default values from setting.toml
            await self._ensure_config_rows(db, config_dict=config_dict)
            await self._ensure_account_operation_schema(db)
            await self._ensure_admin_session_schema(db)

            await db.commit()
            print("Database migration check completed.")

    async def init_db(self):
        """Initialize database tables"""
        async with self._connect(write=True) as db:
            await db.execute("PRAGMA journal_mode = WAL")
            await db.execute("PRAGMA synchronous = NORMAL")
            # Tokens table (Flow2API版本)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    st TEXT UNIQUE NOT NULL,
                    at TEXT,
                    at_expires TIMESTAMP,
                    email TEXT NOT NULL,
                    name TEXT,
                    remark TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_used_at TIMESTAMP,
                    use_count INTEGER DEFAULT 0,
                    credits INTEGER DEFAULT 0,
                    user_paygate_tier TEXT,
                    current_project_id TEXT,
                    current_project_name TEXT,
                    image_enabled BOOLEAN DEFAULT 1,
                    video_enabled BOOLEAN DEFAULT 1,
                    image_concurrency INTEGER DEFAULT -1,
                    video_concurrency INTEGER DEFAULT -1,
                    captcha_proxy_url TEXT,
                    extension_route_key TEXT,
                    protocol_mode TEXT DEFAULT 'session',
                    google_cookies TEXT DEFAULT '',
                    login_account TEXT DEFAULT '',
                    login_password TEXT DEFAULT '',
                    proxy_url TEXT DEFAULT '',
                    auto_refresh_enabled BOOLEAN DEFAULT 1,
                    refresh_interval_minutes INTEGER DEFAULT 120,
                    last_st_refresh_at TIMESTAMP,
                    last_st_refresh_result TEXT DEFAULT '',
                    adspower_serial INTEGER,
                    ban_reason TEXT,
                    banned_at TIMESTAMP
                )
            """)

            # Projects table (新增)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT UNIQUE NOT NULL,
                    token_id INTEGER NOT NULL,
                    project_name TEXT NOT NULL,
                    tool_name TEXT DEFAULT 'PINHOLE',
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (token_id) REFERENCES tokens(id)
                )
            """)

            # Token stats table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS token_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id INTEGER NOT NULL,
                    image_count INTEGER DEFAULT 0,
                    video_count INTEGER DEFAULT 0,
                    success_count INTEGER DEFAULT 0,
                    error_count INTEGER DEFAULT 0,
                    last_success_at TIMESTAMP,
                    last_error_at TIMESTAMP,
                    today_image_count INTEGER DEFAULT 0,
                    today_video_count INTEGER DEFAULT 0,
                    today_error_count INTEGER DEFAULT 0,
                    today_date DATE,
                    consecutive_error_count INTEGER DEFAULT 0,
                    FOREIGN KEY (token_id) REFERENCES tokens(id)
                )
            """)

            # Latest failed validation per account. Kept apart from tokens so a failed
            # check never rewrites an account row (credential writers own that row).
            await db.execute("""
                CREATE TABLE IF NOT EXISTS token_health (
                    token_id INTEGER PRIMARY KEY,
                    reason TEXT NOT NULL DEFAULT '',
                    checked_at TIMESTAMP
                )
            """)
            await self._ensure_account_operation_schema(db)

            # Tasks table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT UNIQUE NOT NULL,
                    token_id INTEGER NOT NULL,
                    model TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'processing',
                    progress INTEGER DEFAULT 0,
                    result_urls TEXT,
                    error_message TEXT,
                    scene_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    FOREIGN KEY (token_id) REFERENCES tokens(id)
                )
            """)

            # Request logs table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS request_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_id INTEGER,
                    operation TEXT NOT NULL,
                    request_body TEXT,
                    response_body TEXT,
                    status_code INTEGER NOT NULL,
                    duration FLOAT NOT NULL,
                    status_text TEXT DEFAULT '',
                    progress INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (token_id) REFERENCES tokens(id)
                )
            """)

            # Admin config table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS admin_config (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    username TEXT DEFAULT 'admin',
                    password TEXT DEFAULT 'admin',
                    api_key TEXT DEFAULT 'han1234',
                    error_ban_threshold INTEGER DEFAULT 3,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            await self._ensure_admin_session_schema(db)

            # Proxy config table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS proxy_config (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    enabled BOOLEAN DEFAULT 0,
                    proxy_url TEXT,
                    media_proxy_enabled BOOLEAN DEFAULT 0,
                    media_proxy_url TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Generation config table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS generation_config (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    image_timeout INTEGER DEFAULT 300,
                    video_timeout INTEGER DEFAULT 1500,
                    max_retries INTEGER DEFAULT 3,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Call logic config table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS call_logic_config (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    call_mode TEXT DEFAULT 'default',
                    polling_mode_enabled BOOLEAN DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Cache config table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS cache_config (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    cache_enabled BOOLEAN DEFAULT 0,
                    cache_timeout INTEGER DEFAULT 7200,
                    cache_base_url TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Debug config table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS debug_config (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    enabled BOOLEAN DEFAULT 0,
                    log_requests BOOLEAN DEFAULT 1,
                    log_responses BOOLEAN DEFAULT 1,
                    mask_token BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Captcha config table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS captcha_config (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    captcha_method TEXT DEFAULT 'yescaptcha',
                    yescaptcha_api_key TEXT DEFAULT '',
                    yescaptcha_base_url TEXT DEFAULT 'https://api.yescaptcha.com',
                    yescaptcha_task_type TEXT DEFAULT 'RecaptchaV3TaskProxylessM1S9',
                    capmonster_api_key TEXT DEFAULT '',
                    capmonster_base_url TEXT DEFAULT 'https://api.capmonster.cloud',
                    ezcaptcha_api_key TEXT DEFAULT '',
                    ezcaptcha_base_url TEXT DEFAULT 'https://api.ez-captcha.com',
                    capsolver_api_key TEXT DEFAULT '',
                    capsolver_base_url TEXT DEFAULT 'https://api.capsolver.com',
                    captcharun_api_key TEXT DEFAULT '',
                    captcharun_base_url TEXT DEFAULT 'https://api.captcha-run.com',
                    twocaptcha_api_key TEXT DEFAULT '',
                    twocaptcha_base_url TEXT DEFAULT 'https://api.2captcha.com',
                    remote_browser_base_url TEXT DEFAULT '',
                    remote_browser_api_key TEXT DEFAULT '',
                    remote_browser_timeout INTEGER DEFAULT 60,
                    website_key TEXT DEFAULT '6LdsFiUsAAAAAIjVDZcuLhaHiDn5nnHVXVRQGeMV',
                    page_action TEXT DEFAULT 'IMAGE_GENERATION',

                    browser_proxy_enabled BOOLEAN DEFAULT 0,
                    browser_proxy_url TEXT,
                    browser_count INTEGER DEFAULT 1,
                    personal_project_pool_size INTEGER DEFAULT 4,
                    personal_max_resident_tabs INTEGER DEFAULT 5,
                    browser_personal_fresh_restart_every_n_solves INTEGER DEFAULT 10,
                    personal_idle_tab_ttl_seconds INTEGER DEFAULT 600,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Plugin config table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS plugin_config (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    connection_token TEXT DEFAULT '',
                    auto_enable_on_update BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            await db.execute("""
                CREATE TABLE IF NOT EXISTS token_refresh_config (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    enabled BOOLEAN DEFAULT 1,
                    refresh_interval_minutes INTEGER DEFAULT 120,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_task_id ON tasks(task_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_token_st ON tokens(st)")
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_project_id ON projects(project_id)"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_tokens_email ON tokens(email)"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_tokens_is_active_last_used_at ON tokens(is_active, last_used_at)"
            )

            # Migrate request_logs table if needed
            await self._migrate_request_logs(db)

            # Request logs query indexes (列表按 created_at 排序 / token 过滤)
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_request_logs_created_at ON request_logs(created_at DESC)"
            )
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_request_logs_token_id_created_at ON request_logs(token_id, created_at DESC)"
            )

            # Token stats lookup index
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_token_stats_token_id ON token_stats(token_id)"
            )

            await db.commit()

    async def _migrate_request_logs(self, db):
        """Migrate request_logs table from old schema to new schema"""
        try:
            has_model = await self._column_exists(db, "request_logs", "model")
            has_operation = await self._column_exists(db, "request_logs", "operation")

            if has_model and not has_operation:
                print("?? ?????request_logs???,????...")
                await db.execute("ALTER TABLE request_logs RENAME TO request_logs_old")
                await db.execute("""
                    CREATE TABLE request_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        token_id INTEGER,
                        operation TEXT NOT NULL,
                        request_body TEXT,
                        response_body TEXT,
                        status_code INTEGER NOT NULL,
                        duration FLOAT NOT NULL,
                        status_text TEXT DEFAULT '',
                        progress INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (token_id) REFERENCES tokens(id)
                    )
                """)
                await db.execute("""
                    INSERT INTO request_logs (token_id, operation, request_body, status_code, duration, status_text, progress, created_at, updated_at)
                    SELECT
                        token_id,
                        model as operation,
                        json_object('model', model, 'prompt', substr(prompt, 1, 100)) as request_body,
                        CASE
                            WHEN status = 'completed' THEN 200
                            WHEN status = 'failed' THEN 500
                            ELSE 102
                        END as status_code,
                        response_time as duration,
                        CASE
                            WHEN status = 'completed' THEN 'completed'
                            WHEN status = 'failed' THEN 'failed'
                            ELSE 'processing'
                        END as status_text,
                        CASE
                            WHEN status = 'completed' THEN 100
                            WHEN status = 'failed' THEN 0
                            ELSE 0
                        END as progress,
                        created_at,
                        created_at
                    FROM request_logs_old
                """)
                await db.execute("DROP TABLE request_logs_old")
                print("? request_logs?????")

            if not await self._column_exists(db, "request_logs", "status_text"):
                await db.execute(
                    "ALTER TABLE request_logs ADD COLUMN status_text TEXT DEFAULT ''"
                )
            if not await self._column_exists(db, "request_logs", "progress"):
                await db.execute(
                    "ALTER TABLE request_logs ADD COLUMN progress INTEGER DEFAULT 0"
                )
            if not await self._column_exists(db, "request_logs", "updated_at"):
                await db.execute(
                    "ALTER TABLE request_logs ADD COLUMN updated_at TIMESTAMP"
                )
            await db.execute(
                "UPDATE request_logs SET updated_at = created_at WHERE updated_at IS NULL"
            )
        except Exception as e:
            print(f"?? request_logs?????: {e}")
            # Continue even if migration fails

    async def _ensure_token_identity_available(
        self,
        db,
        *,
        email: Optional[str] = None,
        login_account: Optional[str] = None,
        exclude_token_id: Optional[int] = None,
    ) -> None:
        identities = sorted(
            {
                str(value or "").strip().lower()
                for value in (email, login_account)
                if str(value or "").strip()
            }
        )
        if not identities:
            return
        clauses = []
        params: List[Any] = []
        for identity in identities:
            clauses.append(
                "(email = ? COLLATE NOCASE OR login_account = ? COLLATE NOCASE)"
            )
            params.extend((identity, identity))
        query = "SELECT id FROM tokens WHERE (" + " OR ".join(clauses) + ")"
        if exclude_token_id is not None:
            query += " AND id != ?"
            params.append(exclude_token_id)
        query += " LIMIT 1"
        cursor = await db.execute(query, params)
        if await cursor.fetchone():
            raise ValueError(f"账号已存在: {identities[0]}")

    # Token operations
    async def add_token(self, token: Token) -> int:
        """Add a new token"""
        async with self._connect(write=True) as db:
            await db.execute("BEGIN IMMEDIATE")
            await self._ensure_token_identity_available(
                db,
                email=token.email,
                login_account=token.login_account,
            )
            cursor = await db.execute(
                """
                INSERT INTO tokens (st, at, at_expires, email, name, remark, is_active,
                                   credits, user_paygate_tier, current_project_id, current_project_name,
                                   image_enabled, video_enabled, image_concurrency, video_concurrency,
                                   captcha_proxy_url, extension_route_key,
                                   protocol_mode, google_cookies, login_account, login_password,
                                   proxy_url, auto_refresh_enabled, refresh_interval_minutes,
                                   last_st_refresh_at, last_st_refresh_result, adspower_serial)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    token.st,
                    token.at,
                    token.at_expires,
                    token.email,
                    token.name,
                    token.remark,
                    token.is_active,
                    token.credits,
                    token.user_paygate_tier,
                    token.current_project_id,
                    token.current_project_name,
                    token.image_enabled,
                    token.video_enabled,
                    token.image_concurrency,
                    token.video_concurrency,
                    token.captcha_proxy_url,
                    token.extension_route_key,
                    token.protocol_mode,
                    token.google_cookies,
                    token.login_account,
                    token.login_password,
                    token.proxy_url,
                    token.auto_refresh_enabled,
                    token.refresh_interval_minutes,
                    token.last_st_refresh_at,
                    token.last_st_refresh_result,
                    token.adspower_serial,
                ),
            )
            await db.commit()
            token_id = cursor.lastrowid

            # Create stats entry
            await db.execute(
                """
                INSERT INTO token_stats (token_id) VALUES (?)
            """,
                (token_id,),
            )
            await db.commit()

            return token_id

    async def _ensure_account_operation_schema(self, connection):
        # No foreign key: snapshots and account IDs survive account deletion.
        for statement in ACCOUNT_AUDIT_SCHEMA:
            await connection.execute(statement)

    async def append_account_operation_log(self, event: Dict[str, Any]) -> Optional[int]:
        """Write a normalized audit event without holding the business write lock."""
        event = normalize_stored_account_audit_event(event)
        async with aiosqlite.connect(self.db_path, timeout=1.0) as connection:
            await connection.execute("PRAGMA busy_timeout = 1000")
            await self._ensure_account_operation_schema(connection)
            if event.get("token_id") and (not event.get("token_email") or not event.get("token_serial")):
                if await self._table_exists(connection, "tokens"):
                    cursor = await connection.execute(
                        "SELECT email, login_account, adspower_serial FROM tokens WHERE id=?",
                        (event["token_id"],),
                    )
                    row = await cursor.fetchone()
                    if row:
                        event["token_email"] = event.get("token_email") or sanitize_audit_email(row[0] or row[1])
                        event["token_serial"] = event.get("token_serial") or sanitize_audit_serial(row[2])
            cursor = await connection.execute(ACCOUNT_AUDIT_INSERT, event)
            inserted_id = cursor.lastrowid if cursor.rowcount else None
            if inserted_id is None and event.get("event_key"):
                cursor = await connection.execute(
                    "SELECT id FROM account_operation_logs WHERE event_key=?", (event["event_key"],)
                )
                row = await cursor.fetchone()
                inserted_id = row[0] if row else None
            await connection.commit()
            return inserted_id

    async def get_account_operation_logs(self, *, page: int = 1, page_size: int = 50,
                                         token_id: Optional[int] = None,
                                         operation: Optional[str] = None,
                                         status: Optional[str] = None,
                                         source: Optional[str] = None,
                                         q: Optional[str] = None) -> Dict[str, Any]:
        page, page_size = max(1, int(page)), min(100, max(1, int(page_size)))
        result = {"items": [], "total": 0, "page": page, "page_size": page_size,
                  "operations": sorted(ACCOUNT_AUDIT_OPERATIONS), "sources": sorted(ACCOUNT_AUDIT_SOURCES)}
        conditions, params = [], []
        for field, value in (("token_id", token_id), ("operation", operation), ("status", status), ("source", source)):
            if value is not None and value != "":
                conditions.append(f"{field} = ?")
                params.append(value)
        if q:
            # Search is a literal fragment, not SQL or an unbounded LIKE pattern.
            query = str(q)[:254].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            conditions.append("(token_email LIKE ? ESCAPE '\\' OR token_serial LIKE ? ESCAPE '\\')")
            params.extend((f"%{query}%", f"%{query}%"))
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        async with self._connect() as connection:
            if not await self._table_exists(connection, "account_operation_logs"):
                return result
            connection.row_factory = aiosqlite.Row
            # One read transaction keeps totals and page contents consistent.
            await connection.execute("BEGIN")
            cursor = await connection.execute("SELECT COUNT(*) FROM account_operation_logs" + where, params)
            result["total"] = (await cursor.fetchone())[0]
            cursor = await connection.execute(
                "SELECT * FROM account_operation_logs" + where + " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
                [*params, page_size, (page - 1) * page_size],
            )
            result["items"] = [decode_account_audit_event(row) for row in await cursor.fetchall()]
            return result

    async def get_account_operation_log(self, log_id: int) -> Optional[Dict[str, Any]]:
        async with self._connect() as connection:
            if not await self._table_exists(connection, "account_operation_logs"):
                return None
            connection.row_factory = aiosqlite.Row
            cursor = await connection.execute("SELECT * FROM account_operation_logs WHERE id=?", (log_id,))
            row = await cursor.fetchone()
            return decode_account_audit_event(row) if row else None

    async def get_token(self, token_id: int) -> Optional[Token]:
        """Get token by ID"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM tokens WHERE id = ?", (token_id,))
            row = await cursor.fetchone()
            if row:
                return Token(**dict(row))
            return None

    async def get_token_by_st(self, st: str) -> Optional[Token]:
        """Get token by ST"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM tokens WHERE st = ?", (st,))
            row = await cursor.fetchone()
            if row:
                return Token(**dict(row))
            return None

    async def get_token_by_email(self, email: str) -> Optional[Token]:
        """Get token by email"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """
                SELECT * FROM tokens
                WHERE email = ? COLLATE NOCASE
                   OR login_account = ? COLLATE NOCASE
                ORDER BY id DESC
                LIMIT 1
                """,
                (email, email),
            )
            row = await cursor.fetchone()
            if row:
                return Token(**dict(row))
            return None

    async def get_all_tokens(self) -> List[Token]:
        """Get all tokens"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM tokens ORDER BY created_at DESC")
            rows = await cursor.fetchall()
            return [Token(**dict(row)) for row in rows]

    async def get_all_tokens_with_stats(self) -> List[Dict[str, Any]]:
        """Get all tokens with merged statistics in one query"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            today = self._current_stats_date()
            cursor = await db.execute(
                """
                SELECT
                    t.*,
                    COALESCE(ts.image_count, 0) AS image_count,
                    COALESCE(ts.video_count, 0) AS video_count,
                    COALESCE(ts.error_count, 0) AS error_count,
                    COALESCE(CASE WHEN ts.today_date = ? THEN ts.today_image_count ELSE 0 END, 0) AS today_image_count,
                    COALESCE(CASE WHEN ts.today_date = ? THEN ts.today_video_count ELSE 0 END, 0) AS today_video_count,
                    COALESCE(CASE WHEN ts.today_date = ? THEN ts.today_error_count ELSE 0 END, 0) AS today_error_count,
                    COALESCE(ts.consecutive_error_count, 0) AS consecutive_error_count,
                    ts.last_error_at AS last_error_at,
                    COALESCE(th.reason, '') AS last_health_reason,
                    th.checked_at AS last_health_at
                FROM tokens t
                LEFT JOIN token_stats ts ON ts.token_id = t.id
                LEFT JOIN token_health th ON th.token_id = t.id
                ORDER BY t.created_at DESC
            """,
                (today, today, today),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_dashboard_stats(self) -> Dict[str, int]:
        """Get dashboard counters with aggregated SQL queries"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            today = self._current_stats_date()

            token_cursor = await db.execute("""
                SELECT
                    COUNT(*) AS total_tokens,
                    COALESCE(SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END), 0) AS active_tokens
                FROM tokens
            """)
            token_row = await token_cursor.fetchone()

            stats_cursor = await db.execute(
                """
                SELECT
                    COALESCE(SUM(image_count), 0) AS total_images,
                    COALESCE(SUM(video_count), 0) AS total_videos,
                    COALESCE(SUM(error_count), 0) AS total_errors,
                    COALESCE(SUM(CASE WHEN today_date = ? THEN today_image_count ELSE 0 END), 0) AS today_images,
                    COALESCE(SUM(CASE WHEN today_date = ? THEN today_video_count ELSE 0 END), 0) AS today_videos,
                    COALESCE(SUM(CASE WHEN today_date = ? THEN today_error_count ELSE 0 END), 0) AS today_errors
                FROM token_stats
            """,
                (today, today, today),
            )
            stats_row = await stats_cursor.fetchone()

            token_data = dict(token_row) if token_row else {}
            stats_data = dict(stats_row) if stats_row else {}

            return {
                "total_tokens": int(token_data.get("total_tokens") or 0),
                "active_tokens": int(token_data.get("active_tokens") or 0),
                "total_images": int(stats_data.get("total_images") or 0),
                "total_videos": int(stats_data.get("total_videos") or 0),
                "total_errors": int(stats_data.get("total_errors") or 0),
                "today_images": int(stats_data.get("today_images") or 0),
                "today_videos": int(stats_data.get("today_videos") or 0),
                "today_errors": int(stats_data.get("today_errors") or 0),
            }

    async def get_system_info_stats(self) -> Dict[str, int]:
        """Get lightweight system counters used by admin dashboard"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT
                    COUNT(*) AS total_tokens,
                    COALESCE(SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END), 0) AS active_tokens,
                    COALESCE(SUM(CASE WHEN is_active = 1 THEN credits ELSE 0 END), 0) AS total_credits
                FROM tokens
            """)
            row = await cursor.fetchone()
            data = dict(row) if row else {}
            return {
                "total_tokens": int(data.get("total_tokens") or 0),
                "active_tokens": int(data.get("active_tokens") or 0),
                "total_credits": int(data.get("total_credits") or 0),
            }

    async def get_active_tokens(self) -> List[Token]:
        """Get all active tokens"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM tokens WHERE is_active = 1 ORDER BY last_used_at ASC"
            )
            rows = await cursor.fetchall()
            return [Token(**dict(row)) for row in rows]

    async def update_token(self, token_id: int, **kwargs):
        """Update token fields"""
        async with self._connect(write=True) as db:
            if "email" in kwargs or "login_account" in kwargs:
                await db.execute("BEGIN IMMEDIATE")
                await self._ensure_token_identity_available(
                    db,
                    email=kwargs.get("email"),
                    login_account=kwargs.get("login_account"),
                    exclude_token_id=token_id,
                )
            updates = []
            params = []

            for key, value in kwargs.items():
                updates.append(f"{key} = ?")
                params.append(value)

            if updates:
                params.append(token_id)
                query = f"UPDATE tokens SET {', '.join(updates)} WHERE id = ?"
                await db.execute(query, params)
                await db.commit()

    async def commit_recovered_credentials(
        self, expected: Token, *, google_cookies: str, at: str,
        at_expires: datetime, credits: float, user_paygate_tier: Optional[str] = None,
    ) -> bool:
        """Accept verified credentials only if the bound account is still unchanged."""
        async with self._connect(write=True) as db:
            await db.execute("BEGIN IMMEDIATE")
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM tokens WHERE id = ?", (expected.id,))
            row = await cursor.fetchone()
            current = Token(**dict(row)) if row is not None else None
            ignored = {"created_at", "last_used_at", "use_count", "credits", "user_paygate_tier",
                       "last_st_refresh_at", "last_st_refresh_result"}
            if current is None or any(
                getattr(current, key) != getattr(expected, key)
                for key in Token.model_fields if key not in ignored
            ):
                await db.rollback()
                return False
            await db.execute(
                "UPDATE tokens SET google_cookies = ?, at = ?, at_expires = ?, credits = ?, "
                "user_paygate_tier = ? WHERE id = ?",
                (google_cookies, at, at_expires, credits, user_paygate_tier, expected.id),
            )
            await db.execute("DELETE FROM token_health WHERE token_id = ?", (expected.id,))
            await db.commit()
            return True

    async def update_token_if_cookie_matches(
        self, token_id: int, expected_cookies: str, **kwargs
    ) -> bool:
        """Save a refresh without overwriting a newer account Cookie push."""
        allowed = {
            "google_cookies", "st", "at", "at_expires", "credits",
            "user_paygate_tier", "last_st_refresh_at", "last_st_refresh_result",
        }
        if not kwargs or not set(kwargs).issubset(allowed):
            raise ValueError("Invalid cookie refresh fields")
        async with self._connect(write=True) as db:
            assignments = ", ".join(f"{key} = ?" for key in kwargs)
            cursor = await db.execute(
                f"UPDATE tokens SET {assignments} WHERE id = ? AND COALESCE(google_cookies, '') = ?",
                [*kwargs.values(), token_id, expected_cookies or ""],
            )
            await db.commit()
            return cursor.rowcount > 0

    async def delete_token(self, token_id: int):
        """Delete token and related data"""
        async with self._connect(write=True) as db:
            await db.execute(
                "UPDATE request_logs SET token_id = NULL WHERE token_id = ?",
                (token_id,),
            )
            await db.execute("DELETE FROM tasks WHERE token_id = ?", (token_id,))
            await db.execute("DELETE FROM token_stats WHERE token_id = ?", (token_id,))
            await db.execute("DELETE FROM token_health WHERE token_id = ?", (token_id,))
            await db.execute("DELETE FROM projects WHERE token_id = ?", (token_id,))
            await db.execute("DELETE FROM tokens WHERE id = ?", (token_id,))
            await db.commit()

    async def set_token_health(self, token_id: int, reason: str):
        """Remember the latest failed validation reason (safe category text only)."""
        async with self._connect(write=True) as db:
            await db.execute(
                """
                INSERT INTO token_health (token_id, reason, checked_at)
                VALUES (?, ?, ?)
                ON CONFLICT(token_id) DO UPDATE SET reason = excluded.reason,
                                                   checked_at = excluded.checked_at
                """,
                (token_id, (reason or "")[:200], datetime.now(timezone.utc)),
            )
            await db.commit()

    async def clear_token_health(self, token_id: int):
        """Forget the stored failure after a successful validation or new credentials."""
        async with self._connect(write=True) as db:
            await db.execute("DELETE FROM token_health WHERE token_id = ?", (token_id,))
            await db.commit()

    # Project operations
    async def add_project(self, project: Project) -> int:
        """Add a new project"""
        async with self._connect(write=True) as db:
            cursor = await db.execute(
                """
                INSERT INTO projects (project_id, token_id, project_name, tool_name, is_active)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    project.project_id,
                    project.token_id,
                    project.project_name,
                    project.tool_name,
                    project.is_active,
                ),
            )
            await db.commit()
            return cursor.lastrowid

    async def get_project_by_id(self, project_id: str) -> Optional[Project]:
        """Get project by UUID"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM projects WHERE project_id = ?", (project_id,)
            )
            row = await cursor.fetchone()
            if row:
                return Project(**dict(row))
            return None

    async def get_projects_by_token(self, token_id: int) -> List[Project]:
        """Get all projects for a token"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM projects WHERE token_id = ? ORDER BY created_at DESC",
                (token_id,),
            )
            rows = await cursor.fetchall()
            return [Project(**dict(row)) for row in rows]

    async def delete_project(self, project_id: str):
        """Delete project"""
        async with self._connect(write=True) as db:
            await db.execute("DELETE FROM projects WHERE project_id = ?", (project_id,))
            await db.commit()

    # Task operations
    @staticmethod
    def _json_record(value) -> Dict[str, Any]:
        try:
            parsed = json.loads(value or "null")
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    @classmethod
    def _log_operation_ids(cls, row):
        response = cls._json_record(row["response_body"])
        observed_ids = set()
        for value in (response, response.get("error"), response.get("submission")):
            if isinstance(value, dict):
                observed_ids.update(str(value[key]) for key in ("task_id", "operation_id", "upstream_task_id") if value.get(key))
        return observed_ids

    @classmethod
    def _receipt_log_matches(cls, row, submission_id, account_id, operation_id):
        """Associate a log by durable IDs, never by its prompt or elapsed time."""
        if row["token_id"] not in (None, account_id):
            return False
        request = cls._json_record(row["request_body"])
        recorded_submission = request.get("client_submission_id")
        if recorded_submission and recorded_submission != submission_id:
            return False
        observed_ids = cls._log_operation_ids(row)
        if observed_ids and observed_ids != {operation_id}:
            return False
        return (recorded_submission == submission_id or
                (row["token_id"] == account_id and observed_ids == {operation_id}))

    async def _finish_submission_in_transaction(self, db, receipt) -> Dict[str, int]:
        """Repair task/log projections of an already proven terminal receipt."""
        counts = {"tasks": 0, "logs": 0}
        account_id, operation_id = receipt["account_id"], receipt["operation_id"]
        state = receipt["state"]
        failure = self._json_record(receipt["error"])
        confirmed = state == "confirmed" and bool(receipt["video_url"])
        failed = (state == "failed" and failure.get("code") == "video_generation_failed"
                  and failure.get("submission_pending") is False and failure.get("upstream_accepted") is True
                  and failure.get("operation_id", operation_id) == operation_id)
        if account_id is None or not operation_id or not (confirmed or failed):
            return counts
        status = "completed" if confirmed else "failed"
        message = "" if confirmed else failure.get("message") or "视频生成失败"
        if await self._table_exists(db, "tasks"):
            cursor = await db.execute(
                "UPDATE tasks SET status=?,progress=CASE WHEN ?='completed' THEN 100 ELSE progress END,"
                "result_urls=CASE WHEN ?='completed' THEN ? ELSE result_urls END,error_message=?,"
                "completed_at=COALESCE(completed_at,CURRENT_TIMESTAMP) WHERE task_id=? AND token_id=? "
                "AND status IN ('processing','running','queued','pending','submitted','status_unknown',?)",
                (status, status, status, json.dumps([receipt["video_url"]]) if confirmed else None,
                 message, operation_id, account_id, status),
            )
            counts["tasks"] = cursor.rowcount
        if not await self._table_exists(db, "request_logs"):
            return counts
        cursor = await db.execute(
            "SELECT * FROM request_logs WHERE (token_id=? OR token_id IS NULL) "
            "AND (status_code=102 OR status_text IN ('status_unknown','video_status_unknown'))",
            (account_id,),
        )
        for log in await cursor.fetchall():
            if not self._receipt_log_matches(log, receipt["client_submission_id"], account_id, operation_id):
                continue
            response = ({"status": "success", "task_id": operation_id, "url": receipt["video_url"]}
                        if confirmed else {"error": dict(failure, task_id=operation_id, operation_id=operation_id)})
            previous = self._json_record(log["response_body"])
            if previous:
                response["previous_observation"] = previous.get("previous_observation", previous)
            cursor = await db.execute(
                "UPDATE request_logs SET token_id=?,status_code=?,status_text=?,response_body=?,"
                "progress=CASE WHEN ?='completed' THEN 100 ELSE progress END,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (account_id, 200 if confirmed else 502, status, json.dumps(response, ensure_ascii=False), status, log["id"]),
            )
            counts["logs"] += cursor.rowcount
        return counts

    async def reconcile_submission_terminal(
        self, submission_id: str, *, account_id: int, operation_id: str,
        state: Optional[str] = None, video_url: Optional[str] = None, error: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Atomically settle one exact receipt and its task/log projections.

        Passing no state repairs an existing proven terminal result. Observation
        failures and active upstream results never end the original local worker.
        """
        async with self._connect(write=True) as db:
            await db.execute("BEGIN IMMEDIATE")
            db.row_factory = aiosqlite.Row
            if not await self._table_exists(db, "client_submissions"):
                return {"status": "binding_mismatch", "tasks": 0, "logs": 0}
            cursor = await db.execute("SELECT * FROM client_submissions WHERE client_submission_id=?", (submission_id,))
            row = await cursor.fetchone()
            if row is None or row["account_id"] != account_id or row["operation_id"] != operation_id:
                return {"status": "binding_mismatch", "tasks": 0, "logs": 0}
            if state is not None:
                proven = (state == "confirmed" and bool(video_url)) or (
                    state == "failed" and isinstance(error, dict) and error.get("code") == "video_generation_failed"
                    and error.get("submission_pending") is False and error.get("upstream_accepted") is True
                    and error.get("operation_id") == operation_id)
                if not proven or row["state"] not in ("pending", state):
                    return {"status": "receipt_conflict", "tasks": 0, "logs": 0}
                await db.execute(
                    "UPDATE client_submissions SET state=?,video_url=?,error=?,updated_at=CURRENT_TIMESTAMP "
                    "WHERE client_submission_id=? AND account_id=? AND operation_id=?",
                    (state, video_url if state == "confirmed" else row["video_url"],
                     json.dumps(error, ensure_ascii=False) if error is not None else None,
                     submission_id, account_id, operation_id),
                )
                cursor = await db.execute("SELECT * FROM client_submissions WHERE client_submission_id=?", (submission_id,))
                row = await cursor.fetchone()
            counts = await self._finish_submission_in_transaction(db, row)
            await db.commit()
            return {"status": row["state"], **counts}

    async def reconcile_interrupted_requests(
        self, *, before: datetime, local_workers_stopped: bool = False,
        token_id: Optional[int] = None, task_ids: Optional[List[int]] = None,
    ) -> Dict[str, int]:
        """Close previous-worker requests while retaining every upstream receipt.

        The caller must prove exclusive ownership of the service database, or
        hold the selected account's maintenance lock and prove its workers ended.
        A timestamp alone is not such proof. A task_ids scope never touches other
        requests on the account, including requests created after the cutoff.
        """
        if local_workers_stopped is not True:
            raise ValueError("local_workers_stopped proof is required")
        if not isinstance(before, datetime) or before.tzinfo is None:
            raise ValueError("an aware UTC cutoff is required")
        cutoff = before.astimezone(timezone.utc).isoformat()
        counts = {"tasks_unknown": 0, "logs_closed": 0, "terminal_tasks": 0, "terminal_logs": 0}
        async with self._connect(write=True) as db:
            await db.execute("BEGIN IMMEDIATE")
            db.row_factory = aiosqlite.Row
            conditions, params = ["julianday(created_at)<julianday(?)"], [cutoff]
            if token_id is not None:
                conditions.append("token_id=?")
                params.append(token_id)
            if task_ids is not None:
                if not task_ids:
                    return counts
                conditions.append("id IN (" + ",".join("?" for _ in task_ids) + ")")
                params.extend(task_ids)
            cursor = await db.execute("SELECT * FROM tasks WHERE " + " AND ".join(conditions), params)
            tasks = await cursor.fetchall()
            receipts = []
            if await self._table_exists(db, "client_submissions"):
                cursor = await db.execute("SELECT * FROM client_submissions")
                receipts = await cursor.fetchall()
            by_operation = {}
            by_submission = {row["client_submission_id"]: row for row in receipts}
            for row in receipts:
                by_operation.setdefault((row["account_id"], row["operation_id"]), []).append(row)
            selected_operations = set()
            active = {"processing", "running", "queued", "pending", "submitted", "status_unknown"}
            for task in tasks:
                selected_operations.add((task["token_id"], task["task_id"]))
                matching = by_operation.get((task["token_id"], task["task_id"]), [])
                # Ambiguous receipts and contradictory evidence remain untouched.
                if len(matching) > 1 or (matching and matching[0]["state"] == "refused"):
                    continue
                receipt = matching[0] if matching else None
                if receipt and receipt["state"] in ("confirmed", "failed"):
                    repaired = await self._finish_submission_in_transaction(db, receipt)
                    counts["terminal_tasks"] += repaired["tasks"]
                    counts["terminal_logs"] += repaired["logs"]
                    continue
                if task["status"] not in active:
                    continue
                message = "本地生成进程已结束；原视频结果尚未确认，请查询原提交，勿重复提交"
                cursor = await db.execute(
                    "UPDATE tasks SET status='status_unknown',error_message=?,completed_at=NULL WHERE id=?",
                    (message, task["id"]),
                )
                counts["tasks_unknown"] += cursor.rowcount
            cursor = await db.execute(
                "SELECT * FROM request_logs WHERE status_code=102 AND julianday(created_at)<julianday(?) "
                "AND julianday(COALESCE(updated_at,created_at))<julianday(?)"
                + (" AND token_id=?" if token_id is not None else ""),
                (cutoff, cutoff, token_id) if token_id is not None else (cutoff, cutoff),
            )
            for log in await cursor.fetchall():
                if log["operation"] not in ("generate_image", "generate_video", "extend_video"):
                    continue
                request = self._json_record(log["request_body"])
                receipt = by_submission.get(request.get("client_submission_id"))
                if receipt and log["token_id"] not in (None, receipt["account_id"]):
                    continue
                operation_id = receipt["operation_id"] if receipt else None
                account_id = receipt["account_id"] if receipt else log["token_id"]
                if not operation_id:
                    observed_ids = self._log_operation_ids(log)
                    if len(observed_ids) == 1:
                        observed_id = next(iter(observed_ids))
                        if (account_id, observed_id) in selected_operations:
                            operation_id = observed_id
                if task_ids is not None and (account_id, operation_id) not in selected_operations:
                    continue
                if receipt and operation_id:
                    if not self._receipt_log_matches(log, receipt["client_submission_id"], account_id, operation_id):
                        continue
                    if receipt["state"] in ("confirmed", "failed"):
                        repaired = await self._finish_submission_in_transaction(db, receipt)
                        counts["terminal_logs"] += repaired["logs"]
                        continue
                    if receipt["state"] != "pending":
                        continue
                message = "本地请求因服务进程结束而中断；上游提交结果尚未确认，请勿重复提交"
                error = {"code": "request_interrupted", "message": message, "reason": "service_restarted",
                         "submission_pending": True, "upstream_accepted": None}
                code, status = 503, "failed"  # End the local request, not an unconfirmed upstream generation.
                if operation_id:
                    error.update(code="video_status_unknown", task_id=operation_id, operation_id=operation_id,
                                 upstream_accepted=True)
                    code, status = 502, "video_status_unknown"
                previous = self._json_record(log["response_body"])
                proof = previous.get("error")
                if (not operation_id and isinstance(proof, dict) and proof.get("submission_pending") is False
                        and proof.get("upstream_accepted") is False
                        and proof.get("code") in ("submission_not_started", "submission_rejected", "no_available_token")):
                    error = proof
                    if receipt and receipt["state"] == "pending":
                        await db.execute("UPDATE client_submissions SET state='refused',error=?,updated_at=CURRENT_TIMESTAMP "
                                         "WHERE client_submission_id=? AND operation_id IS NULL AND state='pending'",
                                         (json.dumps(proof, ensure_ascii=False), receipt["client_submission_id"]))
                response = {"error": error}
                if previous:
                    response["previous_observation"] = previous.get("previous_observation", previous)
                cursor = await db.execute(
                    "UPDATE request_logs SET token_id=?,status_code=?,status_text=?,response_body=?,updated_at=CURRENT_TIMESTAMP "
                    "WHERE id=? AND status_code=102",
                    (account_id, code, status, json.dumps(response, ensure_ascii=False), log["id"]),
                )
                counts["logs_closed"] += cursor.rowcount
            await db.commit()
        return counts

    async def create_task(self, task: Task) -> int:
        """Create a new task"""
        async with self._connect(write=True) as db:
            cursor = await db.execute(
                """
                INSERT INTO tasks (task_id, token_id, model, prompt, status, progress, scene_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    task.task_id,
                    task.token_id,
                    task.model,
                    task.prompt,
                    task.status,
                    task.progress,
                    task.scene_id,
                ),
            )
            await db.commit()
            return cursor.lastrowid

    async def get_task(self, task_id: str) -> Optional[Task]:
        """Get task by ID"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
            )
            row = await cursor.fetchone()
            if row:
                task_dict = dict(row)
                # Parse result_urls from JSON
                if task_dict.get("result_urls"):
                    task_dict["result_urls"] = json.loads(task_dict["result_urls"])
                return Task(**task_dict)
            return None

    async def persist_interrupted_video_request(
        self, *, task_id: str, token_id: int, log_id: Optional[int], payload: Dict[str, Any],
        task: Optional[Task] = None, client_submission_id: Optional[str] = None,
        project_id: Optional[str] = None, operations: Optional[List[Dict[str, Any]]] = None,
        progress: int = 45,
    ) -> str:
        """Close a local video observer without changing a confirmed upstream result."""
        operation = operations[0] if operations else {}
        operation_id = (operation.get("operation") or {}).get("name") or operation.get("name")
        if operation_id != task_id or (task is not None and (task.task_id != task_id or task.token_id != token_id)):
            return "binding_mismatch"
        async with self._connect(write=True) as db:
            await db.execute("BEGIN IMMEDIATE")
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,))
            row = await cursor.fetchone()
            if row is not None and row["token_id"] != token_id:
                await db.rollback()
                return "binding_mismatch"
            if row is None and task is None:
                await db.rollback()
                return "binding_mismatch"
            receipt = None
            if client_submission_id and await self._table_exists(db, "client_submissions"):
                cursor = await db.execute("SELECT * FROM client_submissions WHERE client_submission_id=?", (client_submission_id,))
                receipt = await cursor.fetchone()
            exact_receipt = (receipt is not None and receipt["account_id"] == token_id
                             and receipt["operation_id"] == task_id)
            compatible_receipt = (receipt is not None and receipt["account_id"] in (None, token_id)
                                  and receipt["operation_id"] in (None, task_id))
            if compatible_receipt and receipt["state"] == "refused":
                # Refusal and an accepted operation conflict; keep both pieces
                # of evidence intact rather than inventing an unresolved task.
                await db.rollback()
                return "receipt_terminal"
            if row is None and task is not None:
                await db.execute(
                    "INSERT INTO tasks (task_id,token_id,model,prompt,status,progress,scene_id) VALUES (?,?,?,?,?,?,?)",
                    (task_id, token_id, task.model, task.prompt, "status_unknown", progress, task.scene_id),
                )
            status = row["status"] if row is not None else "status_unknown"
            pending_states = {"processing", "running", "queued", "pending", "submitted", "status_unknown"}
            resolved_urls = None
            resolved_error = None
            if exact_receipt and receipt["state"] in {"confirmed", "failed"} and status in pending_states:
                if receipt["state"] == "confirmed" and receipt["video_url"]:
                    resolved_urls = [receipt["video_url"]]
                    status = "completed"
                    await db.execute("UPDATE tasks SET status='completed',progress=100,result_urls=?,error_message='',"
                                     "completed_at=CURRENT_TIMESTAMP WHERE task_id=?",
                                     (json.dumps(resolved_urls), task_id))
                elif receipt["state"] == "failed":
                    try:
                        failure = json.loads(receipt["error"] or "null")
                    except (TypeError, ValueError):
                        failure = None
                    if (not isinstance(failure, dict) or failure.get("code") != "video_generation_failed"
                            or failure.get("submission_pending") is not False or failure.get("upstream_accepted") is not True):
                        await db.rollback()
                        return "receipt_terminal"
                    resolved_error = failure.get("message") or "视频生成失败"
                    status = "failed"
                    await db.execute("UPDATE tasks SET status='failed',error_message=?,completed_at=CURRENT_TIMESTAMP WHERE task_id=?",
                                     (resolved_error, task_id))
                else:
                    await db.rollback()
                    return "receipt_terminal"
            # Unknown future states are left intact rather than assumed active.
            terminal = status not in pending_states
            response = {"error": payload}
            code, text = 502, "video_status_unknown"
            if status in {"completed", "success"}:
                urls = resolved_urls if resolved_urls is not None else json.loads(row["result_urls"] or "[]")
                response = {"status": "success", "task_id": task_id}
                if urls:
                    response["url"] = urls[0]
                code, text, progress = 200, "completed", 100
            elif status in {"failed", "error", "cancelled", "canceled"}:
                response = {"error": {"message": resolved_error or row["error_message"] or "视频生成失败",
                    "code": "video_generation_failed", "task_id": task_id,
                    "submission_pending": False, "upstream_accepted": True}}
                code, text = 502, "failed"
            elif not terminal:
                await db.execute(
                    "UPDATE tasks SET status='status_unknown',error_message=?,completed_at=NULL "
                    "WHERE task_id=? AND status NOT IN ('completed','failed','cancelled','canceled')",
                    (payload["message"], task_id),
                )
                status = "status_unknown"
            if log_id:
                cursor = await db.execute("SELECT response_body FROM request_logs WHERE id=?", (log_id,))
                previous = await cursor.fetchone()
                try:
                    observation = json.loads(previous["response_body"]) if previous else None
                    if isinstance(observation, dict):
                        response["previous_observation"] = observation.get("previous_observation", observation)
                except (TypeError, ValueError):
                    pass
                await db.execute(
                    "UPDATE request_logs SET token_id=?,response_body=?,status_code=?,status_text=?,progress=?,"
                    "updated_at=CURRENT_TIMESTAMP WHERE id=? AND (token_id IS NULL OR token_id=?) "
                    "AND status_text NOT IN ('completed','failed') AND (status_code=102 OR status_text='video_status_unknown')",
                    (token_id, json.dumps(response, ensure_ascii=False), code, text, progress, log_id, token_id),
                )
            if (not terminal and client_submission_id and operations
                    and await self._table_exists(db, "client_submissions")):
                # Fill a receipt interrupted during accepted(), but keep an
                # existing operation snapshot and every terminal receipt intact.
                error = dict(payload, client_submission_id=client_submission_id, operation_id=task_id, account_id=token_id)
                await db.execute(
                    "UPDATE client_submissions SET account_id=COALESCE(account_id,?),operation_id=COALESCE(operation_id,?),"
                    "project_id=COALESCE(project_id,?),operations=COALESCE(operations,?),error=?,updated_at=CURRENT_TIMESTAMP "
                    "WHERE client_submission_id=? AND state='pending' AND (account_id IS NULL OR account_id=?) "
                    "AND (operation_id IS NULL OR operation_id=?)",
                    (token_id, task_id, project_id, json.dumps(operations, ensure_ascii=False),
                     json.dumps(error, ensure_ascii=False), client_submission_id, token_id, task_id),
                )
            await db.commit()
            return status

    async def update_task(self, task_id: str, **kwargs):
        """Update task"""
        async with self._connect(write=True) as db:
            updates = []
            params = []

            for key, value in kwargs.items():
                if value is not None:
                    # Convert list to JSON string for result_urls
                    if key == "result_urls" and isinstance(value, list):
                        value = json.dumps(value)
                    updates.append(f"{key} = ?")
                    params.append(value)

            if updates:
                params.append(task_id)
                query = f"UPDATE tasks SET {', '.join(updates)} WHERE task_id = ?"
                await db.execute(query, params)
                await db.commit()

    # Token stats operations (kept for compatibility, now delegates to specific methods)
    async def increment_token_stats(self, token_id: int, stat_type: str):
        """Increment token statistics (delegates to specific methods)"""
        if stat_type == "image":
            await self.increment_image_count(token_id)
        elif stat_type == "video":
            await self.increment_video_count(token_id)
        elif stat_type == "error":
            await self.increment_error_count(token_id)

    async def get_token_stats(self, token_id: int) -> Optional[TokenStats]:
        """Get token statistics"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM token_stats WHERE token_id = ?", (token_id,)
            )
            row = await cursor.fetchone()
            if row:
                return TokenStats(**dict(row))
            return None

    async def increment_image_count(self, token_id: int):
        """Increment image generation count with daily reset"""
        async with self._connect(write=True) as db:
            today = self._current_stats_date()
            # Get current stats
            cursor = await db.execute(
                "SELECT today_date FROM token_stats WHERE token_id = ?", (token_id,)
            )
            row = await cursor.fetchone()

            # If date changed, reset all daily counters before recording today's image usage.
            if row and row[0] != today:
                await db.execute(
                    """
                    UPDATE token_stats
                    SET image_count = image_count + 1,
                        today_image_count = 1,
                        today_video_count = 0,
                        today_error_count = 0,
                        today_date = ?
                    WHERE token_id = ?
                """,
                    (today, token_id),
                )
            else:
                # Same day, just increment both
                await db.execute(
                    """
                    UPDATE token_stats
                    SET image_count = image_count + 1,
                        today_image_count = today_image_count + 1,
                        today_date = ?
                    WHERE token_id = ?
                """,
                    (today, token_id),
                )
            await db.commit()

    async def increment_video_count(self, token_id: int):
        """Increment video generation count with daily reset"""
        async with self._connect(write=True) as db:
            today = self._current_stats_date()
            # Get current stats
            cursor = await db.execute(
                "SELECT today_date FROM token_stats WHERE token_id = ?", (token_id,)
            )
            row = await cursor.fetchone()

            # If date changed, reset all daily counters before recording today's video usage.
            if row and row[0] != today:
                await db.execute(
                    """
                    UPDATE token_stats
                    SET video_count = video_count + 1,
                        today_image_count = 0,
                        today_video_count = 1,
                        today_error_count = 0,
                        today_date = ?
                    WHERE token_id = ?
                """,
                    (today, token_id),
                )
            else:
                # Same day, just increment both
                await db.execute(
                    """
                    UPDATE token_stats
                    SET video_count = video_count + 1,
                        today_video_count = today_video_count + 1,
                        today_date = ?
                    WHERE token_id = ?
                """,
                    (today, token_id),
                )
            await db.commit()

    async def increment_error_count(self, token_id: int):
        """Increment error count with daily reset

        Updates two counters:
        - error_count: Historical total errors (never reset)
        - consecutive_error_count: Consecutive errors (reset on success/enable)
        - today_error_count: Today's errors (reset on date change)
        """
        async with self._connect(write=True) as db:
            today = self._current_stats_date()
            # Get current stats
            cursor = await db.execute(
                "SELECT today_date FROM token_stats WHERE token_id = ?", (token_id,)
            )
            row = await cursor.fetchone()

            # If date changed, reset all daily counters before recording today's error.
            if row and row[0] != today:
                await db.execute(
                    """
                    UPDATE token_stats
                    SET error_count = error_count + 1,
                        consecutive_error_count = consecutive_error_count + 1,
                        today_image_count = 0,
                        today_video_count = 0,
                        today_error_count = 1,
                        today_date = ?,
                        last_error_at = CURRENT_TIMESTAMP
                    WHERE token_id = ?
                """,
                    (today, token_id),
                )
            else:
                # Same day, just increment all counters
                await db.execute(
                    """
                    UPDATE token_stats
                    SET error_count = error_count + 1,
                        consecutive_error_count = consecutive_error_count + 1,
                        today_error_count = today_error_count + 1,
                        today_date = ?,
                        last_error_at = CURRENT_TIMESTAMP
                    WHERE token_id = ?
                """,
                    (today, token_id),
                )
            await db.commit()

    async def reset_error_count(self, token_id: int):
        """Reset consecutive error count (only reset consecutive_error_count, keep error_count and today_error_count)

        This is called when:
        - Token is manually enabled by admin
        - Request succeeds (resets consecutive error counter)

        Note: error_count (total historical errors) is NEVER reset
        """
        async with self._connect(write=True) as db:
            await db.execute(
                """
                UPDATE token_stats SET consecutive_error_count = 0 WHERE token_id = ?
            """,
                (token_id,),
            )
            await db.commit()

    # Admin sessions
    async def _ensure_admin_session_schema(self, db):
        """Persist only hashed browser credentials and their fixed UTC expiry."""
        await db.execute("""
            CREATE TABLE IF NOT EXISTS admin_sessions (
                token_hash TEXT PRIMARY KEY NOT NULL,
                credentials_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions(expires_at)"
        )

    @staticmethod
    def _admin_session_token_hash(token: str) -> Optional[str]:
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 1024
            or not token.isascii()
            or any(not character.isprintable() or character.isspace() for character in token)
        ):
            return None
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _admin_credentials_hash(username: str, password: str) -> str:
        credentials = json.dumps([username, password], ensure_ascii=False)
        return hashlib.sha256(credentials.encode("utf-8")).hexdigest()

    async def create_admin_session(
        self,
        token: str,
        ttl_seconds: int = 30 * 24 * 60 * 60,
        *,
        expected_credentials: Optional[tuple[str, str]] = None,
    ) -> datetime:
        """Save an opaque session, returning its UTC expiration time."""
        token_hash = self._admin_session_token_hash(token)
        if token_hash is None:
            raise ValueError("Invalid admin session token")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
            raise ValueError("Admin session lifetime must be a positive number of seconds")
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl_seconds)
        async with self._connect(write=True) as db:
            # Serialize credential reads and session insertion across workers.
            await db.execute("BEGIN IMMEDIATE")
            cursor = await db.execute(
                "SELECT username, password FROM admin_config WHERE id = 1"
            )
            credentials = await cursor.fetchone()
            if credentials is None:
                raise RuntimeError("Admin configuration is not initialized")
            credentials_hash = self._admin_credentials_hash(*credentials)
            if expected_credentials is not None and not hmac.compare_digest(
                credentials_hash, self._admin_credentials_hash(*expected_credentials)
            ):
                raise ValueError("Admin credentials changed before session creation")
            await db.execute(
                "DELETE FROM admin_sessions WHERE expires_at <= ? OR credentials_hash != ?",
                (now.timestamp(), credentials_hash),
            )
            # A fresh opaque token is required; live collisions are rejected.
            await db.execute(
                """
                INSERT INTO admin_sessions (token_hash, credentials_hash, created_at, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (token_hash, credentials_hash, now.timestamp(), expires_at.timestamp()),
            )
            await db.commit()
        return expires_at

    async def is_admin_session_valid(self, token: str) -> bool:
        """Validate committed state directly so revocation applies to every worker."""
        token_hash = self._admin_session_token_hash(token)
        if token_hash is None:
            return False
        async with self._connect() as db:
            cursor = await db.execute(
                """
                SELECT sessions.credentials_hash, admin.username, admin.password
                FROM admin_sessions AS sessions
                JOIN admin_config AS admin ON admin.id = 1
                WHERE sessions.token_hash = ? AND sessions.expires_at > ?
                """,
                (token_hash, datetime.now(timezone.utc).timestamp()),
            )
            row = await cursor.fetchone()
        if row is None:
            return False
        return hmac.compare_digest(row[0], self._admin_credentials_hash(row[1], row[2]))

    async def revoke_admin_session(self, token: str):
        """Revoke one browser session; malformed and unknown tokens are harmless."""
        token_hash = self._admin_session_token_hash(token)
        if token_hash is None:
            return
        async with self._connect(write=True) as db:
            await db.execute("DELETE FROM admin_sessions WHERE token_hash = ?", (token_hash,))
            await db.commit()

    async def revoke_all_admin_sessions(self):
        """Revoke all browser sessions without an in-memory validation cache."""
        async with self._connect(write=True) as db:
            await db.execute("DELETE FROM admin_sessions")
            await db.commit()

    # Config operations
    async def get_admin_config(self) -> Optional[AdminConfig]:
        """Get admin configuration"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM admin_config WHERE id = 1")
            row = await cursor.fetchone()
            if row:
                return AdminConfig(**dict(row))
            return None

    async def update_admin_config(self, **kwargs):
        """Update admin configuration"""
        async with self._connect(write=True) as db:
            await db.execute("BEGIN IMMEDIATE")
            cursor = await db.execute(
                "SELECT username, password FROM admin_config WHERE id = 1"
            )
            previous_credentials = await cursor.fetchone()
            updates = []
            params = []

            for key, value in kwargs.items():
                if value is not None:
                    updates.append(f"{key} = ?")
                    params.append(value)

            if updates:
                updates.append("updated_at = CURRENT_TIMESTAMP")
                query = f"UPDATE admin_config SET {', '.join(updates)} WHERE id = 1"
                await db.execute(query, params)
                if previous_credentials and any(
                    kwargs.get(key) is not None and kwargs[key] != previous_credentials[index]
                    for index, key in enumerate(("username", "password"))
                ):
                    await db.execute("DELETE FROM admin_sessions")
                await db.commit()

    async def get_proxy_config(self) -> Optional[ProxyConfig]:
        """Get proxy configuration"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM proxy_config WHERE id = 1")
            row = await cursor.fetchone()
            if row:
                return ProxyConfig(**dict(row))
            return None

    async def update_proxy_config(
        self,
        enabled: bool,
        proxy_url: Optional[str] = None,
        media_proxy_enabled: Optional[bool] = None,
        media_proxy_url: Optional[str] = None,
    ):
        """Update proxy configuration"""
        async with self._connect(write=True) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM proxy_config WHERE id = 1")
            row = await cursor.fetchone()

            if row:
                current = dict(row)
                new_media_proxy_enabled = (
                    media_proxy_enabled
                    if media_proxy_enabled is not None
                    else current.get("media_proxy_enabled", False)
                )
                new_media_proxy_url = (
                    media_proxy_url
                    if media_proxy_url is not None
                    else current.get("media_proxy_url")
                )

                await db.execute(
                    """
                    UPDATE proxy_config
                    SET enabled = ?, proxy_url = ?,
                        media_proxy_enabled = ?, media_proxy_url = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = 1
                """,
                    (enabled, proxy_url, new_media_proxy_enabled, new_media_proxy_url),
                )
            else:
                new_media_proxy_enabled = (
                    media_proxy_enabled if media_proxy_enabled is not None else False
                )
                new_media_proxy_url = media_proxy_url
                await db.execute(
                    """
                    INSERT INTO proxy_config (id, enabled, proxy_url, media_proxy_enabled, media_proxy_url)
                    VALUES (1, ?, ?, ?, ?)
                """,
                    (enabled, proxy_url, new_media_proxy_enabled, new_media_proxy_url),
                )

            await db.commit()

    async def get_generation_config(self) -> Optional[GenerationConfig]:
        """Get generation configuration"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM generation_config WHERE id = 1")
            row = await cursor.fetchone()
            if row:
                return GenerationConfig(**dict(row))
            return None

    async def update_generation_config(
        self,
        image_timeout: Optional[int] = None,
        video_timeout: Optional[int] = None,
        max_retries: Optional[int] = None,
    ):
        """Update generation configuration"""
        async with self._connect(write=True) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM generation_config WHERE id = 1")
            row = await cursor.fetchone()
            current = dict(row) if row else {}

            normalized_image_timeout = (
                image_timeout
                if image_timeout is not None
                else current.get("image_timeout", 300)
            )
            normalized_video_timeout = (
                video_timeout
                if video_timeout is not None
                else current.get("video_timeout", 1500)
            )
            try:
                normalized_max_retries = (
                    max(1, int(max_retries))
                    if max_retries is not None
                    else max(1, int(current.get("max_retries", 3)))
                )
            except Exception:
                normalized_max_retries = 3

            if row:
                await db.execute(
                    """
                    UPDATE generation_config
                    SET image_timeout = ?, video_timeout = ?, max_retries = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = 1
                """,
                    (
                        normalized_image_timeout,
                        normalized_video_timeout,
                        normalized_max_retries,
                    ),
                )
            else:
                await db.execute(
                    """
                    INSERT INTO generation_config (id, image_timeout, video_timeout, max_retries)
                    VALUES (1, ?, ?, ?)
                """,
                    (
                        normalized_image_timeout,
                        normalized_video_timeout,
                        normalized_max_retries,
                    ),
                )
            await db.commit()

    async def get_call_logic_config(self) -> CallLogicConfig:
        """Get token call logic configuration."""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM call_logic_config WHERE id = 1")
            row = await cursor.fetchone()
            if row:
                row_dict = dict(row)
                mode = row_dict.get("call_mode")
                if mode not in ("default", "polling"):
                    row_dict["call_mode"] = (
                        "polling" if row_dict.get("polling_mode_enabled") else "default"
                    )
                return CallLogicConfig(**row_dict)
            return CallLogicConfig(call_mode="default", polling_mode_enabled=False)

    async def update_call_logic_config(self, call_mode: str):
        """Update token call logic configuration."""
        normalized = "polling" if call_mode == "polling" else "default"
        polling_mode_enabled = normalized == "polling"
        async with self._connect(write=True) as db:
            await db.execute(
                """
                INSERT OR REPLACE INTO call_logic_config (id, call_mode, polling_mode_enabled, updated_at)
                VALUES (1, ?, ?, CURRENT_TIMESTAMP)
            """,
                (normalized, polling_mode_enabled),
            )
            await db.commit()

    # Request log operations
    async def add_request_log(self, log: RequestLog) -> int:
        """Add request log and return log id"""
        async with self._connect(write=True) as db:
            cursor = await db.execute(
                """
                INSERT INTO request_logs (token_id, operation, request_body, response_body, status_code, duration, status_text, progress)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                log.token_id,
                log.operation,
                log.request_body,
                log.response_body,
                log.status_code,
                log.duration,
                log.status_text or "",
                log.progress,
                ),
            )
            await db.commit()
            return cursor.lastrowid

    async def update_request_log(self, log_id: int, **kwargs):
        """Update an existing request log row."""
        if not kwargs:
            return

        allowed_fields = {
            "token_id",
            "operation",
            "request_body",
            "response_body",
            "status_code",
            "duration",
            "status_text",
            "progress",
        }
        update_fields = {
            key: value for key, value in kwargs.items() if key in allowed_fields
        }
        if not update_fields:
            return

        clauses = []
        values = []
        for key, value in update_fields.items():
            clauses.append(f"{key} = ?")
            values.append(value)
        clauses.append("updated_at = CURRENT_TIMESTAMP")
        values.append(log_id)

        async with self._connect(write=True) as db:
            await db.execute(
                f"UPDATE request_logs SET {', '.join(clauses)} WHERE id = ?",
                values,
            )
            await db.commit()

    async def get_logs(
        self,
        limit: int = 100,
        token_id: Optional[int] = None,
        include_payload: bool = False,
    ):
        """Get request logs with token info, optionally including payload fields"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            payload_columns = (
                "rl.request_body, rl.response_body," if include_payload else ""
            )
            response_excerpt_column = "substr(COALESCE(rl.response_body, ''), 1, 2048) as response_body_excerpt,"
            has_status_text = await self._column_exists(
                db, "request_logs", "status_text"
            )
            has_progress = await self._column_exists(db, "request_logs", "progress")
            has_updated_at = await self._column_exists(db, "request_logs", "updated_at")
            status_text_column = (
                "rl.status_text," if has_status_text else "'' as status_text,"
            )
            progress_column = "rl.progress," if has_progress else "0 as progress,"
            updated_at_column = (
                "rl.updated_at," if has_updated_at else "rl.created_at as updated_at,"
            )

            if token_id:
                cursor = await db.execute(
                    f"""
                    SELECT
                        rl.id,
                        rl.token_id,
                        rl.operation,
                        {payload_columns}
                        {response_excerpt_column}
                        rl.status_code,
                        rl.duration,
                        {status_text_column}
                        {progress_column}
                        rl.created_at,
                        {updated_at_column}
                        t.email as token_email,
                        t.name as token_username
                    FROM request_logs rl
                    LEFT JOIN tokens t ON rl.token_id = t.id
                    WHERE rl.token_id = ?
                    ORDER BY rl.created_at DESC
                    LIMIT ?
                """,
                    (token_id, limit),
                )
            else:
                cursor = await db.execute(
                    f"""
                    SELECT
                        rl.id,
                        rl.token_id,
                        rl.operation,
                        {payload_columns}
                        {response_excerpt_column}
                        rl.status_code,
                        rl.duration,
                        {status_text_column}
                        {progress_column}
                        rl.created_at,
                        {updated_at_column}
                        t.email as token_email,
                        t.name as token_username
                    FROM request_logs rl
                    LEFT JOIN tokens t ON rl.token_id = t.id
                    ORDER BY rl.created_at DESC
                    LIMIT ?
                """,
                    (limit,),
                )

            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def get_log_detail(self, log_id: int) -> Optional[Dict[str, Any]]:
        """Get single request log detail including payload fields"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            has_status_text = await self._column_exists(
                db, "request_logs", "status_text"
            )
            has_progress = await self._column_exists(db, "request_logs", "progress")
            has_updated_at = await self._column_exists(db, "request_logs", "updated_at")
            status_text_column = (
                "rl.status_text," if has_status_text else "'' as status_text,"
            )
            progress_column = "rl.progress," if has_progress else "0 as progress,"
            updated_at_column = (
                "rl.updated_at," if has_updated_at else "rl.created_at as updated_at,"
            )
            cursor = await db.execute(
                f"""
                SELECT
                    rl.id,
                    rl.token_id,
                    rl.operation,
                    rl.request_body,
                    rl.response_body,
                    rl.status_code,
                    rl.duration,
                    {status_text_column}
                    {progress_column}
                    rl.created_at,
                    {updated_at_column}
                    t.email as token_email,
                    t.name as token_username
                FROM request_logs rl
                LEFT JOIN tokens t ON rl.token_id = t.id
                WHERE rl.id = ?
                LIMIT 1
            """,
                (log_id,),
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def clear_all_logs(self):
        """Clear all request logs"""
        async with self._connect(write=True) as db:
            await db.execute("DELETE FROM request_logs")
            await db.commit()

    async def init_config_from_toml(
        self, config_dict: dict, is_first_startup: bool = True
    ):
        """
        Initialize database configuration from setting.toml

        Args:
            config_dict: Configuration dictionary from setting.toml
            is_first_startup: If True, initialize all config rows from setting.toml.
                            If False (upgrade mode), only ensure missing config rows exist with default values.
        """
        async with self._connect(write=True) as db:
            if is_first_startup:
                # First startup: Initialize all config tables with values from setting.toml
                await self._ensure_config_rows(db, config_dict)
            else:
                # Upgrade mode: Only ensure missing config rows exist (with default values, not from TOML)
                await self._ensure_config_rows(db, config_dict=None)

            await db.commit()

    async def reload_config_to_memory(self):
        """
        Reload all configuration from database to in-memory Config instance.
        This should be called after any configuration update to ensure hot-reload.

        Includes:
        - Admin config (username, password, api_key)
        - Cache config (enabled, timeout, base_url)
        - Generation config (image_timeout, video_timeout)
        - Proxy config will be handled by ProxyManager
        """
        from .config import config

        # Reload admin config
        admin_config = await self.get_admin_config()
        if admin_config:
            config.set_admin_username_from_db(admin_config.username)
            config.set_admin_password_from_db(admin_config.password)
            config.api_key = admin_config.api_key

        # Reload cache config
        cache_config = await self.get_cache_config()
        if cache_config:
            config.set_cache_enabled(cache_config.cache_enabled)
            config.set_cache_timeout(cache_config.cache_timeout)
            config.set_cache_base_url(cache_config.cache_base_url or "")

        # Reload generation config
        generation_config = await self.get_generation_config()
        if generation_config:
            config.set_image_timeout(generation_config.image_timeout)
            config.set_video_timeout(generation_config.video_timeout)
            config.set_flow_max_retries(generation_config.max_retries)

        # Reload call logic config
        call_logic_config = await self.get_call_logic_config()
        if call_logic_config:
            config.set_call_logic_mode(call_logic_config.call_mode)

        # Reload debug config
        debug_config = await self.get_debug_config()
        if debug_config:
            config.set_debug_enabled(debug_config.enabled)

        # Reload captcha config
        captcha_config = await self.get_captcha_config()
        if captcha_config:
            config.set_captcha_method(captcha_config.captcha_method)
            config.set_yescaptcha_api_key(captcha_config.yescaptcha_api_key)
            config.set_yescaptcha_base_url(captcha_config.yescaptcha_base_url)
            config.set_yescaptcha_task_type(captcha_config.yescaptcha_task_type)
            config.set_capmonster_api_key(captcha_config.capmonster_api_key)
            config.set_capmonster_base_url(captcha_config.capmonster_base_url)
            config.set_ezcaptcha_api_key(captcha_config.ezcaptcha_api_key)
            config.set_ezcaptcha_base_url(captcha_config.ezcaptcha_base_url)
            config.set_capsolver_api_key(captcha_config.capsolver_api_key)
            config.set_capsolver_base_url(captcha_config.capsolver_base_url)
            config.set_captcharun_api_key(captcha_config.captcharun_api_key)
            config.set_captcharun_base_url(captcha_config.captcharun_base_url)
            config.set_twocaptcha_api_key(captcha_config.twocaptcha_api_key)
            config.set_twocaptcha_base_url(captcha_config.twocaptcha_base_url)
            config.set_remote_browser_base_url(captcha_config.remote_browser_base_url)
            config.set_remote_browser_api_key(captcha_config.remote_browser_api_key)
            config.set_remote_browser_timeout(captcha_config.remote_browser_timeout)
            config.set_browser_count(captcha_config.browser_count)
            config.set_personal_project_pool_size(
                captcha_config.personal_project_pool_size
            )
            config.set_personal_max_resident_tabs(
                captcha_config.personal_max_resident_tabs
            )
            config.set_browser_personal_fresh_restart_every_n_solves(
                captcha_config.browser_personal_fresh_restart_every_n_solves
            )
            config.set_personal_idle_tab_ttl_seconds(
                captcha_config.personal_idle_tab_ttl_seconds
            )

    # Cache config operations
    async def get_cache_config(self) -> CacheConfig:
        """Get cache configuration"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM cache_config WHERE id = 1")
            row = await cursor.fetchone()
            if row:
                return CacheConfig(**dict(row))
            # Return default if not found
            return CacheConfig(cache_enabled=False, cache_timeout=7200)

    async def update_cache_config(
        self, enabled: bool = None, timeout: int = None, base_url: Optional[str] = None
    ):
        """Update cache configuration"""
        async with self._connect(write=True) as db:
            db.row_factory = aiosqlite.Row
            # Get current values
            cursor = await db.execute("SELECT * FROM cache_config WHERE id = 1")
            row = await cursor.fetchone()

            if row:
                current = dict(row)
                # Use new values if provided, otherwise keep existing
                new_enabled = (
                    enabled
                    if enabled is not None
                    else current.get("cache_enabled", False)
                )
                new_timeout = (
                    timeout
                    if timeout is not None
                    else current.get("cache_timeout", 7200)
                )
                new_base_url = (
                    base_url if base_url is not None else current.get("cache_base_url")
                )

                # If base_url is explicitly set to empty string, treat as None
                if base_url == "":
                    new_base_url = None

                await db.execute(
                    """
                    UPDATE cache_config
                    SET cache_enabled = ?, cache_timeout = ?, cache_base_url = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = 1
                """,
                    (new_enabled, new_timeout, new_base_url),
                )
            else:
                # Insert default row if not exists
                new_enabled = enabled if enabled is not None else False
                new_timeout = timeout if timeout is not None else 7200
                new_base_url = base_url if base_url is not None else None

                await db.execute(
                    """
                    INSERT INTO cache_config (id, cache_enabled, cache_timeout, cache_base_url)
                    VALUES (1, ?, ?, ?)
                """,
                    (new_enabled, new_timeout, new_base_url),
                )

            await db.commit()

    # Debug config operations
    async def get_debug_config(self) -> "DebugConfig":
        """Get debug configuration"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM debug_config WHERE id = 1")
            row = await cursor.fetchone()
            if row:
                return DebugConfig(**dict(row))
            # Return default if not found
            return DebugConfig(
                enabled=False, log_requests=True, log_responses=True, mask_token=True
            )

    async def update_debug_config(
        self,
        enabled: bool = None,
        log_requests: bool = None,
        log_responses: bool = None,
        mask_token: bool = None,
    ):
        """Update debug configuration"""
        async with self._connect(write=True) as db:
            db.row_factory = aiosqlite.Row
            # Get current values
            cursor = await db.execute("SELECT * FROM debug_config WHERE id = 1")
            row = await cursor.fetchone()

            if row:
                current = dict(row)
                # Use new values if provided, otherwise keep existing
                new_enabled = (
                    enabled if enabled is not None else current.get("enabled", False)
                )
                new_log_requests = (
                    log_requests
                    if log_requests is not None
                    else current.get("log_requests", True)
                )
                new_log_responses = (
                    log_responses
                    if log_responses is not None
                    else current.get("log_responses", True)
                )
                new_mask_token = (
                    mask_token
                    if mask_token is not None
                    else current.get("mask_token", True)
                )

                await db.execute(
                    """
                    UPDATE debug_config
                    SET enabled = ?, log_requests = ?, log_responses = ?, mask_token = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = 1
                """,
                    (new_enabled, new_log_requests, new_log_responses, new_mask_token),
                )
            else:
                # Insert default row if not exists
                new_enabled = enabled if enabled is not None else False
                new_log_requests = log_requests if log_requests is not None else True
                new_log_responses = log_responses if log_responses is not None else True
                new_mask_token = mask_token if mask_token is not None else True

                await db.execute(
                    """
                    INSERT INTO debug_config (id, enabled, log_requests, log_responses, mask_token)
                    VALUES (1, ?, ?, ?, ?)
                """,
                    (new_enabled, new_log_requests, new_log_responses, new_mask_token),
                )

            await db.commit()

    # Captcha config operations
    async def get_captcha_config(self) -> CaptchaConfig:
        """Get captcha configuration"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM captcha_config WHERE id = 1")
            row = await cursor.fetchone()
            if row:
                return CaptchaConfig(**dict(row))
            return CaptchaConfig()

    async def update_captcha_config(
        self,
        captcha_method: str = None,
        yescaptcha_api_key: str = None,
        yescaptcha_base_url: str = None,
        yescaptcha_task_type: str = None,
        capmonster_api_key: str = None,
        capmonster_base_url: str = None,
        ezcaptcha_api_key: str = None,
        ezcaptcha_base_url: str = None,
        capsolver_api_key: str = None,
        capsolver_base_url: str = None,
        captcharun_api_key: str = None,
        captcharun_base_url: str = None,
        twocaptcha_api_key: str = None,
        twocaptcha_base_url: str = None,
        remote_browser_base_url: str = None,
        remote_browser_api_key: str = None,
        remote_browser_timeout: int = None,
        browser_proxy_enabled: bool = None,
        browser_proxy_url: str = None,
        browser_count: int = None,
        personal_project_pool_size: int = None,
        personal_max_resident_tabs: int = None,
        browser_personal_fresh_restart_every_n_solves: int = None,
        personal_idle_tab_ttl_seconds: int = None,
    ):
        """Update captcha configuration"""
        async with self._connect(write=True) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM captcha_config WHERE id = 1")
            row = await cursor.fetchone()

            if row:
                current = dict(row)
                new_method = (
                    captcha_method
                    if captcha_method is not None
                    else current.get("captcha_method", "yescaptcha")
                )
                new_yes_key = (
                    yescaptcha_api_key
                    if yescaptcha_api_key is not None
                    else current.get("yescaptcha_api_key", "")
                )
                new_yes_url = (
                    yescaptcha_base_url
                    if yescaptcha_base_url is not None
                    else current.get(
                        "yescaptcha_base_url", "https://api.yescaptcha.com"
                    )
                )
                new_yes_task_type = normalize_yescaptcha_task_type(
                    yescaptcha_task_type
                    if yescaptcha_task_type is not None
                    else current.get("yescaptcha_task_type")
                )
                new_cap_key = (
                    capmonster_api_key
                    if capmonster_api_key is not None
                    else current.get("capmonster_api_key", "")
                )
                new_cap_url = (
                    capmonster_base_url
                    if capmonster_base_url is not None
                    else current.get(
                        "capmonster_base_url", "https://api.capmonster.cloud"
                    )
                )
                new_ez_key = (
                    ezcaptcha_api_key
                    if ezcaptcha_api_key is not None
                    else current.get("ezcaptcha_api_key", "")
                )
                new_ez_url = (
                    ezcaptcha_base_url
                    if ezcaptcha_base_url is not None
                    else current.get("ezcaptcha_base_url", "https://api.ez-captcha.com")
                )
                new_cs_key = (
                    capsolver_api_key
                    if capsolver_api_key is not None
                    else current.get("capsolver_api_key", "")
                )
                new_cs_url = (
                    capsolver_base_url
                    if capsolver_base_url is not None
                    else current.get("capsolver_base_url", "https://api.capsolver.com")
                )
                new_run_key = (
                    captcharun_api_key
                    if captcharun_api_key is not None
                    else current.get("captcharun_api_key", "")
                )
                new_run_url = (
                    captcharun_base_url
                    if captcharun_base_url is not None
                    else current.get(
                        "captcharun_base_url", "https://api.captcha-run.com"
                    )
                )
                new_remote_base_url = (
                    remote_browser_base_url
                    if remote_browser_base_url is not None
                    else current.get("remote_browser_base_url", "")
                )
                new_remote_api_key = (
                    remote_browser_api_key
                    if remote_browser_api_key is not None
                    else current.get("remote_browser_api_key", "")
                )
                new_remote_timeout = (
                    remote_browser_timeout
                    if remote_browser_timeout is not None
                    else current.get("remote_browser_timeout", 60)
                )
                new_proxy_enabled = (
                    browser_proxy_enabled
                    if browser_proxy_enabled is not None
                    else current.get("browser_proxy_enabled", False)
                )
                new_proxy_url = (
                    browser_proxy_url
                    if browser_proxy_url is not None
                    else current.get("browser_proxy_url")
                )
                new_browser_count = (
                    browser_count
                    if browser_count is not None
                    else current.get("browser_count", 1)
                )
                new_personal_project_pool_size = (
                    personal_project_pool_size
                    if personal_project_pool_size is not None
                    else current.get("personal_project_pool_size", 4)
                )
                new_personal_max_tabs = (
                    personal_max_resident_tabs
                    if personal_max_resident_tabs is not None
                    else current.get("personal_max_resident_tabs", 5)
                )
                new_personal_fresh_restart_every = (
                    browser_personal_fresh_restart_every_n_solves
                    if browser_personal_fresh_restart_every_n_solves is not None
                    else current.get(
                        "browser_personal_fresh_restart_every_n_solves", 10
                    )
                )
                new_personal_idle_ttl = (
                    personal_idle_tab_ttl_seconds
                    if personal_idle_tab_ttl_seconds is not None
                    else current.get("personal_idle_tab_ttl_seconds", 600)
                )
                new_remote_timeout = (
                    max(5, int(new_remote_timeout))
                    if new_remote_timeout is not None
                    else 60
                )
                new_browser_count = max(1, min(20, int(new_browser_count)))
                new_personal_project_pool_size = max(
                    1, min(50, int(new_personal_project_pool_size))
                )
                new_personal_max_tabs = max(
                    1, min(50, int(new_personal_max_tabs))
                )  # 限制1-50
                new_personal_fresh_restart_every = max(
                    0, int(new_personal_fresh_restart_every)
                )
                new_personal_idle_ttl = max(60, int(new_personal_idle_ttl))  # 最少60秒

                await db.execute(
                    """
                    UPDATE captcha_config
                    SET captcha_method = ?, yescaptcha_api_key = ?, yescaptcha_base_url = ?,
                        yescaptcha_task_type = ?,
                        capmonster_api_key = ?, capmonster_base_url = ?,
                        ezcaptcha_api_key = ?, ezcaptcha_base_url = ?,
                        capsolver_api_key = ?, capsolver_base_url = ?,
                        captcharun_api_key = ?, captcharun_base_url = ?,
                        remote_browser_base_url = ?, remote_browser_api_key = ?, remote_browser_timeout = ?,
                        browser_proxy_enabled = ?, browser_proxy_url = ?, browser_count = ?,
                        personal_project_pool_size = ?,
                        personal_max_resident_tabs = ?,
                        browser_personal_fresh_restart_every_n_solves = ?,
                        personal_idle_tab_ttl_seconds = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = 1
                """,
                    (
                        new_method,
                        new_yes_key,
                        new_yes_url,
                        new_yes_task_type,
                        new_cap_key,
                        new_cap_url,
                        new_ez_key,
                        new_ez_url,
                        new_cs_key,
                        new_cs_url,
                        new_run_key,
                        new_run_url,
                        (new_remote_base_url or "").strip(),
                        (new_remote_api_key or "").strip(),
                        new_remote_timeout,
                        new_proxy_enabled,
                        new_proxy_url,
                        new_browser_count,
                        new_personal_project_pool_size,
                        new_personal_max_tabs,
                        new_personal_fresh_restart_every,
                        new_personal_idle_ttl,
                    ),
                )
            else:
                new_method = (
                    captcha_method if captcha_method is not None else "yescaptcha"
                )
                new_yes_key = (
                    yescaptcha_api_key if yescaptcha_api_key is not None else ""
                )
                new_yes_url = (
                    yescaptcha_base_url
                    if yescaptcha_base_url is not None
                    else "https://api.yescaptcha.com"
                )
                new_yes_task_type = normalize_yescaptcha_task_type(yescaptcha_task_type)
                new_cap_key = (
                    capmonster_api_key if capmonster_api_key is not None else ""
                )
                new_cap_url = (
                    capmonster_base_url
                    if capmonster_base_url is not None
                    else "https://api.capmonster.cloud"
                )
                new_ez_key = ezcaptcha_api_key if ezcaptcha_api_key is not None else ""
                new_ez_url = (
                    ezcaptcha_base_url
                    if ezcaptcha_base_url is not None
                    else "https://api.ez-captcha.com"
                )
                new_cs_key = capsolver_api_key if capsolver_api_key is not None else ""
                new_cs_url = (
                    capsolver_base_url
                    if capsolver_base_url is not None
                    else "https://api.capsolver.com"
                )
                new_run_key = (
                    captcharun_api_key if captcharun_api_key is not None else ""
                )
                new_run_url = (
                    captcharun_base_url
                    if captcharun_base_url is not None
                    else "https://api.captcha-run.com"
                )
                new_remote_base_url = (
                    remote_browser_base_url
                    if remote_browser_base_url is not None
                    else ""
                )
                new_remote_api_key = (
                    remote_browser_api_key if remote_browser_api_key is not None else ""
                )
                new_remote_timeout = (
                    remote_browser_timeout if remote_browser_timeout is not None else 60
                )
                new_proxy_enabled = (
                    browser_proxy_enabled
                    if browser_proxy_enabled is not None
                    else False
                )
                new_proxy_url = browser_proxy_url
                new_browser_count = browser_count if browser_count is not None else 1
                new_personal_project_pool_size = (
                    personal_project_pool_size
                    if personal_project_pool_size is not None
                    else 4
                )
                new_personal_max_tabs = (
                    personal_max_resident_tabs
                    if personal_max_resident_tabs is not None
                    else 5
                )
                new_personal_fresh_restart_every = (
                    browser_personal_fresh_restart_every_n_solves
                    if browser_personal_fresh_restart_every_n_solves is not None
                    else 10
                )
                new_personal_idle_ttl = (
                    personal_idle_tab_ttl_seconds
                    if personal_idle_tab_ttl_seconds is not None
                    else 600
                )
                new_remote_timeout = max(5, int(new_remote_timeout))
                new_browser_count = max(1, min(20, int(new_browser_count)))
                new_personal_project_pool_size = max(
                    1, min(50, int(new_personal_project_pool_size))
                )
                new_personal_max_tabs = max(1, min(50, int(new_personal_max_tabs)))
                new_personal_fresh_restart_every = max(
                    0, int(new_personal_fresh_restart_every)
                )
                new_personal_idle_ttl = max(60, int(new_personal_idle_ttl))

                await db.execute(
                    """
                    INSERT INTO captcha_config (id, captcha_method, yescaptcha_api_key, yescaptcha_base_url,
                        yescaptcha_task_type,
                        capmonster_api_key, capmonster_base_url, ezcaptcha_api_key, ezcaptcha_base_url,
                        capsolver_api_key, capsolver_base_url,
                        captcharun_api_key, captcharun_base_url,
                        remote_browser_base_url, remote_browser_api_key, remote_browser_timeout,
                        browser_proxy_enabled, browser_proxy_url, browser_count,
                        personal_project_pool_size,
                        personal_max_resident_tabs, browser_personal_fresh_restart_every_n_solves,
                        personal_idle_tab_ttl_seconds)
                    VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        new_method,
                        new_yes_key,
                        new_yes_url,
                        new_yes_task_type,
                        new_cap_key,
                        new_cap_url,
                        new_ez_key,
                        new_ez_url,
                        new_cs_key,
                        new_cs_url,
                        new_run_key,
                        new_run_url,
                        (new_remote_base_url or "").strip(),
                        (new_remote_api_key or "").strip(),
                        new_remote_timeout,
                        new_proxy_enabled,
                        new_proxy_url,
                        new_browser_count,
                        new_personal_project_pool_size,
                        new_personal_max_tabs,
                        new_personal_fresh_restart_every,
                        new_personal_idle_ttl,
                    ),
                )

            # Keep the new provider update in the same transaction as the existing fields.
            previous_captcha = dict(row) if row else {}
            await db.execute(
                "UPDATE captcha_config SET twocaptcha_api_key = ?, twocaptcha_base_url = ? WHERE id = 1",
                (
                    twocaptcha_api_key
                    if twocaptcha_api_key is not None
                    else previous_captcha.get("twocaptcha_api_key", ""),
                    twocaptcha_base_url
                    if twocaptcha_base_url is not None
                    else previous_captcha.get("twocaptcha_base_url", "https://api.2captcha.com"),
                ),
            )
            await db.commit()

    # Plugin config operations
    async def get_plugin_config(self) -> PluginConfig:
        """Get plugin configuration"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM plugin_config WHERE id = 1")
            row = await cursor.fetchone()
            if row:
                return PluginConfig(**dict(row))
            return PluginConfig()

    async def update_plugin_config(
        self, connection_token: str, auto_enable_on_update: bool = True
    ):
        """Update plugin configuration"""
        async with self._connect(write=True) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM plugin_config WHERE id = 1")
            row = await cursor.fetchone()

            if row:
                await db.execute(
                    """
                    UPDATE plugin_config
                    SET connection_token = ?, auto_enable_on_update = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = 1
                """,
                    (connection_token, auto_enable_on_update),
                )
            else:
                await db.execute(
                    """
                    INSERT INTO plugin_config (id, connection_token, auto_enable_on_update)
                    VALUES (1, ?, ?)
                """,
                    (connection_token, auto_enable_on_update),
                )

            await db.commit()

    async def get_token_refresh_config(self) -> TokenRefreshConfig:
        """Get protocol ST refresh configuration"""
        async with self._connect() as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM token_refresh_config WHERE id = 1")
            row = await cursor.fetchone()
            if row:
                return TokenRefreshConfig(**dict(row))
            return TokenRefreshConfig()

    async def update_token_refresh_config(
        self,
        enabled: Optional[bool] = None,
        refresh_interval_minutes: Optional[int] = None,
        *, apply_to_active_tokens: bool = False,
    ) -> TokenRefreshConfig:
        """Update protocol ST refresh configuration."""
        changed_tokens = []
        async with self._connect(write=True) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM token_refresh_config WHERE id = 1")
            row = await cursor.fetchone()
            current = dict(row) if row else {}
            new_enabled = (
                enabled if enabled is not None else bool(current.get("enabled", True))
            )
            try:
                new_interval = int(
                    refresh_interval_minutes
                    if refresh_interval_minutes is not None
                    else current.get("refresh_interval_minutes", 120)
                )
            except Exception:
                new_interval = 120
            new_interval = max(1, new_interval)

            if row:
                await db.execute(
                    """
                    UPDATE token_refresh_config
                    SET enabled = ?, refresh_interval_minutes = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = 1
                """,
                    (new_enabled, new_interval),
                )
            else:
                await db.execute(
                    """
                    INSERT INTO token_refresh_config (id, enabled, refresh_interval_minutes)
                    VALUES (1, ?, ?)
                """,
                    (new_enabled, new_interval),
                )
            if apply_to_active_tokens and new_enabled:
                cursor = await db.execute(
                    """SELECT id, email, login_account, adspower_serial FROM tokens
                       WHERE is_active = 1 AND
                       (COALESCE(auto_refresh_enabled, 0) != 1 OR
                        COALESCE(refresh_interval_minutes, 120) != ?)""",
                    (new_interval,),
                )
                changed_tokens = [dict(item) for item in await cursor.fetchall()]
                await db.execute(
                    """UPDATE tokens SET auto_refresh_enabled = 1, refresh_interval_minutes = ?
                       WHERE is_active = 1""",
                    (new_interval,),
                )
            await db.commit()

        for item in changed_tokens:
            await audit_account_operation(
                self, item["id"], operation="config_update", status="success",
                reason="settings_updated", stage="settings", source=operation_source(),
                token=item, details={"setting": "token_refresh", "auto_refresh_enabled": True,
                                    "refresh_interval_minutes": new_interval},
            )
        return await self.get_token_refresh_config()
