"""Persistent storage for State Grid Info integration via HA Store."""

import glob
import json
import logging
import os
import shutil
from datetime import datetime
from typing import Any

from homeassistant.helpers.storage import Store

_LOGGER = logging.getLogger(__name__)

STORAGE_VERSION = 1
MAX_BACKUPS = 7
LEGACY_FILE_TEMPLATE = "state_grid_info_{}.json"


class StateGridStorage:
    """Manage persistent storage for state grid data.

    Built on HA's Store helper — atomic writes, corrupt-file recovery
    with an automatic Repairs issue, and inclusion in native backups
    all come free.

    Rules:
    - Data can only be added, never deleted.
    - Existing entries can be updated with new values.
    - dayList is merged by "day" key.
    - monthList is merged by "month" key.
    - yearList is merged by "year" key.
    - Legacy plain-JSON files (pre-Store) are migrated once and
      renamed to .migrated.
    - A daily snapshot (.bak-YYYYMMDD) is kept for the last MAX_BACKUPS days.
    """

    def __init__(self, hass, consumer_number: str):
        """Initialize storage."""
        self._hass = hass
        self._consumer_number = consumer_number
        self._store = Store(
            hass,
            STORAGE_VERSION,
            f"state_grid_info.{consumer_number}",
            atomic_writes=True,
        )
        self._legacy_path = hass.config.path(
            LEGACY_FILE_TEMPLATE.format(consumer_number)
        )
        self._data: dict[str, Any] = {}

    @property
    def data(self) -> dict[str, Any]:
        """Return current stored data."""
        return self._data

    @staticmethod
    def _empty_data() -> dict[str, Any]:
        """Return a fresh empty data structure."""
        return {
            "date": "",
            "balance": 0,
            "dayList": [],
            "monthList": [],
            "yearList": [],
            "consumer_name": "",
        }

    def _load_legacy_sync(self) -> dict[str, Any] | None:
        """Load and archive the legacy plain-JSON file, if present (executor)."""
        if not os.path.exists(self._legacy_path):
            return None
        try:
            with open(self._legacy_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError) as ex:
            _LOGGER.warning("旧存储文件无法读取，跳过迁移: %s", ex)
            return None
        migrated = f"{self._legacy_path}.migrated"
        try:
            os.replace(self._legacy_path, migrated)
            _LOGGER.info("旧存储文件已迁移到 HA Store，原文件归档为: %s", migrated)
        except OSError as ex:
            _LOGGER.warning("旧存储文件归档失败（不影响迁移）: %s", ex)
        return data

    async def async_load(self) -> None:
        """Load data from HA Store, migrating any legacy JSON file."""
        data = await self._store.async_load()
        legacy = await self._hass.async_add_executor_job(self._load_legacy_sync)
        if data is None and legacy:
            data = legacy
            await self._store.async_save(data)
        self._data = data if isinstance(data, dict) else self._empty_data()
        _LOGGER.info(
            "已加载持久化数据: %s (dayList=%d条, monthList=%d条, yearList=%d条)",
            self._store.key,
            len(self._data.get("dayList", [])),
            len(self._data.get("monthList", [])),
            len(self._data.get("yearList", [])),
        )

    def _snapshot_sync(self) -> None:
        """Keep one snapshot of the Store file per day, retaining MAX_BACKUPS."""
        try:
            today = datetime.now().strftime("%Y%m%d")
            backup_path = f"{self._store.path}.bak-{today}"
            if not os.path.exists(backup_path) and os.path.exists(self._store.path):
                shutil.copy2(self._store.path, backup_path)
            backups = sorted(glob.glob(f"{self._store.path}.bak-*"), reverse=True)
            for old in backups[MAX_BACKUPS:]:
                os.remove(old)
                _LOGGER.debug("已清理过期备份: %s", old)
        except OSError as ex:
            _LOGGER.warning("创建每日备份失败: %s", ex)

    def _merge_list_by_key(self, existing: list, new_items: list, key: str) -> list:
        """Merge two lists by a key field.

        - New items are added.
        - Existing items (matched by key) are updated with new values.
        - Items only in existing are kept (never deleted).
        """
        existing_map = {item[key]: item for item in existing}
        for item in new_items:
            k = item[key]
            if k in existing_map:
                existing_map[k].update(item)
            else:
                existing_map[k] = item
        return sorted(existing_map.values(), key=lambda x: x[key], reverse=True)

    async def async_update(self, new_data: dict[str, Any]) -> dict[str, Any]:
        """Merge new data into storage, persist via Store, return merged result.

        - dayList: merge by "day"
        - monthList: merge by "month"
        - yearList: merge by "year"
        - Scalar fields (date, balance, consumer_name): always update
        """
        if not new_data:
            return self._data

        # Merge scalar fields - always update
        self._data["date"] = new_data.get("date", self._data.get("date", ""))
        self._data["balance"] = new_data.get("balance", self._data.get("balance", 0))
        self._data["consumer_name"] = new_data.get(
            "consumer_name", self._data.get("consumer_name", "")
        )
        self._data["totalEleNum"] = new_data.get(
            "totalEleNum", self._data.get("totalEleNum", 0)
        )
        self._data["totalEleCost"] = new_data.get(
            "totalEleCost", self._data.get("totalEleCost", 0)
        )

        # Merge dayList by "day"
        if "dayList" in new_data:
            self._data["dayList"] = self._merge_list_by_key(
                self._data.get("dayList", []), new_data["dayList"], "day"
            )

        # Merge monthList by "month"
        if "monthList" in new_data:
            self._data["monthList"] = self._merge_list_by_key(
                self._data.get("monthList", []), new_data["monthList"], "month"
            )

        # Merge yearList by "year"
        if "yearList" in new_data:
            self._data["yearList"] = self._merge_list_by_key(
                self._data.get("yearList", []), new_data["yearList"], "year"
            )

        # Persist via Store (atomic), then keep a daily snapshot
        await self._store.async_save(self._data)
        await self._hass.async_add_executor_job(self._snapshot_sync)

        _LOGGER.info(
            "数据已合并并持久化: dayList=%d条, monthList=%d条, yearList=%d条",
            len(self._data.get("dayList", [])),
            len(self._data.get("monthList", [])),
            len(self._data.get("yearList", [])),
        )

        return dict(self._data)
