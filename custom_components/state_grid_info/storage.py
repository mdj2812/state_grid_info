"""Persistent storage for State Grid Info integration."""

import glob
import json
import logging
import os
import shutil
import tempfile
from datetime import datetime
from typing import Any

_LOGGER = logging.getLogger(__name__)

MAX_BACKUPS = 7


class StateGridStorage:
    """Manage persistent JSON storage for state grid data.

    Rules:
    - Data can only be added, never deleted.
    - Existing entries can be updated with new values.
    - dayList is merged by "day" key.
    - monthList is merged by "month" key.
    - yearList is merged by "year" key.
    - Writes are atomic (temp file + os.replace) to survive power loss.
    - Corrupted files are preserved as .broken-<timestamp>, never silently discarded.
    - A daily snapshot (.bak-YYYYMMDD) is kept for the last MAX_BACKUPS days.
    """

    def __init__(self, hass, consumer_number: str):
        """Initialize storage."""
        self._hass = hass
        self._consumer_number = consumer_number
        self._file_path = hass.config.path(f"state_grid_info_{consumer_number}.json")
        self._data: dict[str, Any] = {}
        self.corrupt_backup_path: str | None = None

    @property
    def file_path(self) -> str:
        """Return the JSON file path."""
        return self._file_path

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

    def _load_sync(self) -> None:
        """Load data from JSON file (sync, must run in executor)."""
        try:
            if os.path.exists(self._file_path):
                with open(self._file_path, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
                _LOGGER.info(
                    "已加载持久化数据: %s (dayList=%d条, monthList=%d条, yearList=%d条)",
                    self._file_path,
                    len(self._data.get("dayList", [])),
                    len(self._data.get("monthList", [])),
                    len(self._data.get("yearList", [])),
                )
            else:
                self._data = self._empty_data()
                _LOGGER.info("持久化文件不存在，初始化空数据: %s", self._file_path)
        except (json.JSONDecodeError, IOError) as ex:
            # Never silently discard accumulated history: preserve the
            # unreadable file for manual recovery before starting fresh.
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            self.corrupt_backup_path = f"{self._file_path}.broken-{timestamp}"
            try:
                os.replace(self._file_path, self.corrupt_backup_path)
                _LOGGER.error(
                    "持久化数据损坏: %s — 原文件已保留为 %s，将从空数据重新开始。"
                    "请检查备份文件手动恢复历史数据。错误: %s",
                    self._file_path,
                    self.corrupt_backup_path,
                    ex,
                )
            except OSError as backup_err:
                self.corrupt_backup_path = None
                _LOGGER.error(
                    "持久化数据损坏且备份失败: %s (错误: %s, 备份错误: %s)",
                    self._file_path,
                    ex,
                    backup_err,
                )
            self._data = self._empty_data()

    async def async_load(self) -> None:
        """Load data from JSON file asynchronously."""
        await self._hass.async_add_executor_job(self._load_sync)
        if self.corrupt_backup_path:
            from homeassistant.components import persistent_notification

            persistent_notification.async_create(
                self._hass,
                f"国家电网集成存储文件损坏，原文件已备份为 "
                f"`{self.corrupt_backup_path}`。日用电历史数据已重置，"
                f"请检查备份文件手动恢复。",
                title="State Grid Info: 存储数据损坏",
                notification_id=f"state_grid_storage_corrupt_{self._consumer_number}",
            )

    def _save_sync(self) -> None:
        """Save data to JSON file atomically (sync, must run in executor).

        Writes to a temp file in the same directory, then os.replace() —
        a crash mid-write can never truncate the existing storage file.
        """
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(
                dir=os.path.dirname(self._file_path),
                prefix=".state_grid_info_",
                suffix=".tmp",
            )
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, self._file_path)
            _LOGGER.debug("已保存持久化数据: %s", self._file_path)
        except IOError as ex:
            _LOGGER.error("保存持久化数据失败: %s", ex)
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def _backup_daily_sync(self) -> None:
        """Keep one backup snapshot per day, retaining the most recent MAX_BACKUPS."""
        try:
            today = datetime.now().strftime("%Y%m%d")
            backup_path = f"{self._file_path}.bak-{today}"
            if not os.path.exists(backup_path) and os.path.exists(self._file_path):
                shutil.copy2(self._file_path, backup_path)
            backups = sorted(glob.glob(f"{self._file_path}.bak-*"), reverse=True)
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

    def update(self, new_data: dict[str, Any]) -> dict[str, Any]:
        """Update storage with new data, then return merged result.

        - dayList: merge by "day"
        - monthList: merge by "month"
        - yearList: merge by "year"
        - Scalar fields (date, balance, consumer_name): always update

        Note: This method does synchronous file I/O via _save_sync.
        It must be called via hass.async_add_executor_job from async code.
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

        # Save to file, then keep a daily snapshot for point-in-time recovery
        self._save_sync()
        self._backup_daily_sync()

        _LOGGER.info(
            "数据已合并并持久化: dayList=%d条, monthList=%d条, yearList=%d条",
            len(self._data.get("dayList", [])),
            len(self._data.get("monthList", [])),
            len(self._data.get("yearList", [])),
        )

        return dict(self._data)
