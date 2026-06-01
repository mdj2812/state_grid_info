"""国家电网辅助信息集成."""
import logging
import homeassistant.helpers.config_validation as cv
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.const import Platform


from .const import DOMAIN, CONF_CONSUMER_NUMBER

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.SENSOR]

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up State Grid Info from a config entry."""
    import asyncio
    from datetime import timedelta
    
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        "config": entry.data,
        "entities": []
    }
    
    # 设置平台
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    
    # 创建定期刷新任务
    async def refresh_data_periodically():
        """定期刷新数据，确保数据更新"""
        try:
            while True:
                # 每5分钟刷新一次
                await asyncio.sleep(300)  # 5分钟
                
                # 获取协调器并触发更新
                coordinator = None
                for entity in hass.data.get(DOMAIN, {}).get(entry.entry_id, {}).get("entities", []):
                    if hasattr(entity, "coordinator"):
                        coordinator = entity.coordinator
                        break
                
                if coordinator:
                    _LOGGER.info("执行定期数据刷新")
                    await coordinator.async_refresh()
                else:
                    _LOGGER.warning("未找到协调器，无法执行定期刷新")
        except asyncio.CancelledError:
            # 任务被取消
            pass
        except Exception as ex:
            _LOGGER.error("定期刷新任务出错: %s", ex)
    
    # 启动定期刷新任务
    refresh_task = hass.loop.create_task(refresh_data_periodically())
    
    # 保存任务引用以便后续清理
    hass.data[DOMAIN][entry.entry_id]["refresh_task"] = refresh_task
    
    return True

async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    # 获取协调器并清理资源
    coordinator = None
    for entity in hass.data.get(DOMAIN, {}).get(entry.entry_id, {}).get("entities", []):
        if hasattr(entity, "coordinator"):
            coordinator = entity.coordinator
            break
    
    # 取消定期刷新任务
    refresh_task = hass.data.get(DOMAIN, {}).get(entry.entry_id, {}).get("refresh_task")
    if refresh_task:
        _LOGGER.info("取消定期刷新任务")
        refresh_task.cancel()
        try:
            await refresh_task
        except Exception:
            pass
    
    # 卸载平台
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    
    # 清理资源
    if coordinator and hasattr(coordinator, "async_unload"):
        _LOGGER.info("清理协调器资源")
        await coordinator.async_unload()
    
    if unload_ok:
        if entry.entry_id in hass.data.get(DOMAIN, {}):
            hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok
