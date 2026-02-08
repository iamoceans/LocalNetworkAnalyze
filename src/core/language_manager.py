"""
Language manager service.

Bridges the configuration system and translation system,
providing a unified interface for language management.
"""

from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from src.core.logger import get_logger
from src.core.config import AppConfig, GuiConfig
from src.core.i18n import Translator, get_translator


class LanguageManager:
    """Manages language configuration and translation.

    This service provides:
    - Translation lookup via t() method
    - Language switching with persistence
    - Observer pattern for UI updates on language change
    """

    def __init__(
        self,
        config: GuiConfig,
        config_path: Optional[Path] = None,
        app_config: Optional[AppConfig] = None,
    ) -> None:
        """Initialize language manager.

        Args:
            config: GUI configuration containing language setting
            config_path: Path to config file for persistence
            app_config: Full app config (for creating updated configs)
        """
        self._translator = get_translator()
        self._config = config
        self._config_path = config_path
        self._app_config = app_config
        self._logger = get_logger(__name__)
        self._observers: List[Callable[[str], None]] = []

        # Apply configured language
        self._apply_config_language()

    def _apply_config_language(self) -> None:
        """Apply the language from config to translator."""
        lang = self._config.language
        try:
            self._translator.set_language(lang)
            self._logger.info(f"Language initialized: {lang}")
        except ValueError:
            # Language not available, fallback to English
            self._logger.warning(
                f"Language '{lang}' not available, using 'en'"
            )
            self._translator.set_language("en")

    def t(self, key: str, **kwargs: Any) -> str:
        """Get translated string.

        Convenience method for translation lookup.

        Args:
            key: Translation key in dot notation
            **kwargs: Format parameters

        Returns:
            Translated string

        Example:
            >>> lang.t("dashboard.title")
            'Network Dashboard'
            >>> lang.t("status.captured", interface="eth0")
            'Capturing on eth0'
        """
        return self._translator.translate(key, **kwargs)

    def set_language(self, lang: str) -> None:
        """Switch language and persist to config.

        Args:
            lang: Language code ("en" or "zh")

        Raises:
            ValueError: If language code is not supported
        """
        # Validate language
        if lang not in self._translator.get_available_languages():
            raise ValueError(
                f"Unsupported language: {lang}. "
                f"Available: {', '.join(self._translator.get_available_languages())}"
            )

        # Switch language in translator
        self._translator.set_language(lang)

        # Persist to config file
        if self._config_path and self._app_config:
            self._save_language_to_config(lang)

        # Notify observers
        self._notify_observers(lang)

        self._logger.info(f"Language switched to: {lang}")

    def get_language(self) -> str:
        """Get current language code.

        Returns:
            Current language code (e.g., "en", "zh")
        """
        return self._translator.get_language()

    def get_available_languages(self) -> List[str]:
        """Get available language codes.

        Returns:
            List of available language codes
        """
        return self._translator.get_available_languages()

    def add_observer(self, callback: Callable[[str], None]) -> None:
        """Add observer for language changes.

        The callback will be invoked with the new language code
        whenever the language is changed.

        Args:
            callback: Function to call on language change
        """
        if callback not in self._observers:
            self._observers.append(callback)

    def remove_observer(self, callback: Callable[[str], None]) -> None:
        """Remove observer.

        Args:
            callback: Function to remove from observers
        """
        try:
            self._observers.remove(callback)
        except ValueError:
            pass

    def _notify_observers(self, lang: str) -> None:
        """Notify all observers of language change.

        Args:
            lang: New language code
        """
        for observer in self._observers:
            try:
                observer(lang)
            except Exception as e:
                self._logger.error(
                    f"Error in language change observer: {e}"
                )

    def _save_language_to_config(self, lang: str) -> None:
        """Save language setting to config file.

        Args:
            lang: Language code to save
        """
        if not self._config_path or not self._app_config:
            return

        try:
            # Create new config with updated language
            updated_config = self._app_config.with_language(lang)
            updated_config.to_file(self._config_path)
            self._logger.info(f"Language saved to config: {lang}")
        except Exception as e:
            self._logger.error(f"Failed to save language config: {e}")

    def get_language_name(self, code: str) -> str:
        """Get display name for language code.

        Args:
            code: Language code

        Returns:
            Display name for the language
        """
        names = {
            "en": self.t("language.english"),
            "zh": self.t("language.chinese"),
        }
        return names.get(code, code)


def create_language_manager(
    config: GuiConfig,
    config_path: Optional[Path] = None,
    app_config: Optional[AppConfig] = None,
) -> LanguageManager:
    """Create a language manager instance.

    Args:
        config: GUI configuration
        config_path: Path to config file for persistence
        app_config: Full app config

    Returns:
        LanguageManager instance
    """
    return LanguageManager(config, config_path, app_config)
