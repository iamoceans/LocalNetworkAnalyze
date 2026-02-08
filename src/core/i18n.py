"""
Internationalization (i18n) module.

Provides translation functionality for multiple languages.
Uses JSON files for translation storage.
"""

import json
import threading
from pathlib import Path
from typing import Any, Dict, Optional
from src.core.logger import get_logger


class Translator:
    """Thread-safe translator with singleton pattern.

    Provides translation lookup with fallback support and
    runtime language switching capabilities.
    """

    _instance: Optional['Translator'] = None
    _lock = threading.Lock()

    def __new__(cls) -> 'Translator':
        """Ensure only one instance exists."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize translator.

        Only initializes once due to singleton pattern.
        """
        if hasattr(self, '_initialized'):
            return

        self._current_lang = "en"
        self._translations: Dict[str, Dict[str, Any]] = {}
        self._translations_lock = threading.Lock()
        self._logger = get_logger(__name__)

        self._load_translations()
        self._initialized = True

    def _load_translations(self) -> None:
        """Load all available translation files.

        Looks for JSON files in src/core/translations/ directory.
        """
        translations_dir = Path(__file__).parent / "translations"

        if not translations_dir.exists():
            translations_dir.mkdir(parents=True, exist_ok=True)
            self._logger.warning(
                f"Created translations directory: {translations_dir}"
            )

        for json_file in translations_dir.glob("*.json"):
            lang_code = json_file.stem
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    self._translations[lang_code] = json.load(f)
                self._logger.info(f"Loaded translations: {lang_code}")
            except (json.JSONDecodeError, IOError) as e:
                self._logger.error(f"Failed to load {json_file}: {e}")

    def translate(self, key: str, **kwargs: Any) -> str:
        """Get translated string for the given key.

        Args:
            key: Translation key in dot notation (e.g., "dashboard.title")
            **kwargs: Format parameters for the translated string

        Returns:
            Translated string, or the key itself if not found

        Example:
            >>> translator.translate("dashboard.title")
            'Network Dashboard'
            >>> translator.translate("status.captured", interface="eth0")
            'Capturing on eth0'
        """
        parts = key.split(".")
        current = self._translations.get(self._current_lang, {})

        # Navigate through nested dictionary
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part, key)
            else:
                return key  # Not found, return key as fallback

        if not isinstance(current, str):
            return key  # Not a string, return key as fallback

        # Apply format parameters if provided
        if kwargs:
            try:
                return current.format(**kwargs)
            except (KeyError, ValueError) as e:
                self._logger.warning(
                    f"Format failed for key '{key}': {e}"
                )
                return current

        return current

    def set_language(self, lang: str) -> None:
        """Switch to a different language.

        Args:
            lang: Language code ("en" or "zh")

        Raises:
            ValueError: If language code is not supported
        """
        if lang not in self._translations:
            available = ", ".join(self._translations.keys())
            raise ValueError(
                f"Unsupported language: {lang}. "
                f"Available: {available}"
            )

        with self._translations_lock:
            self._current_lang = lang
        self._logger.info(f"Language switched to: {lang}")

    def get_language(self) -> str:
        """Get current language code.

        Returns:
            Current language code (e.g., "en", "zh")
        """
        return self._current_lang

    def get_available_languages(self) -> list[str]:
        """Get list of available language codes.

        Returns:
            List of available language codes
        """
        return list(self._translations.keys())


# Global translator instance
_translator: Optional[Translator] = None


def get_translator() -> Translator:
    """Get the global translator instance.

    Returns:
        Translator singleton instance
    """
    global _translator
    if _translator is None:
        _translator = Translator()
    return _translator


def translate(key: str, **kwargs: Any) -> str:
    """Convenience function for translation.

    Args:
        key: Translation key
        **kwargs: Format parameters

    Returns:
        Translated string
    """
    return get_translator().translate(key, **kwargs)


def set_language(lang: str) -> None:
    """Set the global language.

    Args:
        lang: Language code ("en" or "zh")
    """
    get_translator().set_language(lang)


def get_language() -> str:
    """Get the current language.

    Returns:
        Current language code
    """
    return get_translator().get_language()
