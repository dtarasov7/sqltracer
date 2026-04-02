#!/usr/bin/env python3
"""Config source providers for sqltracer.

Priority order:
1. Vault
2. Encrypted config file
3. Plain config file
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import getpass
import json
import os
import re
import urllib.error
import urllib.request
from typing import Dict, List, Tuple

RE_NUMERIC_LITERAL = re.compile(r"^[+-]?\d+(?:\.\d+)?$")


def detect_config_path(argv: List[str]) -> str:
    """EN: Detect plain config path from CLI args or default filenames.
    RU: Определить путь plain-config из CLI-аргументов или default-файлов.

    Args:
        argv (List[str]): EN: Raw CLI token list.
            RU: Список токенов CLI.

    Returns:
        str: EN: Detected absolute/explicit path or empty string.
            RU: Найденный путь или пустая строка.
    """
    for index, token in enumerate(argv):
        if token == "--config" and index + 1 < len(argv):
            return argv[index + 1]
        if token.startswith("--config="):
            return token.split("=", 1)[1]
    for candidate in (".sqltracer.yaml",):
        path = os.path.abspath(candidate)
        if os.path.exists(path):
            return path
    return ""


def parse_yaml_scalar(value: str) -> object:
    """EN: Parse scalar value from minimal YAML subset.
    RU: Распарсить scalar-значение из минимального YAML-подмножества.

    Args:
        value (str): EN: Raw scalar text. RU: Текст scalar-значения.

    Returns:
        object: EN: Parsed bool/int/float/string value.
            RU: Значение типа bool/int/float/string.
    """
    if value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) >= 2:
        return value[1:-1]
    lower = value.lower()
    if lower in ("true", "yes", "on"):
        return True
    if lower in ("false", "no", "off"):
        return False
    if RE_NUMERIC_LITERAL.match(value):
        if "." in value:
            return float(value)
        return int(value)
    return value


def parse_simple_yaml_text(text: str, source: str) -> Dict[str, object]:
    """EN: Parse indentation-based flat YAML subset into dictionary.
    RU: Распарсить отступный YAML-поднабор в словарь.

    Args:
        text (str): EN: YAML text body. RU: YAML-текст.
        source (str): EN: Source label for diagnostics.
            RU: Метка источника для диагностики.

    Returns:
        Dict[str, object]: EN: Parsed mapping structure.
            RU: Распарсенная структура словаря.

    Raises:
        ValueError: EN: Malformed YAML lines or invalid indentation.
            RU: Некорректные строки YAML или неверные отступы.
    """
    root: Dict[str, object] = {}
    stack: List[Tuple[int, Dict[str, object]]] = [(-1, root)]
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if ":" not in stripped:
            raise ValueError(f"invalid config line {lineno} in {source}: {raw_line.rstrip()}")
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack:
            raise ValueError(f"invalid indentation in config line {lineno} in {source}")
        current = stack[-1][1]
        if not value:
            nested: Dict[str, object] = {}
            current[key] = nested
            stack.append((indent, nested))
            continue
        current[key] = parse_yaml_scalar(value)
    return root


def parse_config_text(text: str, source: str) -> Dict[str, object]:
    """EN: Parse config as JSON object or fallback YAML subset.
    RU: Распарсить конфиг как JSON-объект или fallback на YAML-поднабор.

    Args:
        text (str): EN: Config text body. RU: Текст конфига.
        source (str): EN: Source label for errors.
            RU: Метка источника для ошибок.

    Returns:
        Dict[str, object]: EN: Parsed config mapping.
            RU: Распарсенный config-словарь.

    Raises:
        ValueError: EN: JSON/YAML content is syntactically invalid.
            RU: JSON/YAML содержимое синтаксически неверно.
    """
    stripped = text.strip()
    if not stripped:
        return {}
    with contextlib.suppress(json.JSONDecodeError):
        data = json.loads(stripped)
        if not isinstance(data, dict):
            raise ValueError(f"config source {source} must contain a JSON object")
        return data
    return parse_simple_yaml_text(text, source)


def validate_config_mapping(data: Dict[str, object], source: str) -> Dict[str, object]:
    """EN: Validate top-level config invariants shared by all sources.
    RU: Проверить базовые инварианты конфига для всех источников.

    Args:
        data (Dict[str, object]): EN: Parsed config mapping.
            RU: Распарсенный config-словарь.
        source (str): EN: Source label for diagnostics.
            RU: Метка источника для диагностики.

    Returns:
        Dict[str, object]: EN: Same mapping when valid.
            RU: Тот же словарь при валидном содержимом.

    Raises:
        RuntimeError: EN: Unsupported database driver configured.
            RU: Настроен неподдерживаемый драйвер БД.
    """
    driver = str(data.get("driver", "postgres")).lower()
    if driver not in ("postgres", "postgresql"):
        raise RuntimeError(f"unsupported driver in {source}: {driver}")
    return data


def load_plain_config_file(path: str) -> Dict[str, object]:
    """EN: Load and parse plain-text config file.
    RU: Загрузить и распарсить обычный текстовый конфиг-файл.

    Args:
        path (str): EN: Config file path. RU: Путь к файлу конфига.

    Returns:
        Dict[str, object]: EN: Validated config mapping.
            RU: Валидированный config-словарь.

    Raises:
        RuntimeError: EN: File I/O or parse errors.
            RU: Ошибки чтения файла или парсинга.
    """
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise RuntimeError(f"failed to read config file {path}: {exc}") from exc
    try:
        data = parse_config_text(text, path)
    except ValueError as exc:
        raise RuntimeError(f"failed to parse config file {path}: {exc}") from exc
    return validate_config_mapping(data, f"config file {path}")


def derive_config_key(password: str, salt: bytes) -> bytes:
    """EN: Derive Fernet key bytes from password and salt (PBKDF2).
    RU: Вычислить Fernet-ключ из пароля и salt (PBKDF2).

    Args:
        password (str): EN: User password. RU: Пользовательский пароль.
        salt (bytes): EN: Random 16-byte salt. RU: Случайный salt (16 байт).

    Returns:
        bytes: EN: URL-safe base64 encoded key.
            RU: URL-safe base64-кодированный ключ.

    Raises:
        RuntimeError: EN: cryptography dependency is missing.
            RU: Отсутствует зависимость cryptography.
    """
    try:
        from cryptography.hazmat.backends import default_backend  # type: ignore
        from cryptography.hazmat.primitives import hashes  # type: ignore
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
    except ImportError as exc:
        raise RuntimeError("encrypted config requires the cryptography package") from exc
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def load_encrypted_config_file(path: str, password: str = "") -> Dict[str, object]:
    """EN: Load encrypted config produced by config-encryptor tool.
    RU: Загрузить зашифрованный конфиг, созданный config-encryptor.

    Args:
        path (str): EN: Encrypted file path.
            RU: Путь к зашифрованному файлу.
        password (str): EN: Optional password override.
            RU: Необязательный пароль-override.

    Returns:
        Dict[str, object]: EN: Validated decrypted config mapping.
            RU: Валидированный расшифрованный config-словарь.

    Raises:
        RuntimeError: EN: Read/decrypt/parse/dependency errors.
            RU: Ошибки чтения/расшифровки/парсинга/зависимостей.
    """
    if not path:
        return {}
    try:
        with open(path, "rb") as handle:
            file_data = handle.read()
    except OSError as exc:
        raise RuntimeError(f"failed to read encrypted config {path}: {exc}") from exc
    if len(file_data) < 16:
        raise RuntimeError(f"encrypted config file {path} is corrupted or too short")

    if not password:
        password = os.environ.get("SQLTRACER_CONFIG_PASSWORD", "")
    if not password:
        password = getpass.getpass("Enter config decryption password: ")
    if not password:
        raise RuntimeError("empty password; encrypted config cannot be decrypted")

    try:
        from cryptography.fernet import Fernet  # type: ignore
    except ImportError as exc:
        raise RuntimeError("encrypted config requires the cryptography package") from exc

    salt = file_data[:16]
    encrypted_data = file_data[16:]
    key = derive_config_key(password, salt)
    try:
        decrypted_data = Fernet(key).decrypt(encrypted_data)
    except Exception as exc:
        raise RuntimeError(f"failed to decrypt config {path}: invalid password or corrupted file") from exc
    try:
        text = decrypted_data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"decrypted config {path} is not valid UTF-8") from exc
    try:
        data = parse_config_text(text, f"encrypted config {path}")
    except ValueError as exc:
        raise RuntimeError(f"failed to parse decrypted config {path}: {exc}") from exc
    return validate_config_mapping(data, f"encrypted config {path}")


def extract_vault_secret_config(secret_data: object, source: str) -> Dict[str, object]:
    """EN: Extract config mapping from Vault secret variants.
    RU: Извлечь config-словарь из разных форматов Vault-secret.

    Args:
        secret_data (object): EN: Raw secret JSON payload fragment.
            RU: Фрагмент JSON payload из Vault.
        source (str): EN: Source label for diagnostics.
            RU: Метка источника для диагностики.

    Returns:
        Dict[str, object]: EN: Validated config mapping.
            RU: Валидированный config-словарь.

    Raises:
        RuntimeError: EN: Invalid structure or parse errors.
            RU: Неверная структура или ошибки парсинга.
    """
    if not isinstance(secret_data, dict):
        raise RuntimeError(f"Vault secret {source} must be a mapping")

    for key in ("config", "config_yaml", "config_json", "sqltracer_config"):
        value = secret_data.get(key)
        if isinstance(value, str) and value.strip():
            try:
                parsed = parse_config_text(value, f"{source}:{key}")
            except ValueError as exc:
                raise RuntimeError(f"failed to parse Vault config from {source}:{key}: {exc}") from exc
            return validate_config_mapping(parsed, f"{source}:{key}")
    return validate_config_mapping(secret_data, source)


def load_config_from_vault(
    vault_url: str,
    vault_path: str,
    username: str = "",
    password: str = "",
    allow_insecure_http: bool = False,
) -> Dict[str, object]:
    """EN: Authenticate via Vault userpass and load config secret.
    RU: Аутентифицироваться в Vault через userpass и загрузить config-secret.

    Args:
        vault_url (str): EN: Vault base URL.
            RU: Базовый URL Vault.
        vault_path (str): EN: Secret path to read.
            RU: Путь секрета для чтения.
        username (str): EN: Optional username override.
            RU: Необязательный override логина.
        password (str): EN: Optional password override.
            RU: Необязательный override пароля.
        allow_insecure_http (bool): EN: Allow http:// Vault URL when True.
            RU: Разрешить http:// URL Vault при True.

    Returns:
        Dict[str, object]: EN: Validated config mapping from Vault.
            RU: Валидированный config-словарь из Vault.

    Raises:
        RuntimeError: EN: Auth/read/format errors.
            RU: Ошибки аутентификации/чтения/формата.
    """
    if not vault_url or not vault_path:
        raise RuntimeError("Vault config requires both --vault-url and --vault-path")
    normalized_url = vault_url.strip()
    lowered_url = normalized_url.lower()
    if lowered_url.startswith("http://") and not allow_insecure_http:
        raise RuntimeError(
            "Vault URL must use https:// by default; pass --allow-insecure-vault-http only for local testing"
        )
    if not lowered_url.startswith(("https://", "http://")):
        raise RuntimeError("Vault URL must start with https:// or http://")
    username = username or os.environ.get("VAULT_USERNAME", "")
    password = password or os.environ.get("VAULT_PASSWORD", "")
    if not username:
        username = input("Vault Username: ").strip()
    if not password:
        password = getpass.getpass("Vault Password: ")
    if not username or not password:
        raise RuntimeError("Vault username/password are required")

    base = normalized_url.rstrip("/")
    auth_url = f"{base}/v1/auth/userpass/login/{username}"
    login_payload = json.dumps({"password": password}).encode("utf-8")
    login_request = urllib.request.Request(
        auth_url,
        data=login_payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(login_request, timeout=10) as response:
            login_data = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Vault login failed for {auth_url}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Vault login returned invalid JSON from {auth_url}") from exc

    token = login_data.get("auth", {}).get("client_token") if isinstance(login_data, dict) else None
    if not token:
        raise RuntimeError(f"Vault login did not return a client token from {auth_url}")

    secret_url = f"{base}/v1/{vault_path.lstrip('/')}"
    secret_request = urllib.request.Request(
        secret_url,
        headers={"X-Vault-Token": str(token)},
        method="GET",
    )
    try:
        with urllib.request.urlopen(secret_request, timeout=10) as response:
            secret_payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Vault read failed for {secret_url}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Vault read returned invalid JSON from {secret_url}") from exc

    # EN: Handle KV v2 shape (`data.data`) and KV v1 shape (`data`).
    # RU: Поддержка формата KV v2 (`data.data`) и KV v1 (`data`).
    if (
        isinstance(secret_payload, dict)
        and isinstance(secret_payload.get("data"), dict)
        and isinstance(secret_payload["data"].get("data"), dict)
    ):
        secret_data = secret_payload["data"]["data"]
    elif isinstance(secret_payload, dict) and isinstance(secret_payload.get("data"), dict):
        secret_data = secret_payload["data"]
    else:
        secret_data = secret_payload
    return extract_vault_secret_config(secret_data, f"vault:{vault_path}")


def load_config_source(args: argparse.Namespace, argv: List[str]) -> Tuple[Dict[str, object], str]:
    """EN: Resolve final config source with priority Vault > encrypted > plain.
    RU: Выбрать итоговый источник конфига с приоритетом Vault > encrypted > plain.

    Args:
        args (argparse.Namespace): EN: Parsed CLI arguments.
            RU: Распарсенные CLI-аргументы.
        argv (List[str]): EN: Raw CLI token list.
            RU: Список CLI-токенов.

    Returns:
        Tuple[Dict[str, object], str]:
            EN: (config mapping, source label/path).
            RU: (config-словарь, метка/путь источника).

    Raises:
        RuntimeError: EN: Source-specific load/validation errors.
            RU: Ошибки загрузки/валидации выбранного источника.
    """
    if args.vault_url or args.vault_path:
        if not (args.vault_url and args.vault_path):
            raise RuntimeError("both --vault-url and --vault-path are required together")
        config = load_config_from_vault(
            vault_url=args.vault_url,
            vault_path=args.vault_path,
            username=args.vault_username or "",
            password=args.vault_password or "",
            allow_insecure_http=bool(getattr(args, "allow_insecure_vault_http", False)),
        )
        return config, f"vault:{args.vault_path}"
    if args.encrypted_config:
        return load_encrypted_config_file(args.encrypted_config), os.path.abspath(args.encrypted_config)
    detected_config_path = "" if any(token in ("-h", "--help") for token in argv) else detect_config_path(argv)
    if not detected_config_path:
        return {}, ""
    return load_plain_config_file(detected_config_path), detected_config_path
