#!/usr/bin/env python3
"""EN: Packet I/O helpers with PostgreSQL wire-protocol size limits.
RU: Вспомогательные функции packet I/O с лимитами размера PostgreSQL-протокола.
"""

from __future__ import annotations

import socket
import struct


def read_exact(sock: socket.socket, size: int) -> bytes:
    """EN: Read exactly `size` bytes or fail when socket closes early.
    RU: Прочитать ровно `size` байт или завершиться ошибкой при раннем закрытии.

    Args:
        sock (socket.socket): EN: Source socket. RU: Сокет-источник.
        size (int): EN: Required byte count. RU: Требуемое число байт.

    Returns:
        bytes: EN: Exact payload of requested length.
            RU: Данные точной запрошенной длины.

    Raises:
        ConnectionError: EN: Peer closed socket before full payload.
            RU: Сокет закрыт до получения полного payload.
    """
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("socket closed")
        data.extend(chunk)
    return bytes(data)


def read_startup_message(sock: socket.socket, max_packet_bytes: int) -> bytes:
    """EN: Read PostgreSQL startup packet with hard size validation.
    RU: Прочитать startup-пакет PostgreSQL с жесткой валидацией размера.

    Args:
        sock (socket.socket): EN: Client socket. RU: Клиентский сокет.
        max_packet_bytes (int): EN: Maximum allowed packet size.
            RU: Максимально допустимый размер пакета.

    Returns:
        bytes: EN: Full startup packet including length header.
            RU: Полный startup-пакет вместе с заголовком длины.

    Raises:
        ConnectionError: EN: Invalid packet length or size limit exceeded.
            RU: Некорректная длина пакета или превышение лимита.
    """
    header = read_exact(sock, 4)
    size = struct.unpack("!I", header)[0]
    if size < 4:
        raise ConnectionError("invalid PostgreSQL startup packet length")
    if size > max_packet_bytes:
        raise ConnectionError(
            f"startup packet is too large ({size} bytes > limit {max_packet_bytes} bytes)"
        )
    return header + read_exact(sock, size - 4)


def read_protocol_message(sock: socket.socket, max_packet_bytes: int) -> bytes:
    """EN: Read regular PostgreSQL protocol message with size checks.
    RU: Прочитать обычное сообщение PostgreSQL-протокола с проверками размера.

    Args:
        sock (socket.socket): EN: Socket to read from. RU: Сокет чтения.
        max_packet_bytes (int): EN: Maximum allowed message size.
            RU: Максимально допустимый размер сообщения.

    Returns:
        bytes: EN: Full protocol frame (type + length + payload).
            RU: Полный протокольный фрейм (type + length + payload).

    Raises:
        ConnectionError: EN: Invalid message size or configured limit exceeded.
            RU: Неверный размер сообщения или превышение лимита.
    """
    header = read_exact(sock, 5)
    size = struct.unpack("!I", header[1:])[0]
    if size < 4:
        raise ConnectionError("invalid PostgreSQL packet length")
    if size > max_packet_bytes:
        raise ConnectionError(
            f"protocol packet is too large ({size} bytes > limit {max_packet_bytes} bytes)"
        )
    return header + read_exact(sock, size - 4)
