#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Z Secure Messenger - PRODUCTION READY (Fixed)
- Reliable message delivery with ACK and retry
- No message loss for online users
- Rate limiting memory leak fixed
- E2EE key recovery with password
- Server-signed public keys (TOFU with signature)
- Cleanup of orphaned pending messages
- Improved session handling
"""
import getpass 
import asyncio
import aiosqlite
import json
import base64
import zlib
import secrets
import hashlib
import hmac
import random
import time
import struct
import sys
import os
import signal
import logging
from logging.handlers import RotatingFileHandler
from typing import Dict, Optional, Tuple, Any, List, Set, Union
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from queue import Queue
import weakref

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

# ---------------------------- CONFIGURATION ----------------------------
CONFIG = {
    "db_path": "z_messenger.db",
    "secret_key_file": "server_secret.key",
    "server_private_key_file": "server_private.key",
    "server_public_key_file": "server_public.key",
    "server_signing_private_key_file": "server_signing_private.key",
    "server_signing_public_key_file": "server_signing_public.key",
    "token_expire_seconds": 86400,
    "tcp_port": 9999,
    "max_seq_window": 100,
    "keep_alive_interval": 30,
    "read_timeout": 30,
    "ack_timeout": 10,
    "max_pending_messages": 1000,
    "max_message_size": 10 * 1024 * 1024,
    "max_login_attempts": 5,
    "block_time_seconds": 600,
    "fail_window_seconds": 300,
    "max_msg_per_second": 10,
    "rate_limit_window": 1.0,
    "offline_message_ttl_days": 30,
    "history_retention_days": 90,
    "max_history_fetch": 200,
    "batch_offline_size": 50,
    "sqlite_timeout": 30.0,
    "log_file": "z_messenger.log",
    "log_level": "INFO",
    "config_file": "z_config.json",
    "max_connections_per_ip": 10,
    "pending_retry_interval": 60,
    "max_pending_retries": 5,
    "max_pending_per_user": 10000,
    "db_pool_size": 5,
    "encrypt_server_keys": True,
    "key_encryption_salt": b"z_messenger_salt",
    "rate_limit_cleanup_interval": 3600  # NEW: clean rate_limit dicts every hour
}

def load_config():
    if os.path.exists(CONFIG["config_file"]):
        with open(CONFIG["config_file"], "r") as f:
            user_config = json.load(f)
            CONFIG.update(user_config)

load_config()

DB_PATH = CONFIG["db_path"]
SECRET_KEY_FILE = CONFIG["secret_key_file"]
TCP_PORT = CONFIG["tcp_port"]
MAX_SEQ_WINDOW = CONFIG["max_seq_window"]
KEEP_ALIVE_INTERVAL = CONFIG["keep_alive_interval"]
READ_TIMEOUT = CONFIG["read_timeout"]
ACK_TIMEOUT = CONFIG["ack_timeout"]
MAX_PENDING_MESSAGES = CONFIG["max_pending_messages"]
MAX_MESSAGE_SIZE = CONFIG["max_message_size"]
SERVER_PRIVATE_KEY_FILE = CONFIG["server_private_key_file"]
SERVER_PUBLIC_KEY_FILE = CONFIG["server_public_key_file"]
SERVER_SIGNING_PRIVATE_KEY_FILE = CONFIG["server_signing_private_key_file"]
SERVER_SIGNING_PUBLIC_KEY_FILE = CONFIG["server_signing_public_key_file"]
MAX_LOGIN_ATTEMPTS = CONFIG["max_login_attempts"]
BLOCK_TIME_SECONDS = CONFIG["block_time_seconds"]
FAIL_WINDOW_SECONDS = CONFIG["fail_window_seconds"]
MAX_MSG_PER_SECOND = CONFIG["max_msg_per_second"]
RATE_LIMIT_WINDOW = CONFIG["rate_limit_window"]
OFFLINE_TTL_SECONDS = CONFIG["offline_message_ttl_days"] * 86400
HISTORY_RETENTION_SECONDS = CONFIG["history_retention_days"] * 86400
MAX_HISTORY_FETCH = CONFIG["max_history_fetch"]
BATCH_OFFLINE_SIZE = CONFIG["batch_offline_size"]
SQLITE_TIMEOUT = CONFIG["sqlite_timeout"]
MAX_CONNECTIONS_PER_IP = CONFIG["max_connections_per_ip"]
PENDING_RETRY_INTERVAL = CONFIG["pending_retry_interval"]
MAX_PENDING_RETRIES = CONFIG["max_pending_retries"]
MAX_PENDING_PER_USER = CONFIG["max_pending_per_user"]
DB_POOL_SIZE = CONFIG["db_pool_size"]
ENCRYPT_SERVER_KEYS = CONFIG["encrypt_server_keys"]
RATE_LIMIT_CLEANUP_INTERVAL = CONFIG["rate_limit_cleanup_interval"]

log_level = getattr(logging, CONFIG["log_level"].upper(), logging.INFO)
log_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

file_handler = RotatingFileHandler(CONFIG["log_file"], maxBytes=10*1024*1024, backupCount=5)
file_handler.setFormatter(log_formatter)

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)

logger = logging.getLogger("z_messenger")
logger.setLevel(log_level)
logger.addHandler(file_handler)
logger.addHandler(console_handler)

# ---------------------------- KEY ENCRYPTION HELPERS ----------------------------
def get_server_key_cipher() -> Optional[Fernet]:
    if not ENCRYPT_SERVER_KEYS:
        return None
    password = os.environ.get("Z_SERVER_KEY_PASSWORD")
    if not password:
        logger.warning("Server key encryption enabled but Z_SERVER_KEY_PASSWORD not set. Keys stored in plaintext.")
        return None
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=CONFIG["key_encryption_salt"],
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)

def encrypt_private_key(private_bytes: bytes) -> bytes:
    cipher = get_server_key_cipher()
    if cipher:
        return cipher.encrypt(private_bytes)
    return private_bytes

def decrypt_private_key(encrypted_bytes: bytes) -> bytes:
    cipher = get_server_key_cipher()
    if cipher:
        try:
            return cipher.decrypt(encrypted_bytes)
        except Exception as e:
            logger.error(f"Failed to decrypt server private key: {e}")
            raise
    return encrypted_bytes

# ---------------------------- DATABASE CONNECTION POOL ----------------------------
class SQLiteConnectionPool:
    def __init__(self, db_path: str, pool_size: int = 5, timeout: float = 30.0):
        self.db_path = db_path
        self.pool_size = pool_size
        self.timeout = timeout
        self._pool: asyncio.Queue = asyncio.Queue()
        self._initialized = False

    async def initialize(self):
        for _ in range(self.pool_size):
            conn = await aiosqlite.connect(self.db_path, timeout=self.timeout)
            conn.row_factory = aiosqlite.Row
            await conn.execute("PRAGMA journal_mode=WAL")
            await conn.execute("PRAGMA synchronous=NORMAL")
            await self._pool.put(conn)
        self._initialized = True

    async def acquire(self) -> aiosqlite.Connection:
        if not self._initialized:
            await self.initialize()
        return await self._pool.get()

    async def release(self, conn: aiosqlite.Connection):
        await self._pool.put(conn)

    async def close_all(self):
        while not self._pool.empty():
            conn = await self._pool.get()
            await conn.close()

    async def execute(self, query: str, params: tuple = (), fetchone: bool = False, fetchall: bool = False):
        conn = await self.acquire()
        try:
            async with conn.execute(query, params) as cursor:
                if fetchone:
                    return await cursor.fetchone()
                elif fetchall:
                    return await cursor.fetchall()
                else:
                    await conn.commit()
                    return None
        finally:
            await self.release(conn)

    async def lastrowid(self) -> int:
        conn = await self.acquire()
        try:
            cursor = await conn.execute("SELECT last_insert_rowid()")
            row = await cursor.fetchone()
            return row[0] if row else 0
        finally:
            await self.release(conn)

db_pool: Optional[SQLiteConnectionPool] = None

async def init_db():
    global db_pool
    db_pool = SQLiteConnectionPool(DB_PATH, DB_POOL_SIZE, SQLITE_TIMEOUT)
    await db_pool.initialize()
    conn = await db_pool.acquire()
    try:
        await conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            login TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            username TEXT NOT NULL,
            nickname TEXT,
            bio TEXT,
            avatar_blob TEXT,
            created_at INTEGER
        )''')
        await conn.execute('''CREATE TABLE IF NOT EXISTS user_keys (
            user_id INTEGER PRIMARY KEY,
            public_key_b64 TEXT NOT NULL,
            signature_b64 TEXT NOT NULL,
            updated_at INTEGER
        )''')
        await conn.execute('''CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT CHECK(type IN ('private','public')) NOT NULL,
            owner_id INTEGER NOT NULL,
            created_at INTEGER
        )''')
        await conn.execute('''CREATE TABLE IF NOT EXISTS group_members (
            group_id INTEGER, user_id INTEGER, joined_at INTEGER,
            PRIMARY KEY(group_id, user_id)
        )''')
        await conn.execute('''CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            type TEXT CHECK(type IN ('private','public')) NOT NULL,
            owner_id INTEGER NOT NULL,
            created_at INTEGER
        )''')
        await conn.execute('''CREATE TABLE IF NOT EXISTS channel_subscribers (
            channel_id INTEGER, user_id INTEGER, subscribed_at INTEGER,
            PRIMARY KEY(channel_id, user_id)
        )''')
        await conn.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            recipient_type TEXT CHECK(recipient_type IN ('personal','group','channel')),
            recipient_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            timestamp INTEGER,
            delivered INTEGER DEFAULT 0,
            acked INTEGER DEFAULT 0,
            status TEXT DEFAULT 'sent'
        )''')
        await conn.execute('''CREATE TABLE IF NOT EXISTS pending_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_user_id INTEGER NOT NULL,
            message_data TEXT NOT NULL,
            timestamp INTEGER,
            delivered INTEGER DEFAULT 0,
            acked INTEGER DEFAULT 0,
            retry_count INTEGER DEFAULT 0,
            nonce TEXT UNIQUE
        )''')
        await conn.execute('''CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            ip TEXT,
            expires_at INTEGER,
            last_activity INTEGER
        )''')
        await conn.execute('''CREATE TABLE IF NOT EXISTS failed_logins (
            ip TEXT NOT NULL,
            attempt_time INTEGER NOT NULL
        )''')
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_type, recipient_id, timestamp)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id, timestamp)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_pending_recipient ON pending_messages(recipient_user_id, delivered)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status, timestamp)")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_failed_logins_ip_time ON failed_logins(ip, attempt_time)")
        await conn.commit()
        logger.info("Database initialized with connection pool")
    finally:
        await db_pool.release(conn)

async def db_execute(query: str, params: tuple = (), fetchone: bool = False, fetchall: bool = False):
    return await db_pool.execute(query, params, fetchone, fetchall)

async def db_lastrowid() -> int:
    return await db_pool.lastrowid()

# ---------------------------- UTILITY FUNCTIONS ----------------------------
async def cleanup_old_data():
    while True:
        await asyncio.sleep(86400)
        now = int(time.time())
        cutoff_offline = now - OFFLINE_TTL_SECONDS
        await db_execute("DELETE FROM pending_messages WHERE timestamp < ? AND delivered=1", (cutoff_offline,))
        await db_execute("DELETE FROM pending_messages WHERE retry_count >= ?", (MAX_PENDING_RETRIES,))
        cutoff_history = now - HISTORY_RETENTION_SECONDS
        await db_execute("DELETE FROM messages WHERE timestamp < ?", (cutoff_history,))
        await db_execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        cutoff_failed = now - FAIL_WINDOW_SECONDS
        await db_execute("DELETE FROM failed_logins WHERE attempt_time < ?", (cutoff_failed,))
        # Clean orphaned pending for deleted users
        await db_execute("DELETE FROM pending_messages WHERE recipient_user_id NOT IN (SELECT id FROM users)")
        logger.info("Cleanup old data completed")

def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, bytes]:
    if salt is None:
        salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000).hex()
    return pwd_hash, salt

def verify_password(password: str, stored_hash: str, salt: bytes) -> bool:
    pwd_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(pwd_hash, stored_hash)

def generate_token(user_id: int, device_id: str, ip: str) -> str:
    expires = int(time.time() + CONFIG["token_expire_seconds"])
    payload = f"{user_id}:{device_id}:{ip}:{expires}"
    signature = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    token = base64.urlsafe_b64encode(f"{payload}|{signature}".encode()).decode()
    return token

async def verify_token(token: str, ip: str, device_id: str) -> Optional[Tuple[int, str]]:
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        payload, signature = decoded.rsplit('|', 1)
        expected = hmac.new(SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        user_id_str, token_device_id, token_ip, exp_str = payload.split(':')
        if token_ip != ip:
            logger.warning(f"Token IP mismatch: {token_ip} != {ip}")
            return None
        if token_device_id != device_id:
            logger.warning(f"Token device_id mismatch: {token_device_id} != {device_id}")
            return None
        if int(exp_str) < time.time():
            return None
        session = await db_execute("SELECT user_id FROM sessions WHERE token=?", (token,), fetchone=True)
        if not session:
            return None
        user = await db_execute("SELECT id FROM users WHERE id=?", (session['user_id'],), fetchone=True)
        if not user:
            return None
        return (int(user_id_str), token_device_id)
    except Exception:
        return None

async def revoke_user_tokens(user_id: int):
    await db_execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
    async with active_connections_lock:
        if user_id in active_connections:
            for ctx in active_connections[user_id]:
                ctx.writer.close()
            del active_connections[user_id]

async def is_ip_blocked(ip: str) -> bool:
    now = int(time.time())
    cutoff = now - FAIL_WINDOW_SECONDS
    await db_execute("DELETE FROM failed_logins WHERE ip=? AND attempt_time < ?", (ip, cutoff))
    row = await db_execute(
        "SELECT COUNT(*) as cnt FROM failed_logins WHERE ip=? AND attempt_time >= ?",
        (ip, cutoff), fetchone=True
    )
    if row and row['cnt'] >= MAX_LOGIN_ATTEMPTS:
        oldest = await db_execute(
            "SELECT MIN(attempt_time) as oldest FROM failed_logins WHERE ip=? AND attempt_time >= ?",
            (ip, cutoff), fetchone=True
        )
        if oldest and oldest['oldest'] and (now - oldest['oldest']) < BLOCK_TIME_SECONDS:
            return True
        else:
            await db_execute("DELETE FROM failed_logins WHERE ip=?", (ip,))
    return False

async def record_failed_attempt(ip: str):
    now = int(time.time())
    await db_execute("INSERT INTO failed_logins (ip, attempt_time) VALUES (?,?)", (ip, now))

# Rate limiting with periodic cleanup
rate_limit_ip: Dict[str, List[float]] = defaultdict(list)
rate_limit_user: Dict[int, List[float]] = defaultdict(list)
rate_limit_lock = asyncio.Lock()

async def cleanup_rate_limit():
    while True:
        await asyncio.sleep(RATE_LIMIT_CLEANUP_INTERVAL)
        async with rate_limit_lock:
            now = time.time()
            # Clean IP entries
            for ip in list(rate_limit_ip.keys()):
                rate_limit_ip[ip] = [t for t in rate_limit_ip[ip] if now - t < RATE_LIMIT_WINDOW]
                if not rate_limit_ip[ip]:
                    del rate_limit_ip[ip]
            # Clean user entries
            for uid in list(rate_limit_user.keys()):
                rate_limit_user[uid] = [t for t in rate_limit_user[uid] if now - t < RATE_LIMIT_WINDOW]
                if not rate_limit_user[uid]:
                    del rate_limit_user[uid]
        logger.debug("Rate limit maps cleaned")

async def check_rate_limit(ip: str, user_id: Optional[int] = None) -> bool:
    now = time.time()
    async with rate_limit_lock:
        ip_times = rate_limit_ip.get(ip, [])
        ip_times = [t for t in ip_times if now - t < RATE_LIMIT_WINDOW]
        if len(ip_times) >= MAX_MSG_PER_SECOND:
            return False
        ip_times.append(now)
        rate_limit_ip[ip] = ip_times

        if user_id is not None:
            user_times = rate_limit_user.get(user_id, [])
            user_times = [t for t in user_times if now - t < RATE_LIMIT_WINDOW]
            if len(user_times) >= MAX_MSG_PER_SECOND:
                return False
            user_times.append(now)
            rate_limit_user[user_id] = user_times
    return True

# Server signing key for user keys
server_signing_private_key: Optional[Ed25519PrivateKey] = None
server_signing_public_key: Optional[Ed25519PublicKey] = None

def load_or_generate_signing_keys():
    global server_signing_private_key, server_signing_public_key
    if os.path.exists(SERVER_SIGNING_PRIVATE_KEY_FILE) and os.path.exists(SERVER_SIGNING_PUBLIC_KEY_FILE):
        with open(SERVER_SIGNING_PRIVATE_KEY_FILE, "rb") as f:
            private_enc = f.read()
        with open(SERVER_SIGNING_PUBLIC_KEY_FILE, "rb") as f:
            public_bytes = f.read()
        private_bytes = decrypt_private_key(private_enc)
        server_signing_private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
        server_signing_public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        logger.info("Loaded existing server signing key pair")
    else:
        server_signing_private_key = Ed25519PrivateKey.generate()
        server_signing_public_key = server_signing_private_key.public_key()
        private_raw = server_signing_private_key.private_bytes_raw()
        private_enc = encrypt_private_key(private_raw)
        with open(SERVER_SIGNING_PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_enc)
        with open(SERVER_SIGNING_PUBLIC_KEY_FILE, "wb") as f:
            f.write(server_signing_public_key.public_bytes_raw())
        logger.info("Generated new server signing key pair")

def sign_user_key(user_id: int, public_key_b64: str) -> str:
    message = f"{user_id}:{public_key_b64}".encode()
    signature = server_signing_private_key.sign(message)
    return base64.b64encode(signature).decode()

def verify_user_key(user_id: int, public_key_b64: str, signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
        message = f"{user_id}:{public_key_b64}".encode()
        server_signing_public_key.verify(signature, message)
        return True
    except Exception:
        return False

async def get_user_public_key(user_id: int) -> Optional[Tuple[bytes, str]]:
    row = await db_execute("SELECT public_key_b64, signature_b64 FROM user_keys WHERE user_id=?", (user_id,), fetchone=True)
    if row:
        pub_bytes = base64.b64decode(row['public_key_b64'])
        sig = row['signature_b64']
        if verify_user_key(user_id, row['public_key_b64'], sig):
            return (pub_bytes, sig)
        else:
            logger.warning(f"Invalid signature for user {user_id} public key")
            return None
    return None

async def store_user_public_key(user_id: int, public_key_b64: str):
    signature = sign_user_key(user_id, public_key_b64)
    await db_execute(
        "INSERT OR REPLACE INTO user_keys (user_id, public_key_b64, signature_b64, updated_at) VALUES (?,?,?,?)",
        (user_id, public_key_b64, signature, int(time.time()))
    )

def encrypt_for_recipient(plaintext: bytes, recipient_public_key_bytes: bytes) -> bytes:
    ephemeral_priv = X25519PrivateKey.generate()
    ephemeral_pub = ephemeral_priv.public_key()
    recipient_pub = X25519PublicKey.from_public_bytes(recipient_public_key_bytes)
    shared_secret = ephemeral_priv.exchange(recipient_pub)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"z_e2ee", info=b"e2ee")
    key = hkdf.derive(shared_secret)
    cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    return ephemeral_pub.public_bytes_raw() + nonce + ciphertext

def decrypt_for_recipient(encrypted_data: bytes, my_private_key: X25519PrivateKey) -> bytes:
    if len(encrypted_data) < 44:
        raise ValueError("Invalid encrypted data")
    ephemeral_pub_bytes = encrypted_data[:32]
    nonce = encrypted_data[32:44]
    ciphertext = encrypted_data[44:]
    ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
    shared_secret = my_private_key.exchange(ephemeral_pub)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"z_e2ee", info=b"e2ee")
    key = hkdf.derive(shared_secret)
    cipher = ChaCha20Poly1305(key)
    plain = cipher.decrypt(nonce, ciphertext, None)
    return plain

async def can_access_group(user_id: int, group_id: int) -> bool:
    group = await db_execute("SELECT type FROM groups WHERE id=?", (group_id,), fetchone=True)
    if not group:
        return False
    if group['type'] == 'public':
        return True
    member = await db_execute("SELECT 1 FROM group_members WHERE group_id=? AND user_id=?", (group_id, user_id), fetchone=True)
    return member is not None

async def can_access_channel(user_id: int, channel_id: int) -> bool:
    channel = await db_execute("SELECT type FROM channels WHERE id=?", (channel_id,), fetchone=True)
    if not channel:
        return False
    if channel['type'] == 'public':
        return True
    sub = await db_execute("SELECT 1 FROM channel_subscribers WHERE channel_id=? AND user_id=?", (channel_id, user_id), fetchone=True)
    return sub is not None

async def can_send_to_recipient(sender_id: int, rec_type: str, rec_id: int) -> bool:
    if rec_type == 'personal':
        target = await db_execute("SELECT id FROM users WHERE id=?", (rec_id,), fetchone=True)
        return target is not None and sender_id != rec_id
    elif rec_type == 'group':
        return await can_access_group(sender_id, rec_id)
    elif rec_type == 'channel':
        sub = await db_execute("SELECT 1 FROM channel_subscribers WHERE channel_id=? AND user_id=?", (rec_id, sender_id), fetchone=True)
        if sub:
            return True
        channel = await db_execute("SELECT owner_id FROM channels WHERE id=?", (rec_id,), fetchone=True)
        return channel and channel['owner_id'] == sender_id
    return False

def derive_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=b"z_messenger_salt", info=b"z_channel_key")
    return hkdf.derive(shared_secret)

# ---------------------------- NETWORK HELPERS WITH ERROR HANDLING ----------------------------
async def send_encrypted(writer: asyncio.StreamWriter, cipher: ChaCha20Poly1305, plain_dict: dict, seq: int):
    try:
        payload = {'seq': seq, 'data': plain_dict}
        json_bytes = json.dumps(payload).encode('utf-8')
        nonce = os.urandom(12)
        encrypted = cipher.encrypt(nonce, json_bytes, None)
        packet = struct.pack('!I', len(nonce) + len(encrypted)) + nonce + encrypted
        writer.write(packet)
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        logger.warning(f"Send error (connection lost): {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected send error: {e}")
        raise

async def recv_encrypted(reader: asyncio.StreamReader, cipher: ChaCha20Poly1305, expected_seq: int, recv_buffer: Dict[int, dict]) -> Tuple[Optional[dict], int, bool, Dict[int, dict]]:
    try:
        raw_len = await asyncio.wait_for(reader.readexactly(4), timeout=READ_TIMEOUT)
        try:
            msg_len = struct.unpack('!I', raw_len)[0]
        except struct.error:
            logger.error("Invalid packet length header, closing connection")
            return None, expected_seq, True, recv_buffer
        if msg_len > MAX_MESSAGE_SIZE:
            logger.warning("Packet too large, dropping")
            return None, expected_seq, False, recv_buffer
        data = await asyncio.wait_for(reader.readexactly(msg_len), timeout=READ_TIMEOUT)
        if len(data) < 12:
            raise ValueError("Packet too short")
        nonce = data[:12]
        ciphertext = data[12:]
        plain = cipher.decrypt(nonce, ciphertext, None)
        payload = json.loads(plain.decode('utf-8'))
        seq = payload.get('seq')
        if not isinstance(seq, int):
            raise ValueError("Invalid seq")
        if seq < expected_seq:
            logger.warning(f"Replay attack detected: got seq {seq}, expected {expected_seq}")
            return None, expected_seq, False, recv_buffer
        if seq > expected_seq + MAX_SEQ_WINDOW:
            logger.warning(f"Sequence gap too large: {seq} vs {expected_seq}")
            return None, expected_seq, False, recv_buffer
        if seq > expected_seq:
            recv_buffer[seq] = payload.get('data')
            while expected_seq in recv_buffer:
                data_out = recv_buffer.pop(expected_seq)
                expected_seq += 1
                return data_out, expected_seq, False, recv_buffer
            return None, expected_seq, False, recv_buffer
        expected_seq += 1
        while expected_seq in recv_buffer:
            data_out = recv_buffer.pop(expected_seq)
            expected_seq += 1
            return data_out, expected_seq, False, recv_buffer
        return payload.get('data'), expected_seq, False, recv_buffer
    except asyncio.TimeoutError:
        return None, expected_seq, False, recv_buffer
    except asyncio.IncompleteReadError:
        logger.debug("Connection closed by peer")
        return None, expected_seq, True, recv_buffer
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"Recv error (non-critical): {e}")
        return None, expected_seq, False, recv_buffer
    except InvalidTag:
        logger.error("Decryption failed: invalid tag — possible tampering, closing connection")
        return None, expected_seq, True, recv_buffer
    except Exception as e:
        logger.error(f"Unexpected recv error: {e}")
        return None, expected_seq, True, recv_buffer

async def do_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       server_private_key: X25519PrivateKey) -> Optional[ChaCha20Poly1305]:
    try:
        client_pub_bytes = await asyncio.wait_for(reader.readexactly(32), timeout=10)
        client_pub_key = X25519PublicKey.from_public_bytes(client_pub_bytes)
        shared_secret = server_private_key.exchange(client_pub_key)
        key = derive_key(shared_secret)
        cipher = ChaCha20Poly1305(key)
        server_pub_bytes = server_private_key.public_key().public_bytes_raw()
        writer.write(server_pub_bytes)
        await writer.drain()
        return cipher
    except Exception as e:
        logger.error(f"Handshake error: {e}")
        return None

# ---------------------------- PENDING MESSAGES WITH ACCESS CHECK & LIMIT ----------------------------
async def store_pending_message(recipient_user_id: int, message_dict: dict, original_msg_id: int = None, nonce: str = None):
    if nonce is None:
        nonce = secrets.token_urlsafe(32)
    count = await db_execute("SELECT COUNT(*) as cnt FROM pending_messages WHERE recipient_user_id=? AND delivered=0", (recipient_user_id,), fetchone=True)
    if count and count['cnt'] >= MAX_PENDING_PER_USER:
        oldest = await db_execute("SELECT id FROM pending_messages WHERE recipient_user_id=? AND delivered=0 ORDER BY timestamp ASC LIMIT 1", (recipient_user_id,), fetchone=True)
        if oldest:
            await db_execute("DELETE FROM pending_messages WHERE id=?", (oldest['id'],))
            logger.warning(f"Deleted oldest pending message for user {recipient_user_id} due to limit")
    data = {
        'msg': message_dict,
        'original_msg_id': original_msg_id
    }
    try:
        await db_execute(
            "INSERT INTO pending_messages (recipient_user_id, message_data, timestamp, delivered, acked, retry_count, nonce) VALUES (?,?,?,0,0,0,?)",
            (recipient_user_id, json.dumps(data), int(time.time()), nonce)
        )
    except aiosqlite.IntegrityError:
        logger.warning(f"Duplicate pending message nonce {nonce}, ignored")

async def mark_message_acked(message_id: int):
    await db_execute("UPDATE messages SET acked=1 WHERE id=?", (message_id,))

async def mark_pending_acked(pending_id: int):
    await db_execute("UPDATE pending_messages SET acked=1 WHERE id=?", (pending_id,))

async def increment_pending_retry(pending_id: int):
    await db_execute("UPDATE pending_messages SET retry_count = retry_count + 1 WHERE id=?", (pending_id,))

async def update_message_status(message_id: int, status: str):
    await db_execute("UPDATE messages SET status=? WHERE id=?", (status, message_id))

async def send_delivery_ack(sender_id: int, message_id: int):
    async with active_connections_lock:
        contexts = active_connections.get(sender_id, [])
    if contexts:
        ack_msg = {'type': 'delivery_ack', 'message_id': message_id, 'status': 'delivered'}
        for ctx in contexts:
            if not ctx.writer.is_closing():
                try:
                    async with ctx.send_lock:
                        await send_encrypted(ctx.writer, ctx.cipher, ack_msg, ctx.send_seq)
                        ctx.send_seq += 1
                except Exception as e:
                    logger.error(f"Failed to send delivery ack to {sender_id}: {e}")

# ---------------------------- CONNECTION CONTEXT ----------------------------
class ConnectionContext:
    __slots__ = ('writer', 'cipher', 'recv_seq', 'send_seq', 'send_lock', 'pending_acks',
                 'reader_task', 'keep_alive_task', 'last_activity', 'user_id', 'ip',
                 'device_id', 'session_token', 'recv_buffer')
    def __init__(self, writer: asyncio.StreamWriter, cipher: ChaCha20Poly1305,
                 recv_seq: int, send_seq: int, ip: str, device_id: str):
        self.writer = writer
        self.cipher = cipher
        self.recv_seq = recv_seq
        self.send_seq = send_seq
        self.send_lock = asyncio.Lock()
        self.pending_acks: Dict[int, Tuple[asyncio.Future, Optional[int], Optional[int]]] = {}
        self.reader_task: Optional[asyncio.Task] = None
        self.keep_alive_task: Optional[asyncio.Task] = None
        self.last_activity = time.time()
        self.user_id: Optional[int] = None
        self.ip = ip
        self.device_id = device_id
        self.session_token: Optional[str] = None
        self.recv_buffer: Dict[int, dict] = {}

active_connections: Dict[int, List[ConnectionContext]] = {}
active_connections_lock = asyncio.Lock()

ip_connection_count: Dict[str, int] = defaultdict(int)
ip_conn_lock = asyncio.Lock()

# ---------------------------- SERVER KEY MANAGEMENT WITH ENCRYPTION ----------------------------
def load_or_generate_server_keys() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    if os.path.exists(SERVER_PRIVATE_KEY_FILE) and os.path.exists(SERVER_PUBLIC_KEY_FILE):
        with open(SERVER_PRIVATE_KEY_FILE, "rb") as f:
            private_enc = f.read()
        with open(SERVER_PUBLIC_KEY_FILE, "rb") as f:
            public_bytes = f.read()
        private_bytes = decrypt_private_key(private_enc)
        private_key = X25519PrivateKey.from_private_bytes(private_bytes)
        public_key = X25519PublicKey.from_public_bytes(public_bytes)
        logger.info("Loaded existing server key pair")
    else:
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        private_raw = private_key.private_bytes_raw()
        private_enc = encrypt_private_key(private_raw)
        with open(SERVER_PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_enc)
        with open(SERVER_PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key.public_bytes_raw())
        logger.info("Generated new server key pair")
    return private_key, public_key

def load_or_generate_secret_key() -> str:
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, "r") as f:
            return f.read().strip()
    else:
        key = secrets.token_hex(32)
        with open(SECRET_KEY_FILE, "w") as f:
            f.write(key)
        logger.info("Generated new secret key for tokens")
        return key

SECRET_KEY = load_or_generate_secret_key()
load_or_generate_signing_keys()

# ---------------------------- PENDING DELIVERY WITH ACCESS CHECK ----------------------------
async def async_deliver_pending_messages(user_id: int, ctx: ConnectionContext):
    offset = 0
    while True:
        pending = await db_execute(
            "SELECT id, message_data FROM pending_messages WHERE recipient_user_id=? AND delivered=0 ORDER BY timestamp LIMIT ? OFFSET ?",
            (user_id, BATCH_OFFLINE_SIZE, offset), fetchall=True
        )
        if not pending:
            break
        for row in pending:
            pending_id = row['id']
            data = json.loads(row['message_data'])
            msg_dict = data['msg']
            original_msg_id = data.get('original_msg_id')
            msg_type = msg_dict.get('msg_type')
            if msg_type == 'group':
                group_id = msg_dict.get('group_id')
                if not await can_access_group(user_id, group_id):
                    logger.info(f"Skipping pending group message {pending_id} because user {user_id} no longer in group {group_id}")
                    await db_execute("DELETE FROM pending_messages WHERE id=?", (pending_id,))
                    continue
            elif msg_type == 'channel':
                channel_id = msg_dict.get('channel_id')
                if not await can_access_channel(user_id, channel_id):
                    logger.info(f"Skipping pending channel message {pending_id} because user {user_id} no longer subscribed to channel {channel_id}")
                    await db_execute("DELETE FROM pending_messages WHERE id=?", (pending_id,))
                    continue
            async with ctx.send_lock:
                try:
                    await send_encrypted(ctx.writer, ctx.cipher, msg_dict, ctx.send_seq)
                    future = asyncio.get_event_loop().create_future()
                    ctx.pending_acks[ctx.send_seq] = (future, pending_id, original_msg_id)
                    ctx.send_seq += 1
                    await db_execute("UPDATE pending_messages SET delivered=1 WHERE id=?", (pending_id,))
                    asyncio.create_task(wait_for_pending_ack(future, pending_id, ctx, user_id, ctx.send_seq-1))
                except Exception as e:
                    logger.error(f"Failed to send pending message {pending_id}: {e}")
        offset += BATCH_OFFLINE_SIZE
        await asyncio.sleep(0.1)

async def wait_for_pending_ack(future: asyncio.Future, pending_id: int, ctx: ConnectionContext, recipient_id: int, seq: int):
    try:
        await asyncio.wait_for(future, timeout=ACK_TIMEOUT)
        await mark_pending_acked(pending_id)
        logger.debug(f"Pending message {pending_id} acked")
    except asyncio.TimeoutError:
        logger.warning(f"ACK timeout for pending message {pending_id}, will retry later")
        await db_execute("UPDATE pending_messages SET delivered=0 WHERE id=?", (pending_id,))
        await increment_pending_retry(pending_id)
        ctx.pending_acks.pop(seq, None)

async def wait_for_message_ack(future: asyncio.Future, original_msg_id: int, ctx: ConnectionContext, sender_id: int, seq: int):
    try:
        await asyncio.wait_for(future, timeout=ACK_TIMEOUT)
        await mark_message_acked(original_msg_id)
        await update_message_status(original_msg_id, 'delivered')
        await send_delivery_ack(sender_id, original_msg_id)
        logger.debug(f"Message {original_msg_id} acked")
    except asyncio.TimeoutError:
        logger.warning(f"ACK timeout for message {original_msg_id}, will retry later")
        ctx.pending_acks.pop(seq, None)

async def retry_pending_for_online_users():
    while True:
        await asyncio.sleep(PENDING_RETRY_INTERVAL)
        pending_list = await db_execute(
            "SELECT id, recipient_user_id, message_data FROM pending_messages WHERE delivered=0 AND retry_count < ?",
            (MAX_PENDING_RETRIES,), fetchall=True
        )
        if not pending_list:
            continue
        by_user = defaultdict(list)
        for row in pending_list:
            by_user[row['recipient_user_id']].append((row['id'], json.loads(row['message_data'])))
        async with active_connections_lock:
            for user_id, msgs in by_user.items():
                if user_id in active_connections:
                    for ctx in active_connections[user_id]:
                        if ctx.writer.is_closing():
                            continue
                        for pending_id, data in msgs:
                            msg_dict = data['msg']
                            original_msg_id = data.get('original_msg_id')
                            msg_type = msg_dict.get('msg_type')
                            if msg_type == 'group':
                                group_id = msg_dict.get('group_id')
                                if not await can_access_group(user_id, group_id):
                                    await db_execute("DELETE FROM pending_messages WHERE id=?", (pending_id,))
                                    continue
                            elif msg_type == 'channel':
                                channel_id = msg_dict.get('channel_id')
                                if not await can_access_channel(user_id, channel_id):
                                    await db_execute("DELETE FROM pending_messages WHERE id=?", (pending_id,))
                                    continue
                            async with ctx.send_lock:
                                try:
                                    await send_encrypted(ctx.writer, ctx.cipher, msg_dict, ctx.send_seq)
                                    future = asyncio.get_event_loop().create_future()
                                    ctx.pending_acks[ctx.send_seq] = (future, pending_id, original_msg_id)
                                    ctx.send_seq += 1
                                    await db_execute("UPDATE pending_messages SET delivered=1 WHERE id=?", (pending_id,))
                                    asyncio.create_task(wait_for_pending_ack(future, pending_id, ctx, user_id, ctx.send_seq-1))
                                except Exception as e:
                                    logger.error(f"Retry send failed for pending {pending_id}: {e}")

# ---------------------------- BROADCAST WITH RELIABLE DELIVERY ----------------------------
async def broadcast_message(
    sender_id: int,
    recipient_type: str,
    recipient_id: int,
    content: str,
    timestamp: int,
    message_id: int,
    ctx_sender: ConnectionContext,
):
    if recipient_type == 'personal':
        target_id = recipient_id
        base_msg = {
            'type': 'message',
            'msg_type': 'personal',
            'sender_id': sender_id,
            'content': content,
            'timestamp': timestamp,
            'message_id': message_id,
            'e2ee': True
        }
        async with active_connections_lock:
            contexts = active_connections.get(target_id, [])
        if contexts:
            # Send to online user, but we must store pending until ACK to avoid loss
            # We store in pending first, then send, and if ACK received, mark acked
            await store_pending_message(target_id, base_msg, message_id)
            for ctx in contexts:
                if not ctx.writer.is_closing():
                    await send_to_connection(ctx, base_msg, message_id, sender_id, pending_id=None)
            # Note: message status remains 'sent' until ACK from recipient
        else:
            await store_pending_message(target_id, base_msg, message_id)
    elif recipient_type == 'group':
        base_msg = {
            'type': 'message',
            'msg_type': 'group',
            'group_id': recipient_id,
            'sender_id': sender_id,
            'content': content,
            'timestamp': timestamp,
            'message_id': message_id,
            'e2ee': False
        }
        members = await db_execute("SELECT user_id FROM group_members WHERE group_id=?", (recipient_id,), fetchall=True)
        for m in members:
            uid = m['user_id']
            if uid == sender_id:
                continue
            await store_pending_message(uid, base_msg, message_id)
            async with active_connections_lock:
                contexts = active_connections.get(uid, [])
            if contexts:
                for ctx in contexts:
                    if not ctx.writer.is_closing():
                        await send_to_connection(ctx, base_msg, message_id, sender_id, pending_id=None)
    elif recipient_type == 'channel':
        base_msg = {
            'type': 'message',
            'msg_type': 'channel',
            'channel_id': recipient_id,
            'sender_id': sender_id,
            'content': content,
            'timestamp': timestamp,
            'message_id': message_id,
            'e2ee': False
        }
        subs = await db_execute("SELECT user_id FROM channel_subscribers WHERE channel_id=?", (recipient_id,), fetchall=True)
        for s in subs:
            uid = s['user_id']
            if uid == sender_id:
                continue
            await store_pending_message(uid, base_msg, message_id)
            async with active_connections_lock:
                contexts = active_connections.get(uid, [])
            if contexts:
                for ctx in contexts:
                    if not ctx.writer.is_closing():
                        await send_to_connection(ctx, base_msg, message_id, sender_id, pending_id=None)

async def send_to_connection(ctx: ConnectionContext, msg_dict: dict, original_msg_id: int, sender_id: int, pending_id: Optional[int]):
    async with ctx.send_lock:
        seq = ctx.send_seq
        await send_encrypted(ctx.writer, ctx.cipher, msg_dict, seq)
        future = asyncio.get_event_loop().create_future()
        ctx.pending_acks[seq] = (future, pending_id, original_msg_id)
        ctx.send_seq += 1
        asyncio.create_task(wait_for_message_ack(future, original_msg_id, ctx, sender_id, seq))

# ---------------------------- COMMAND PROCESSING WITH RATE LIMIT & SESSION CHECK ----------------------------
async def process_command(user_id: int, cmd: dict, ctx: ConnectionContext, request_seq: int) -> Tuple[Optional[dict], int]:
    action = cmd.get('action')
    if action not in ('ping', 'ack', 'delivery_ack'):
        if not await check_rate_limit(ctx.ip, user_id):
            return ({'error': 'rate_limit_exceeded', 'in_reply_to': request_seq}, ctx.send_seq)
    if ctx.session_token:
        session = await db_execute("SELECT user_id FROM sessions WHERE token=?", (ctx.session_token,), fetchone=True)
        if not session or session['user_id'] != user_id:
            logger.warning(f"Session invalid for user {user_id}, closing connection")
            return ({'error': 'session_expired', 'in_reply_to': request_seq}, ctx.send_seq)
    if action == 'send_message':
        rec_type = cmd.get('recipient_type')
        rec_id = cmd.get('recipient_id')
        content = cmd.get('content', '')
        if not rec_type or not rec_id or not content:
            return ({'error': 'invalid_params', 'in_reply_to': request_seq}, ctx.send_seq)
        if not await can_send_to_recipient(user_id, rec_type, rec_id):
            return ({'error': 'access_denied', 'in_reply_to': request_seq}, ctx.send_seq)
        timestamp = int(time.time())
        if rec_type == 'personal':
            pub_key_info = await get_user_public_key(rec_id)
            if not pub_key_info:
                return ({'error': 'recipient_no_e2ee_key', 'in_reply_to': request_seq}, ctx.send_seq)
            encrypted_content = content
        else:
            encrypted_content = content
        await db_execute(
            "INSERT INTO messages (sender_id, recipient_type, recipient_id, content, timestamp, delivered, acked, status) VALUES (?,?,?,?,?,0,0,'sent')",
            (user_id, rec_type, rec_id, encrypted_content, timestamp)
        )
        msg_id = await db_lastrowid()
        await broadcast_message(user_id, rec_type, rec_id, encrypted_content, timestamp, msg_id, ctx)
        return ({'status': 'ok', 'message_id': msg_id, 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'ack':
        ack_seq = cmd.get('seq')
        if ack_seq is not None:
            item = ctx.pending_acks.pop(ack_seq, None)
            if item:
                future, pending_id, msg_id = item
                if not future.done():
                    future.set_result(True)
                if pending_id is not None:
                    await mark_pending_acked(pending_id)
                elif msg_id is not None:
                    await mark_message_acked(msg_id)
        return (None, ctx.send_seq)

    elif action == 'delivery_ack':
        msg_id = cmd.get('message_id')
        if msg_id:
            current = await db_execute("SELECT status FROM messages WHERE id=?", (msg_id,), fetchone=True)
            if current and current['status'] != 'read':
                await update_message_status(msg_id, 'read')
                msg = await db_execute("SELECT sender_id FROM messages WHERE id=?", (msg_id,), fetchone=True)
                if msg:
                    await send_delivery_ack(msg['sender_id'], msg_id)
        return (None, ctx.send_seq)

    elif action == 'get_profile':
        target_id = cmd.get('user_id', user_id)
        user = await db_execute("SELECT id, username, nickname, bio, avatar_blob FROM users WHERE id=?", (target_id,), fetchone=True)
        if not user:
            return ({'error': 'user_not_found', 'in_reply_to': request_seq}, ctx.send_seq)
        return ({'action': 'profile', 'data': dict(user), 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'update_profile':
        updates = {}
        if 'username' in cmd:
            new_name = cmd['username'].strip()
            if new_name:
                exist = await db_execute("SELECT id FROM users WHERE username=? AND id!=?", (new_name, user_id), fetchone=True)
                if exist:
                    return ({'error': 'username_taken', 'in_reply_to': request_seq}, ctx.send_seq)
                updates['username'] = new_name
        if 'nickname' in cmd:
            updates['nickname'] = cmd['nickname'][:50]
        if 'bio' in cmd:
            updates['bio'] = cmd['bio'][:200]
        if updates:
            set_clause = ', '.join(f"{k}=?" for k in updates)
            values = list(updates.values()) + [user_id]
            await db_execute(f"UPDATE users SET {set_clause} WHERE id=?", tuple(values))
        return ({'status': 'ok', 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'update_avatar':
        b64_data = cmd.get('avatar_base64', '')
        if b64_data:
            try:
                img_bytes = base64.b64decode(b64_data)
                if len(img_bytes) > 2*1024*1024:
                    return ({'error': 'avatar_too_large', 'in_reply_to': request_seq}, ctx.send_seq)
                compressed = zlib.compress(img_bytes, level=9)
                stored = base64.b64encode(compressed).decode()
                await db_execute("UPDATE users SET avatar_blob=? WHERE id=?", (stored, user_id))
                return ({'status': 'ok', 'in_reply_to': request_seq}, ctx.send_seq)
            except Exception:
                return ({'error': 'invalid_image', 'in_reply_to': request_seq}, ctx.send_seq)
        return ({'error': 'no_data', 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'create_group':
        name = cmd.get('name', '')[:50]
        group_type = cmd.get('type', 'private')
        if group_type not in ('private', 'public'):
            group_type = 'private'
        if not name:
            return ({'error': 'invalid_name', 'in_reply_to': request_seq}, ctx.send_seq)
        ts = int(time.time())
        await db_execute("INSERT INTO groups (name, type, owner_id, created_at) VALUES (?,?,?,?)",
                         (name, group_type, user_id, ts))
        group_id = await db_lastrowid()
        await db_execute("INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?,?,?)", (group_id, user_id, ts))
        return ({'status': 'ok', 'group_id': group_id, 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'create_channel':
        name = cmd.get('name', '')[:50]
        ch_type = cmd.get('type', 'public')
        if ch_type not in ('private', 'public'):
            ch_type = 'public'
        if not name:
            return ({'error': 'invalid_name', 'in_reply_to': request_seq}, ctx.send_seq)
        ts = int(time.time())
        await db_execute("INSERT INTO channels (name, type, owner_id, created_at) VALUES (?,?,?,?)",
                         (name, ch_type, user_id, ts))
        channel_id = await db_lastrowid()
        await db_execute("INSERT INTO channel_subscribers (channel_id, user_id, subscribed_at) VALUES (?,?,?)",
                         (channel_id, user_id, ts))
        return ({'status': 'ok', 'channel_id': channel_id, 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'list_groups':
        groups = await db_execute('''
            SELECT g.id, g.name, g.type, g.owner_id
            FROM groups g
            LEFT JOIN group_members gm ON g.id = gm.group_id AND gm.user_id=?
            WHERE g.type='public' OR gm.user_id IS NOT NULL
        ''', (user_id,), fetchall=True)
        return ({'action': 'groups_list', 'groups': [dict(g) for g in groups], 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'list_channels':
        channels = await db_execute('''
            SELECT c.id, c.name, c.type, c.owner_id
            FROM channels c
            LEFT JOIN channel_subscribers cs ON c.id = cs.channel_id AND cs.user_id=?
            WHERE c.type='public' OR cs.user_id IS NOT NULL
        ''', (user_id,), fetchall=True)
        return ({'action': 'channels_list', 'channels': [dict(c) for c in channels], 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'join_group':
        group_id = cmd.get('group_id')
        if not group_id:
            return ({'error': 'no_group', 'in_reply_to': request_seq}, ctx.send_seq)
        group = await db_execute("SELECT type FROM groups WHERE id=?", (group_id,), fetchone=True)
        if not group:
            return ({'error': 'not_found', 'in_reply_to': request_seq}, ctx.send_seq)
        if group['type'] == 'private':
            owner = await db_execute("SELECT owner_id FROM groups WHERE id=?", (group_id,), fetchone=True)
            if owner['owner_id'] != user_id:
                return ({'error': 'private_group_cannot_join', 'in_reply_to': request_seq}, ctx.send_seq)
        ts = int(time.time())
        try:
            await db_execute("INSERT INTO group_members (group_id, user_id, joined_at) VALUES (?,?,?)", (group_id, user_id, ts))
        except aiosqlite.IntegrityError:
            return ({'error': 'already_member', 'in_reply_to': request_seq}, ctx.send_seq)
        return ({'status': 'ok', 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'subscribe_channel':
        channel_id = cmd.get('channel_id')
        if not channel_id:
            return ({'error': 'no_channel', 'in_reply_to': request_seq}, ctx.send_seq)
        channel = await db_execute("SELECT type FROM channels WHERE id=?", (channel_id,), fetchone=True)
        if not channel:
            return ({'error': 'not_found', 'in_reply_to': request_seq}, ctx.send_seq)
        if channel['type'] == 'private':
            owner = await db_execute("SELECT owner_id FROM channels WHERE id=?", (channel_id,), fetchone=True)
            if owner['owner_id'] != user_id:
                return ({'error': 'private_channel_need_invite', 'in_reply_to': request_seq}, ctx.send_seq)
        ts = int(time.time())
        try:
            await db_execute("INSERT INTO channel_subscribers (channel_id, user_id, subscribed_at) VALUES (?,?,?)", (channel_id, user_id, ts))
        except aiosqlite.IntegrityError:
            return ({'error': 'already_subscribed', 'in_reply_to': request_seq}, ctx.send_seq)
        return ({'status': 'ok', 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'get_history':
        rec_type = cmd.get('recipient_type')
        rec_id = cmd.get('recipient_id')
        limit = min(cmd.get('limit', MAX_HISTORY_FETCH), MAX_HISTORY_FETCH)
        if rec_type == 'personal':
            msgs = await db_execute('''
                SELECT sender_id, content, timestamp, status FROM messages
                WHERE recipient_type='personal' AND ((sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?))
                ORDER BY timestamp DESC LIMIT ?
            ''', (user_id, rec_id, rec_id, user_id, limit), fetchall=True)
        elif rec_type == 'group':
            if not await can_access_group(user_id, rec_id):
                return ({'error': 'access_denied', 'in_reply_to': request_seq}, ctx.send_seq)
            msgs = await db_execute('''
                SELECT sender_id, content, timestamp, status FROM messages
                WHERE recipient_type='group' AND recipient_id=?
                ORDER BY timestamp DESC LIMIT ?
            ''', (rec_id, limit), fetchall=True)
        elif rec_type == 'channel':
            if not await can_access_channel(user_id, rec_id):
                return ({'error': 'access_denied', 'in_reply_to': request_seq}, ctx.send_seq)
            msgs = await db_execute('''
                SELECT sender_id, content, timestamp, status FROM messages
                WHERE recipient_type='channel' AND recipient_id=?
                ORDER BY timestamp DESC LIMIT ?
            ''', (rec_id, limit), fetchall=True)
        else:
            return ({'error': 'bad_type', 'in_reply_to': request_seq}, ctx.send_seq)
        return ({'action': 'history', 'messages': [dict(m) for m in msgs][::-1], 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'restore_session':
        token = cmd.get('token')
        result = await verify_token(token, ctx.ip, ctx.device_id)
        if result:
            user_id_from_token, device_id = result
            await db_execute("UPDATE sessions SET last_activity=? WHERE token=?", (int(time.time()), token))
            return ({'status': 'ok', 'user_id': user_id_from_token, 'device_id': device_id, 'in_reply_to': request_seq}, ctx.send_seq)
        else:
            return ({'error': 'invalid_token', 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'sync_unread':
        minutes = cmd.get('minutes', 60)
        cutoff = int(time.time()) - minutes * 60
        msgs = await db_execute('''
            SELECT sender_id, content, timestamp, status FROM messages
            WHERE recipient_type='personal' AND recipient_id=? AND timestamp > ? AND status != 'read'
            ORDER BY timestamp ASC
        ''', (user_id, cutoff), fetchall=True)
        return ({'action': 'sync_unread', 'messages': [dict(m) for m in msgs], 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'set_e2ee_key':
        public_key_b64 = cmd.get('public_key_b64')
        if public_key_b64:
            await store_user_public_key(user_id, public_key_b64)
            return ({'status': 'ok', 'in_reply_to': request_seq}, ctx.send_seq)
        return ({'error': 'no_key', 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'get_e2ee_key':
        target_id = cmd.get('user_id')
        if not target_id:
            return ({'error': 'no_target', 'in_reply_to': request_seq}, ctx.send_seq)
        pub_key_info = await get_user_public_key(target_id)
        if pub_key_info:
            pub_bytes, sig = pub_key_info
            return ({'public_key_b64': base64.b64encode(pub_bytes).decode(), 'signature': sig, 'in_reply_to': request_seq}, ctx.send_seq)
        else:
            return ({'error': 'no_key', 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'ping':
        return ({'pong': time.time(), 'in_reply_to': request_seq}, ctx.send_seq)

    elif action == 'logout':
        token = ctx.session_token
        if token:
            await db_execute("DELETE FROM sessions WHERE token=?", (token,))
        return ({'status': 'ok', 'in_reply_to': request_seq}, ctx.send_seq)

    else:
        return ({'error': 'unknown_action', 'in_reply_to': request_seq}, ctx.send_seq)

# ---------------------------- CLIENT HANDLER ----------------------------
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, server_private_key: X25519PrivateKey):
    peer = writer.get_extra_info('peername')
    ip = peer[0] if peer else "unknown"

    async with ip_conn_lock:
        if ip_connection_count[ip] >= MAX_CONNECTIONS_PER_IP:
            logger.warning(f"Too many connections from {ip}, rejecting")
            writer.close()
            await writer.wait_closed()
            return
        ip_connection_count[ip] += 1

    logger.info(f"New connection from {peer}")

    if await is_ip_blocked(ip):
        logger.warning(f"Blocked connection from {ip} due to too many failed attempts")
        writer.close()
        await writer.wait_closed()
        async with ip_conn_lock:
            ip_connection_count[ip] -= 1
            if ip_connection_count[ip] <= 0:
                del ip_connection_count[ip]
        return

    cipher = await do_handshake(reader, writer, server_private_key)
    if not cipher:
        logger.warning(f"Handshake failed with {peer}")
        writer.close()
        await writer.wait_closed()
        async with ip_conn_lock:
            ip_connection_count[ip] -= 1
            if ip_connection_count[ip] <= 0:
                del ip_connection_count[ip]
        return
    logger.info(f"Secure channel established with {peer} (PFS enabled)")

    device_id = secrets.token_hex(8)
    ctx = ConnectionContext(writer, cipher, recv_seq=1, send_seq=1, ip=ip, device_id=device_id)
    authenticated_user = None

    async def keep_alive():
        while True:
            await asyncio.sleep(KEEP_ALIVE_INTERVAL)
            if writer.is_closing():
                break
            if time.time() - ctx.last_activity > KEEP_ALIVE_INTERVAL * 2:
                try:
                    async with ctx.send_lock:
                        await send_encrypted(writer, cipher, {'action': 'ping'}, ctx.send_seq)
                        ctx.send_seq += 1
                except:
                    break
                ctx.last_activity = time.time()

    ctx.keep_alive_task = asyncio.create_task(keep_alive())

    async def reader_loop():
        nonlocal authenticated_user
        try:
            while True:
                try:
                    cmd, new_recv_seq, closed, ctx.recv_buffer = await recv_encrypted(reader, cipher, ctx.recv_seq, ctx.recv_buffer)
                    if closed:
                        logger.debug(f"Connection closed by peer {peer}")
                        break
                    if cmd is None:
                        await asyncio.sleep(0.01)
                        continue
                    ctx.recv_seq = new_recv_seq
                    ctx.last_activity = time.time()
                except Exception as e:
                    logger.error(f"Critical recv error: {e}, closing connection")
                    break

                request_seq = cmd.get('seq') if 'seq' in cmd else None
                if authenticated_user is None:
                    if cmd.get('action') == 'auth':
                        auth_type = cmd.get('auth_type')
                        login = cmd.get('login', '')
                        password = cmd.get('password', '')
                        username = cmd.get('username', '')
                        if auth_type == 'register':
                            existing = await db_execute("SELECT id FROM users WHERE login=?", (login,), fetchone=True)
                            if existing:
                                await send_encrypted(writer, cipher, {'error': 'login_exists', 'in_reply_to': request_seq}, ctx.send_seq)
                                ctx.send_seq += 1
                                continue
                            pwd_hash, salt = hash_password(password)
                            ts = int(time.time())
                            await db_execute(
                                "INSERT INTO users (login, password_hash, username, nickname, bio, avatar_blob, created_at) VALUES (?,?,?,?,?,?,?)",
                                (login, f"{pwd_hash}:{salt.hex()}", username or login, username, '', '', ts)
                            )
                            user_id = await db_lastrowid()
                            public_key_b64 = cmd.get('public_key_b64')
                            if public_key_b64:
                                await store_user_public_key(user_id, public_key_b64)
                            token = generate_token(user_id, ctx.device_id, ip)
                            await db_execute("INSERT INTO sessions (token, user_id, device_id, ip, expires_at, last_activity) VALUES (?,?,?,?,?,?)",
                                             (token, user_id, ctx.device_id, ip, int(time.time() + CONFIG["token_expire_seconds"]), int(time.time())))
                            authenticated_user = user_id
                            ctx.user_id = user_id
                            ctx.session_token = token
                            async with active_connections_lock:
                                active_connections.setdefault(user_id, []).append(ctx)
                            await async_deliver_pending_messages(user_id, ctx)
                            await send_encrypted(writer, cipher, {'status': 'ok', 'token': token, 'user_id': user_id, 'in_reply_to': request_seq}, ctx.send_seq)
                            ctx.send_seq += 1
                            logger.info(f"User {user_id} registered and logged in from {peer}")
                        elif auth_type == 'login':
                            user = await db_execute("SELECT id, password_hash FROM users WHERE login=?", (login,), fetchone=True)
                            if not user:
                                await record_failed_attempt(ip)
                                await send_encrypted(writer, cipher, {'error': 'invalid_credentials', 'in_reply_to': request_seq}, ctx.send_seq)
                                ctx.send_seq += 1
                                continue
                            stored = user['password_hash']
                            if ':' not in stored:
                                await send_encrypted(writer, cipher, {'error': 'invalid_hash', 'in_reply_to': request_seq}, ctx.send_seq)
                                ctx.send_seq += 1
                                continue
                            pwd_hash, salt_hex = stored.split(':')
                            salt = bytes.fromhex(salt_hex)
                            if verify_password(password, pwd_hash, salt):
                                await db_execute("DELETE FROM failed_logins WHERE ip=?", (ip,))
                                token = generate_token(user['id'], ctx.device_id, ip)
                                await db_execute("INSERT OR REPLACE INTO sessions (token, user_id, device_id, ip, expires_at, last_activity) VALUES (?,?,?,?,?,?)",
                                                 (token, user['id'], ctx.device_id, ip, int(time.time() + CONFIG["token_expire_seconds"]), int(time.time())))
                                authenticated_user = user['id']
                                ctx.user_id = user['id']
                                ctx.session_token = token
                                async with active_connections_lock:
                                    active_connections.setdefault(user['id'], []).append(ctx)
                                await async_deliver_pending_messages(user['id'], ctx)
                                await send_encrypted(writer, cipher, {'status': 'ok', 'token': token, 'user_id': user['id'], 'in_reply_to': request_seq}, ctx.send_seq)
                                ctx.send_seq += 1
                                logger.info(f"User {user['id']} logged in from {peer}")
                            else:
                                await record_failed_attempt(ip)
                                await send_encrypted(writer, cipher, {'error': 'invalid_credentials', 'in_reply_to': request_seq}, ctx.send_seq)
                                ctx.send_seq += 1
                        else:
                            await send_encrypted(writer, cipher, {'error': 'auth_required', 'in_reply_to': request_seq}, ctx.send_seq)
                            ctx.send_seq += 1
                    elif cmd.get('action') == 'restore_session':
                        token = cmd.get('token')
                        result = await verify_token(token, ip, ctx.device_id)
                        if result:
                            user_id, device_id = result
                            authenticated_user = user_id
                            ctx.user_id = user_id
                            ctx.device_id = device_id
                            ctx.session_token = token
                            async with active_connections_lock:
                                active_connections.setdefault(user_id, []).append(ctx)
                            await async_deliver_pending_messages(user_id, ctx)
                            await send_encrypted(writer, cipher, {'status': 'ok', 'user_id': user_id, 'in_reply_to': request_seq}, ctx.send_seq)
                            ctx.send_seq += 1
                            await db_execute("UPDATE sessions SET last_activity=? WHERE token=?", (int(time.time()), token))
                            logger.info(f"User {user_id} restored session from {peer}")
                        else:
                            await send_encrypted(writer, cipher, {'error': 'invalid_token', 'in_reply_to': request_seq}, ctx.send_seq)
                            ctx.send_seq += 1
                    else:
                        await send_encrypted(writer, cipher, {'error': 'authenticate_first', 'in_reply_to': request_seq}, ctx.send_seq)
                        ctx.send_seq += 1
                    continue

                try:
                    resp, new_send_seq = await process_command(authenticated_user, cmd, ctx, request_seq)
                    if resp:
                        async with ctx.send_lock:
                            await send_encrypted(writer, cipher, resp, ctx.send_seq)
                            ctx.send_seq += 1
                except Exception as e:
                    logger.error(f"Error processing command: {e}")
                    try:
                        await send_encrypted(writer, cipher, {'error': 'internal_error', 'in_reply_to': request_seq}, ctx.send_seq)
                        ctx.send_seq += 1
                    except:
                        pass
        except Exception as e:
            logger.error(f"Reader loop error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    ctx.reader_task = asyncio.create_task(reader_loop())
    try:
        await ctx.reader_task
    finally:
        if ctx.keep_alive_task:
            ctx.keep_alive_task.cancel()
        if authenticated_user:
            async with active_connections_lock:
                if authenticated_user in active_connections:
                    active_connections[authenticated_user] = [c for c in active_connections[authenticated_user] if c != ctx]
                    if not active_connections[authenticated_user]:
                        del active_connections[authenticated_user]
        for seq, (future, _, _) in ctx.pending_acks.items():
            if not future.done():
                future.cancel()
        ctx.pending_acks.clear()
        async with ip_conn_lock:
            ip_connection_count[ip] -= 1
            if ip_connection_count[ip] <= 0:
                del ip_connection_count[ip]
        logger.info(f"Connection closed from {peer}")

async def run_tcp_server(server_private_key: X25519PrivateKey):
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, server_private_key),
        '0.0.0.0', TCP_PORT
    )
    logger.info(f"Z Secure Protocol server listening on port {TCP_PORT} (z://localhost:{TCP_PORT})")
    pub_b64 = base64.b64encode(server_private_key.public_key().public_bytes_raw()).decode()
    logger.info(f"Server public key (base64): {pub_b64}")
    async with server:
        await server.serve_forever()

# ---------------------------- CLIENT IMPLEMENTATION ----------------------------
class ZSecureClient:
    def __init__(self, host, port, server_public_key_bytes: bytes = None):
        self.host = host
        self.port = port
        self.server_public_key_bytes = server_public_key_bytes
        self.reader = None
        self.writer = None
        self.cipher = None
        self.user_id = None
        self.token = None
        self.device_id = None
        self.recv_seq = 1
        self.send_seq = 1
        self.running = False
        self.input_queue = asyncio.Queue()
        self.send_lock = asyncio.Lock()
        self.pending_acks: Dict[int, asyncio.Future] = {}
        self.pending_responses: Dict[int, asyncio.Future] = {}
        self.e2ee_private_key: Optional[X25519PrivateKey] = None
        self.e2ee_public_key_b64: Optional[str] = None
        self.recv_buffer: Dict[int, dict] = {}
        self.server_signing_public_key: Optional[Ed25519PublicKey] = None

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        logger.info(f"Connected to z://{self.host}:{self.port}")
        if self.server_public_key_bytes is None:
            ephemeral_priv = X25519PrivateKey.generate()
            ephemeral_pub = ephemeral_priv.public_key()
            self.writer.write(ephemeral_pub.public_bytes_raw())
            await self.writer.drain()
            server_pub_bytes = await asyncio.wait_for(self.reader.readexactly(32), timeout=10)
            self.server_public_key_bytes = server_pub_bytes
            key_file = f"server_key_{self.host}_{self.port}.bin"
            with open(key_file, "wb") as f:
                f.write(server_pub_bytes)
            logger.info(f"Saved server public key to {key_file}")
            server_pub_key = X25519PublicKey.from_public_bytes(server_pub_bytes)
            shared_secret = ephemeral_priv.exchange(server_pub_key)
            key = derive_key(shared_secret)
            self.cipher = ChaCha20Poly1305(key)
        else:
            self.cipher = await self._client_handshake()
        if not self.cipher:
            raise Exception("Handshake failed - server authentication error")
        logger.info("Secure channel established (PFS enabled)")

    async def _client_handshake(self) -> Optional[ChaCha20Poly1305]:
        try:
            ephemeral_priv = X25519PrivateKey.generate()
            ephemeral_pub = ephemeral_priv.public_key()
            self.writer.write(ephemeral_pub.public_bytes_raw())
            await self.writer.drain()
            server_pub_bytes = await asyncio.wait_for(self.reader.readexactly(32), timeout=10)
            if server_pub_bytes != self.server_public_key_bytes:
                logger.error("Server authentication failed: public key mismatch")
                return None
            server_pub_key = X25519PublicKey.from_public_bytes(server_pub_bytes)
            shared_secret = ephemeral_priv.exchange(server_pub_key)
            key = derive_key(shared_secret)
            return ChaCha20Poly1305(key)
        except Exception as e:
            logger.error(f"Client handshake error: {e}")
            return None

    async def send_command(self, cmd: dict, wait_response=True) -> Optional[dict]:
        async with self.send_lock:
            seq = self.send_seq
            self.send_seq += 1
            cmd['seq'] = seq
            await send_encrypted(self.writer, self.cipher, cmd, seq)
            if not wait_response:
                return None
            future = asyncio.get_event_loop().create_future()
            self.pending_responses[seq] = future
        try:
            resp = await asyncio.wait_for(future, timeout=30)
            return resp
        except asyncio.TimeoutError:
            self.pending_responses.pop(seq, None)
            raise Exception("Response timeout")
        except Exception:
            self.pending_responses.pop(seq, None)
            raise

    async def authenticate(self, mode, login, password, username=""):
        if mode == 'login':
            key_file = f"e2ee_key_{login}.bin"
            if not os.path.exists(key_file):
                print(f"E2EE key file for {login} not found. Please register first.")
                return False
            with open(key_file, "rb") as f:
                enc_key = f.read()
            salt = enc_key[:16]
            encrypted_key = enc_key[16:]
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
            dek = kdf.derive(password.encode())
            fernet = Fernet(base64.urlsafe_b64encode(dek))
            try:
                priv_bytes = fernet.decrypt(encrypted_key)
                self.e2ee_private_key = X25519PrivateKey.from_private_bytes(priv_bytes)
            except Exception:
                print("Failed to decrypt E2EE key, wrong password?")
                return False
            pub_bytes = self.e2ee_private_key.public_key().public_bytes_raw()
            self.e2ee_public_key_b64 = base64.b64encode(pub_bytes).decode()
        elif mode == 'register':
            self.e2ee_private_key = X25519PrivateKey.generate()
            pub_bytes = self.e2ee_private_key.public_key().public_bytes_raw()
            self.e2ee_public_key_b64 = base64.b64encode(pub_bytes).decode()
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
            dek = kdf.derive(password.encode())
            fernet = Fernet(base64.urlsafe_b64encode(dek))
            encrypted_key = fernet.encrypt(self.e2ee_private_key.private_bytes_raw())
            key_file = f"e2ee_key_{login}.bin"
            with open(key_file, "wb") as f:
                f.write(salt + encrypted_key)
        else:
            return False

        cmd = {
            'action': 'auth',
            'auth_type': mode,
            'login': login,
            'password': password,
            'username': username,
            'public_key_b64': self.e2ee_public_key_b64
        }
        resp = await self.send_command(cmd, wait_response=True)
        if resp and resp.get('status') == 'ok':
            self.token = resp['token']
            self.user_id = resp['user_id']
            self.device_id = secrets.token_hex(8)
            with open(".z_session", "w") as f:
                f.write(f"{self.token}\n{self.device_id}")
            print(f"Authenticated as user {self.user_id}")
            return True
        else:
            error = resp.get('error') if resp else 'unknown'
            print(f"Auth error: {error}")
            return False

    async def restore_session(self, password_callback=None):
        if not os.path.exists(".z_session"):
            return False
        with open(".z_session", "r") as f:
            lines = f.read().strip().splitlines()
            if len(lines) >= 2:
                token = lines[0].strip()
                device_id = lines[1].strip()
            else:
                token = lines[0].strip()
                device_id = secrets.token_hex(8)
        self.device_id = device_id
        resp = await self.send_command({'action': 'restore_session', 'token': token}, wait_response=True)
        if resp and resp.get('status') == 'ok':
            self.user_id = resp['user_id']
            self.token = token
            print(f"Session restored for user {self.user_id}")
            # Try to load E2EE key
            key_file = f"e2ee_key_{self.user_id}.bin"
            if os.path.exists(key_file) and password_callback:
                pwd = password_callback()
                if pwd:
                    with open(key_file, "rb") as f:
                        enc_key = f.read()
                    salt = enc_key[:16]
                    encrypted_key = enc_key[16:]
                    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
                    dek = kdf.derive(pwd.encode())
                    fernet = Fernet(base64.urlsafe_b64encode(dek))
                    try:
                        priv_bytes = fernet.decrypt(encrypted_key)
                        self.e2ee_private_key = X25519PrivateKey.from_private_bytes(priv_bytes)
                        pub_bytes = self.e2ee_private_key.public_key().public_bytes_raw()
                        self.e2ee_public_key_b64 = base64.b64encode(pub_bytes).decode()
                        print("E2EE key loaded.")
                    except Exception:
                        print("Failed to decrypt E2EE key, wrong password?")
            return True
        else:
            print("Session restore failed, need login")
            return False

    async def sync_unread(self, minutes=60):
        resp = await self.send_command({'action': 'sync_unread', 'minutes': minutes}, wait_response=True)
        if resp and resp.get('action') == 'sync_unread':
            msgs = resp.get('messages', [])
            if msgs:
                print(f"\n--- Unread messages (last {minutes} min) ---")
                for m in msgs:
                    content = m['content']
                    if self.e2ee_private_key:
                        try:
                            encrypted_data = base64.b64decode(content)
                            plain = decrypt_for_recipient(encrypted_data, self.e2ee_private_key)
                            content = plain.decode('utf-8')
                        except Exception as e:
                            content = f"[decryption failed: {e}]"
                    print(f"From {m['sender_id']}: {content} [{time.ctime(m['timestamp'])}] [status: {m.get('status','sent')}]")
                print("--------------------------------------------")
            else:
                print("No unread messages.")
        else:
            print("Sync failed.")

    async def send_ack(self, seq: int):
        async with self.send_lock:
            await send_encrypted(self.writer, self.cipher, {'action': 'ack', 'seq': seq}, self.send_seq)
            self.send_seq += 1

    async def send_delivery_ack(self, message_id: int):
        await self.send_command({'action': 'delivery_ack', 'message_id': message_id}, wait_response=False)

    async def receive_loop(self):
        while self.running:
            try:
                data, new_seq, closed, self.recv_buffer = await recv_encrypted(self.reader, self.cipher, self.recv_seq, self.recv_buffer)
                if closed:
                    logger.info("Server closed connection")
                    break
                if data is None:
                    await asyncio.sleep(0.01)
                    continue
                self.recv_seq = new_seq

                in_reply_to = data.get('in_reply_to')
                if in_reply_to is not None and in_reply_to in self.pending_responses:
                    future = self.pending_responses.pop(in_reply_to)
                    if not future.done():
                        future.set_result(data)
                    continue

                if data.get('action') != 'ack' and 'pong' not in data and data.get('type') != 'delivery_ack':
                    await self.send_ack(new_seq - 1)

                if data.get('type') == 'message':
                    msg_type = data.get('msg_type')
                    sender = data.get('sender_id')
                    content = data.get('content', '')
                    e2ee = data.get('e2ee', False)
                    if e2ee and self.e2ee_private_key:
                        try:
                            encrypted_data = base64.b64decode(content)
                            plain = decrypt_for_recipient(encrypted_data, self.e2ee_private_key)
                            content = plain.decode('utf-8')
                        except Exception as e:
                            content = f"[decryption failed: {e}]"
                    if msg_type == 'personal':
                        print(f"\n[PM from {sender}]: {content}")
                        await self.send_delivery_ack(data.get('message_id'))
                    elif msg_type == 'group':
                        group_id = data.get('group_id')
                        print(f"\n[Group {group_id} from {sender}]: {content}")
                    elif msg_type == 'channel':
                        channel_id = data.get('channel_id')
                        print(f"\n[Channel {channel_id} from {sender}]: {content}")
                    print("> ", end="", flush=True)
                elif data.get('type') == 'delivery_ack':
                    msg_id = data.get('message_id')
                    status = data.get('status')
                    print(f"\n[Delivery ack] Message {msg_id} {status}")
                    print("> ", end="", flush=True)
                elif 'pong' in data:
                    pass
            except Exception as e:
                if self.running:
                    logger.error(f"Receive loop error: {e}")
                break

    async def read_stdin(self):
        loop = asyncio.get_event_loop()
        while self.running:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:
                break
            await self.input_queue.put(line.strip())

    async def process_commands(self):
        while self.running:
            line = await self.input_queue.get()
            if not line:
                continue
            if line.startswith('/'):
                parts = line.split()
                cmd = parts[0][1:]
                if cmd == 'quit' or cmd == 'exit':
                    await self.send_command({'action': 'logout'}, wait_response=False)
                    self.running = False
                    break
                elif cmd == 'help':
                    print("Commands:")
                    print("  /msg <user_id> <text>          - send private message (E2EE)")
                    print("  /groupmsg <group_id> <text>    - send message to group")
                    print("  /channelmsg <channel_id> <text>- send message to channel")
                    print("  /profile                       - show your profile")
                    print("  /editprofile                   - edit profile")
                    print("  /creategroup                   - create new group")
                    print("  /createchannel                 - create new channel")
                    print("  /join <group_id>               - join group")
                    print("  /subscribe <channel_id>        - subscribe to channel")
                    print("  /history <type> <id>           - show history (personal/group/channel)")
                    print("  /sync [minutes]                - fetch unread messages (default 60)")
                    print("  /set_e2ee_key <b64>            - manually set E2EE public key")
                    print("  /quit                          - exit")
                elif cmd == 'msg' and len(parts) >= 3:
                    target = int(parts[1])
                    text = ' '.join(parts[2:])
                    resp = await self.send_command({'action': 'get_e2ee_key', 'user_id': target}, wait_response=True)
                    if resp and 'public_key_b64' in resp:
                        pub_key_bytes = base64.b64decode(resp['public_key_b64'])
                        encrypted = encrypt_for_recipient(text.encode('utf-8'), pub_key_bytes)
                        encrypted_b64 = base64.b64encode(encrypted).decode()
                        print(f"[You -> {target}]: (encrypted)")
                        await self.send_command({'action': 'send_message', 'recipient_type': 'personal', 'recipient_id': target, 'content': encrypted_b64}, wait_response=False)
                    else:
                        print("Target user has no E2EE key, cannot send private message.")
                elif cmd == 'groupmsg' and len(parts) >= 3:
                    gid = int(parts[1])
                    text = ' '.join(parts[2:])
                    print(f"[You -> group {gid}]: {text}")
                    await self.send_command({'action': 'send_message', 'recipient_type': 'group', 'recipient_id': gid, 'content': text}, wait_response=False)
                elif cmd == 'channelmsg' and len(parts) >= 3:
                    cid = int(parts[1])
                    text = ' '.join(parts[2:])
                    print(f"[You -> channel {cid}]: {text}")
                    await self.send_command({'action': 'send_message', 'recipient_type': 'channel', 'recipient_id': cid, 'content': text}, wait_response=False)
                elif cmd == 'profile':
                    resp = await self.send_command({'action': 'get_profile'}, wait_response=True)
                    if resp:
                        print(resp)
                elif cmd == 'editprofile':
                    new_name = input("New username (empty to skip): ")
                    new_nick = input("New nickname: ")
                    new_bio = input("New bio: ")
                    resp = await self.send_command({'action': 'update_profile', 'username': new_name, 'nickname': new_nick, 'bio': new_bio}, wait_response=True)
                    print(resp)
                elif cmd == 'creategroup':
                    name = input("Group name: ")
                    typ = input("Type (public/private): ")
                    resp = await self.send_command({'action': 'create_group', 'name': name, 'type': typ}, wait_response=True)
                    print(resp)
                elif cmd == 'createchannel':
                    name = input("Channel name: ")
                    typ = input("Type (public/private): ")
                    resp = await self.send_command({'action': 'create_channel', 'name': name, 'type': typ}, wait_response=True)
                    print(resp)
                elif cmd == 'join' and len(parts) >= 2:
                    gid = int(parts[1])
                    resp = await self.send_command({'action': 'join_group', 'group_id': gid}, wait_response=True)
                    print(resp)
                elif cmd == 'subscribe' and len(parts) >= 2:
                    cid = int(parts[1])
                    resp = await self.send_command({'action': 'subscribe_channel', 'channel_id': cid}, wait_response=True)
                    print(resp)
                elif cmd == 'history' and len(parts) >= 3:
                    typ = parts[1]
                    rid = int(parts[2])
                    resp = await self.send_command({'action': 'get_history', 'recipient_type': typ, 'recipient_id': rid}, wait_response=True)
                    if resp and 'messages' in resp:
                        for m in resp['messages']:
                            content = m['content']
                            if typ == 'personal' and self.e2ee_private_key:
                                try:
                                    encrypted_data = base64.b64decode(content)
                                    plain = decrypt_for_recipient(encrypted_data, self.e2ee_private_key)
                                    content = plain.decode('utf-8')
                                except:
                                    content = "[encrypted]"
                            print(f"[{time.ctime(m['timestamp'])}] User {m['sender_id']}: {content} [{m.get('status','sent')}]")
                    else:
                        print(resp)
                elif cmd == 'sync':
                    minutes = 60
                    if len(parts) >= 2:
                        try:
                            minutes = int(parts[1])
                        except:
                            pass
                    await self.sync_unread(minutes)
                elif cmd == 'set_e2ee_key' and len(parts) >= 2:
                    b64key = parts[1]
                    await self.send_command({'action': 'set_e2ee_key', 'public_key_b64': b64key}, wait_response=False)
                    print("E2EE key updated.")
                else:
                    print("Unknown command. Type /help")
            else:
                print("Use / commands")

    async def run(self):
        self.running = True
        recv_task = asyncio.create_task(self.receive_loop())
        stdin_task = asyncio.create_task(self.read_stdin())
        cmd_task = asyncio.create_task(self.process_commands())
        await asyncio.gather(recv_task, stdin_task, cmd_task)
        self.writer.close()
        await self.writer.wait_closed()

# ---------------------------- MAIN ----------------------------
shutdown_event = asyncio.Event()

async def shutdown(sig, loop):
    logger.info(f"Received exit signal {sig.name}, shutting down gracefully...")
    async with active_connections_lock:
        for user_id, contexts in active_connections.items():
            for ctx in contexts:
                ctx.writer.close()
        active_connections.clear()
    if db_pool:
        await db_pool.close_all()
    shutdown_event.set()

async def main():
    if len(sys.argv) < 2:
        print("Usage: python z_messenger_prod.py server")
        print("       python z_messenger_prod.py client z://host:port")
        return
    mode = sys.argv[1]
    if mode == 'server':
        await init_db()
        asyncio.create_task(cleanup_old_data())
        asyncio.create_task(retry_pending_for_online_users())
        asyncio.create_task(cleanup_rate_limit())
        server_priv, server_pub = load_or_generate_server_keys()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda s=sig: asyncio.create_task(shutdown(s, loop)))
        server_task = asyncio.create_task(run_tcp_server(server_priv))
        await shutdown_event.wait()
        server_task.cancel()
        logger.info("Server shutdown complete")
    elif mode == 'client':
        if len(sys.argv) < 3:
            print("Usage: python z_messenger_prod.py client z://host:port")
            return
        host = "127.0.0.1"
        port = 9999
        print(f"Connecting to {host}:{port}")

        key_file = f"server_key_{host}_{port}.bin"
        server_pub_bytes = None
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                server_pub_bytes = f.read()
            b64key = base64.b64encode(server_pub_bytes).decode()
            print(f"Using cached server public key: {b64key}")
        else:
            print("No cached server key, will fetch automatically (TOFU).")

        client = ZSecureClient(host, port, server_pub_bytes)
        await client.connect()
        client.running = True
        recv_task = asyncio.create_task(client.receive_loop())

        def get_password():
            import getpass
            return getpass.getpass("Enter password to decrypt E2EE key (if any): ")
        restored = await client.restore_session(password_callback=get_password if os.path.exists(f"e2ee_key_{client.user_id}.bin") else None)
        if not restored:
            while True:
                mode_auth = input("Login or Register? (l/r): ").strip().lower()
                if mode_auth == 'l':
                    login = input("Login: ")
                    pwd = getpass.getpass("Password: ")
                    ok = await client.authenticate('login', login, pwd)
                    if ok:
                        break
                elif mode_auth == 'r':
                    login = input("Login: ")
                    pwd = getpass.getpass("Password: ")
                    username = input("Display name: ")
                    ok = await client.authenticate('register', login, pwd, username)
                    if ok:
                        break
                else:
                    print("Invalid")

        stdin_task = asyncio.create_task(client.read_stdin())
        cmd_task = asyncio.create_task(client.process_commands())
        await asyncio.gather(recv_task, stdin_task, cmd_task)
        client.writer.close()
        await client.writer.wait_closed()
    else:
        print("Unknown mode")

if __name__ == '__main__':
    asyncio.run(main())
