"""
HF Guardian - Authentication & User Management with MongoDB Atlas
Supports user signup, login, PBKDF2 hashing, JWT tokens, and MongoDB Atlas persistence.
"""

import os
import time
import uuid
import hashlib
import secrets
import logging
from typing import Optional, Dict, Any
import jwt

from database import db_manager

logger = logging.getLogger("guardian.auth")

JWT_SECRET = os.getenv("JWT_SECRET", "hf-guardian-sentinel-secret-key-2026-auth")
JWT_ALGORITHM = "HS256"
SESSION_DURATION_SECONDS = 7 * 24 * 3600  # 7 days

# Primary fast storage / cache
_users_by_id: Dict[str, Dict[str, Any]] = {}
_users_by_login: Dict[str, str] = {}  # username/email -> user_id

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 10000)
    return f"{salt}${key.hex()}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        if "$" not in hashed_password:
            return False
        salt, expected_hash = hashed_password.split("$", 1)
        key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), 10000)
        return secrets.compare_digest(key.hex(), expected_hash)
    except Exception:
        return False

def create_access_token(user_data: dict) -> str:
    now = time.time()
    payload = {
        "sub": user_data["id"],
        "username": user_data["username"],
        "email": user_data["email"],
        "full_name": user_data["full_name"],
        "role": user_data["role"],
        "iat": int(now),
        "exp": int(now + SESSION_DURATION_SECONDS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except Exception:
        return None

def init_default_users():
    seed_users = [
        {
            "id": "usr_admin",
            "username": "admin",
            "email": "admin@guardian.sec",
            "full_name": "Alex Vance",
            "role": "Chief Information Security Officer",
            "password_hash": hash_password("Guardian@2026!"),
            "created_at": time.time(),
            "last_login": time.time()
        },
        {
            "id": "usr_analyst",
            "username": "analyst",
            "email": "analyst@guardian.sec",
            "full_name": "Elena Rostova",
            "role": "Lead Security Analyst",
            "password_hash": hash_password("Analyst@2026!"),
            "created_at": time.time(),
            "last_login": time.time()
        }
    ]

    for u in seed_users:
        _users_by_id[u["id"]] = dict(u)
        _users_by_login[u["username"].lower()] = u["id"]
        _users_by_login[u["email"].lower()] = u["id"]

    # If MongoDB is connected, also mirror seed users to MongoDB Atlas
    if db_manager.is_connected:
        try:
            for u in seed_users:
                exists = db_manager.db.users.find_one({"$or": [{"username": u["username"]}, {"email": u["email"]}]})
                if not exists:
                    db_manager.db.users.insert_one(dict(u))
            logger.info("Default sentinel users synced to MongoDB Atlas")
        except Exception as e:
            logger.warning("MongoDB seed notice: %s", e)

def register_user(username: str, email: str, full_name: str, password: str, role: str = "Security Analyst") -> Dict[str, Any]:
    username = username.strip().lower()
    email = email.strip().lower()
    full_name = full_name.strip()

    if not username or len(username) < 3:
        raise ValueError("Username must be at least 3 characters long")
    if "@" not in email or "." not in email:
        raise ValueError("Please provide a valid email address")
    if not full_name:
        raise ValueError("Full name is required")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters long")

    # Check duplicates
    if username in _users_by_login or email in _users_by_login:
        raise ValueError("A user with this username or email already exists")

    if db_manager.is_connected:
        try:
            existing = db_manager.db.users.find_one({
                "$or": [{"username": username}, {"email": email}]
            })
            if existing:
                raise ValueError("A user with this username or email already exists")
        except ValueError:
            raise
        except Exception:
            pass

    user_id = "usr_" + uuid.uuid4().hex[:10]
    pwd_hash = hash_password(password)
    now = time.time()

    user_record = {
        "id": user_id,
        "username": username,
        "email": email,
        "full_name": full_name,
        "role": role,
        "password_hash": pwd_hash,
        "created_at": now,
        "last_login": now
    }

    # Store locally
    _users_by_id[user_id] = dict(user_record)
    _users_by_login[username] = user_id
    _users_by_login[email] = user_id

    # Mirror to MongoDB Atlas
    if db_manager.is_connected:
        try:
            db_manager.db.users.insert_one(dict(user_record))
            logger.info("New user saved to MongoDB Atlas: %s", username)
        except Exception as e:
            logger.warning("MongoDB write notice: %s", e)

    public_user = {k: v for k, v in user_record.items() if k != "password_hash"}
    token = create_access_token(public_user)
    return {"token": token, "user": public_user}

def authenticate_user(login_identifier: str, password: str) -> Dict[str, Any]:
    ident = login_identifier.strip().lower()
    user_record = None

    # Check local store first for instant sub-millisecond lookup
    user_id = _users_by_login.get(ident)
    if user_id and user_id in _users_by_id:
        user_record = _users_by_id[user_id]

    # Check MongoDB if not found in local cache
    if not user_record and db_manager.is_connected:
        try:
            doc = db_manager.db.users.find_one({
                "$or": [{"username": ident}, {"email": ident}]
            })
            if doc:
                user_record = dict(doc)
                _users_by_id[user_record["id"]] = user_record
                _users_by_login[user_record["username"]] = user_record["id"]
                _users_by_login[user_record["email"]] = user_record["id"]
        except Exception as e:
            logger.warning("MongoDB lookup warning: %s", e)

    if not user_record:
        raise ValueError("Invalid username/email or password")

    hashed_pwd = user_record.get("password_hash")
    if not verify_password(password, hashed_pwd):
        raise ValueError("Invalid username/email or password")

    now = time.time()
    user_record["last_login"] = now

    if db_manager.is_connected:
        try:
            db_manager.db.users.update_one({"id": user_record["id"]}, {"$set": {"last_login": now}})
        except Exception:
            pass

    public_user = {k: v for k, v in user_record.items() if k not in ("password_hash", "_id")}
    token = create_access_token(public_user)
    return {"token": token, "user": public_user}

def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    if user_id in _users_by_id:
        return {k: v for k, v in _users_by_id[user_id].items() if k not in ("password_hash", "_id")}

    if db_manager.is_connected:
        try:
            doc = db_manager.db.users.find_one({"id": user_id})
            if doc:
                return {k: v for k, v in doc.items() if k not in ("password_hash", "_id")}
        except Exception:
            pass

    return None

# Seed initial accounts
init_default_users()
