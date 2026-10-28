"""
HF Guardian - MongoDB Atlas Database Connector & Repository Layer
Connects to MongoDB Atlas for persistent users, monitored targets, alerts, and scan logs.
"""

import os
import logging
from typing import Optional
import pymongo

logger = logging.getLogger("guardian.db")

MONGO_URI = os.getenv(
    "MONGO_URI",
    "mongodb://h21535890_db_user:bzcDLTtFEFeWe5mU@ac-nplgtqj-shard-00-00.kcocwrs.mongodb.net:27017,ac-nplgtqj-shard-00-01.kcocwrs.mongodb.net:27017,ac-nplgtqj-shard-00-02.kcocwrs.mongodb.net:27017/?ssl=true&replicaSet=atlas-udaqaq-shard-0&authSource=admin&appName=Cluster0"
)
DB_NAME = "hf_guardian"

class MongoManager:
    def __init__(self, uri: str = MONGO_URI, db_name: str = DB_NAME):
        self.uri = uri
        self.db_name = db_name
        self.client: Optional[pymongo.MongoClient] = None
        self.db = None
        self._connected = False
        self._attempted = False

    def connect(self) -> bool:
        self._attempted = True
        try:
            self.client = pymongo.MongoClient(
                self.uri,
                serverSelectionTimeoutMS=2000,
                connectTimeoutMS=2000,
                socketTimeoutMS=2000
            )
            # Verify connectivity
            self.client.admin.command("ping")
            self.db = self.client[self.db_name]
            self._connected = True
            self._ensure_indexes()
            logger.info("Successfully connected to MongoDB Atlas: %s", self.db_name)
            return True
        except Exception as e:
            logger.info("MongoDB Atlas: %s (Will use persistent local store until user finishes provisioning in Atlas)", e)
            self._connected = False
            return False

    @property
    def is_connected(self) -> bool:
        return self._connected and self.db is not None

    def _ensure_indexes(self):
        if not self._connected or self.db is None:
            return
        try:
            self.db.users.create_index("username", unique=True)
            self.db.users.create_index("email", unique=True)
            self.db.targets.create_index("id", unique=True)
            self.db.alerts.create_index("id", unique=True)
            self.db.alerts.create_index("timestamp")
        except Exception as e:
            logger.warning("Index warning: %s", e)

# Global singleton
db_manager = MongoManager()
