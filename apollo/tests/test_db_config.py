import os
import tempfile
from tortoise import Tortoise

# Create a unique temp file for the DB
temp_db = tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False)
TEST_DB_URL = f"sqlite:///{temp_db.name}"

TORTOISE_ORM = {
    "connections": {"default": TEST_DB_URL},
    "apps": {
        "models": {
            "models": [
                "apollo.db",  # Your main models
            ],
            "default_connection": "default",
        }
    },
}

async def initialize_test_db():
    try:
        await Tortoise.init(config=TORTOISE_ORM)
        await Tortoise.generate_schemas(safe=True)
        print(f"Test database initialized at {temp_db.name}")
    except Exception as e:
        print(f"Failed to initialize test database: {e}")
        raise

async def close_test_db():
    try:
        await Tortoise.close_connections()
        if os.path.exists(temp_db.name):
            os.remove(temp_db.name)
            print(f"Test database cleaned up at {temp_db.name}")
    except Exception as e:
        print(f"Failed to clean up test database: {e}")
        raise