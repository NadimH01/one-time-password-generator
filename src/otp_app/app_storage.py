from dataclasses import dataclass

from .config import (
	DATABASE_DIR,
	DATABASE_PATH,
	KEY_DIR,
	STORAGE_KEY_PATH,
)
from .repository import (
	connect_database,
	create_schema,
)
from .secret_store import (
	generate_storage_key,
	load_storage_key,
	save_storage_key,
)


@dataclass
class ApplicationStorage:
	connection: object
	storage_key: bytes


def initialise_application_storage() -> ApplicationStorage:
	database_exists = DATABASE_PATH.exists()
	key_exists = STORAGE_KEY_PATH.exists()

	if not database_exists and not key_exists:
		DATABASE_DIR.mkdir(
			parents=True,
			exist_ok=True,
		)
		KEY_DIR.mkdir(
			parents=True,
			exist_ok=True,
		)

		storage_key = generate_storage_key()
		save_storage_key(STORAGE_KEY_PATH, storage_key)

		connection = connect_database(DATABASE_PATH)
		create_schema(connection)

		return ApplicationStorage(
			connection=connection,
			storage_key=storage_key,
		)

	if database_exists and key_exists:
		storage_key = load_storage_key(STORAGE_KEY_PATH)
		connection = connect_database(DATABASE_PATH)
		create_schema(connection)

		return ApplicationStorage(
			connection=connection,
			storage_key=storage_key,
		)

	raise RuntimeError(
		"Protected storage is inconsistent: "
		"database/key mismatch."
	)
