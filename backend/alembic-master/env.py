import os

from alembic import context
from sqlalchemy import engine_from_config, pool
from vs_master.models import Base

config = context.config
if context.is_offline_mode():
    database_url = os.environ.get("VS_MASTER_DATABASE_URL", config.get_main_option("sqlalchemy.url"))
    context.configure(url=database_url, target_metadata=Base.metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    section = config.get_section(config.config_ini_section)
    if section is None:
        raise RuntimeError("missing Alembic configuration section")
    engine = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    # Environment overrides the URL (the master service points migrations at its data directory).
    if database_url := os.environ.get("VS_MASTER_DATABASE_URL"):
        engine.dispose()
        from sqlalchemy import create_engine
        engine = create_engine(database_url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()
