import os

from alembic import context
from sqlalchemy import engine_from_config, pool
from vs_router.db import Base

config = context.config
if context.is_offline_mode():
    if database_url := os.environ.get("VS_ROUTER_DATABASE_URL"):
        context.configure(url=database_url, target_metadata=Base.metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    engine = engine_from_config(config.get_section(config.config_ini_section), prefix="sqlalchemy.", poolclass=pool.NullPool)
    # Environment overrides the URL (install.sh points migrations at /var/lib).
    if database_url := os.environ.get("VS_ROUTER_DATABASE_URL"):
        engine.dispose()
        from sqlalchemy import create_engine
        engine = create_engine(database_url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()
