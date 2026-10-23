"""Standalone portal migrations, including caller-owned in-memory connections."""
import os

from alembic import context
from sqlalchemy import create_engine, pool
from vs_portal.models import Base

config = context.config
url = os.environ.get('VS_PORTAL_DATABASE_URL') or config.get_main_option('sqlalchemy.url') or 'sqlite:///vs-portal.db'

if context.is_offline_mode():
    context.configure(url=url, target_metadata=Base.metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    connection = config.attributes.get('connection')
    if connection is not None:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()
    else:
        engine = create_engine(url, poolclass=pool.NullPool)
        try:
            with engine.connect() as connection:
                context.configure(connection=connection, target_metadata=Base.metadata)
                with context.begin_transaction():
                    context.run_migrations()
        finally:
            engine.dispose()
