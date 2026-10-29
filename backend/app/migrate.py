"""A tiny schema upgrader.

`Base.metadata.create_all()` creates MISSING TABLES but never changes existing
ones. When a new phase adds columns to a table (Phase 3 adds status, host,
first_seen... to `alerts`), this adds those columns so your existing database
keeps its data instead of needing a wipe.

Production projects use Alembic for this (versioned migration scripts).
For a lab project, "add any missing column" covers what we need.
"""
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

from .database import Base


def add_missing_columns(engine: Engine) -> list[str]:
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    added = []
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue  # create_all() handles brand-new tables
            have = {c["name"] for c in inspector.get_columns(table.name)}
            for col in table.columns:
                if col.name in have:
                    continue
                col_type = col.type.compile(dialect=engine.dialect)
                default = ""
                if col.server_default is not None:
                    default = f" DEFAULT {col.server_default.arg.text if hasattr(col.server_default.arg, 'text') else repr(col.server_default.arg)}"
                conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN "{col.name}" {col_type}{default}'))
                added.append(f"{table.name}.{col.name}")
    return added
