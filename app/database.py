from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

from config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def search_scans_by_query(db, query: str) -> list:
    # Parameterized query using bind variables to eliminate SQL injection (CWE-89)
    sql = text(
        "SELECT id, title, description, severity, status, cve_id, "
        "affected_component, owner_id, created_at FROM scan_results "
        "WHERE title LIKE :pattern OR description LIKE :pattern "
        "OR cve_id LIKE :pattern"
    )
    pattern = f"%{query}%"
    result = db.execute(sql, {"pattern": pattern})
    return [dict(row._mapping) for row in result]

