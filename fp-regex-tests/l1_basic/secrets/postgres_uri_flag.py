import sqlalchemy

db_url = "postgres://admin:S3cr3tP4ss@db.internal:5432/app"
engine = sqlalchemy.create_engine(db_url)
