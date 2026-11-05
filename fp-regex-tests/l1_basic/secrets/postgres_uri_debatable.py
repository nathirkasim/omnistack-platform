import sqlalchemy

db_url = "postgres://user:password@localhost/db"
engine = sqlalchemy.create_engine(db_url)
