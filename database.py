import psycopg2

# Create the PostgreSQL database connection
def get_db_connection():
    return psycopg2.connect(
        host='localhost',
        database='secure_file_system',
        user='ruegen',
        password='ruegen'
    )

# Create the users table if it doesn't exist
def create_users_table():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                totp_secret TEXT NOT NULL
            )
        ''')
        conn.commit()
