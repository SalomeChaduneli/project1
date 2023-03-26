import sqlite3

# Connect to the database
conn = sqlite3.connect('../database.db')
cursor = conn.cursor()

# Create a table to store user information
cursor.execute("""CREATE TABLE users 
               (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                email TEXT(40) NOT NULL,
                name TEXT(20) NOT NULL,
                surname TEXT(30) NOT NULL                
                )""")

# Create a table to store page information
cursor.execute("""CREATE TABLE pages 
               (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                title TEXT(100) NOT NULL,
                content TEXT(150) NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id))""")


# Register a new user
def register_user(name, surname, password, email):
    cursor.execute('''INSERT INTO users (name, surname, password, email) 
                    VALUES (?, ?, ?, ?)''', (name, surname, password, email))
    conn.commit()

# Get user information by email
def get_user_by_email(email):
    cursor = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    return user

# Log in a user
def login_user(email, password):
    cursor = conn.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password))
    user = cursor.fetchone()
    return user

# Create a new page
def create_page(title, content, user_id):
    cursor.execute('''INSERT INTO pages (title, content, user_id) 
                    VALUES (?, ?, ?)''', (title, content, user_id))
    conn.commit()

# Get pages by user ID
def get_pages_by_user_id(user_id):
    cursor = conn.execute("SELECT * FROM pages WHERE user_id = ?", (user_id,))
    pages = cursor.fetchall()
    return pages


cursor.execute("""DELETE FROM users WHERE id = ?""", (32,))
conn.commit()
conn.close()
