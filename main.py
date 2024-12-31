from twilio.rest import Client
from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Klucz sesji (zmień na bezpieczny!)

# Dane do autoryzacji Twilio
TWILIO_ACCOUNT_SID = 'your_account_sid'
TWILIO_AUTH_TOKEN = 'your_auth_token'
TWILIO_PHONE_NUMBER = 'your_twilio_phone_number'  # Numer Twilio, z którego będziesz wysyłać SMS-y

# Funkcja do wysyłania SMS-a
def send_sms_confirmation(user_phone_number, reservation_date, reservation_time):
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    message = f"""
    Twoja rezerwacja została pomyślnie dokonana na dzień {reservation_date} o godzinie {reservation_time}.
    Dziękujemy za dokonanie rezerwacji!
    """

    try:
        # Wysłanie SMS-a
        client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=user_phone_number
        )
        print("SMS został wysłany pomyślnie!")
    except Exception as e:
        print(f"Nie udało się wysłać SMS-a. Błąd: {e}")

# Funkcja do inicjalizacji bazy danych
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'users.db')

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()

        # Tworzenie tabeli użytkowników, jeśli nie istnieje
        cursor.execute(''' 
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                phone_number TEXT,
                email TEXT UNIQUE
            )
        ''')

        # Tworzenie tabeli rezerwacji, jeśli nie istnieje
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reservations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                reservation_date TEXT NOT NULL, 
                reservation_time TEXT NOT NULL, 
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')

        conn.commit()





# Rejestracja
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        phone_number = request.form['phone_number']  # Pobranie numeru telefonu z formularza

        # Hashowanie hasła
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

        # Dodanie użytkownika do bazy
        try:
            with sqlite3.connect(DB_PATH) as conn: 
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users (username, password, phone_number) VALUES (?, ?, ?)', 
                               (username, hashed_password, phone_number))
                conn.commit()
            flash('Rejestracja zakończona sukcesem! Możesz się teraz zalogować.', 'success')
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash('Nazwa użytkownika już istnieje!', 'danger')

    return render_template('register.html')

# Logowanie
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Sprawdzenie czy użytkownik istnieje w bazie danych
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()

            if user is None:
                flash('Użytkownik o podanej nazwie nie istnieje.', 'danger')
            elif not check_password_hash(user[2], password):
                flash('Nieprawidłowe hasło.', 'danger')
            else:
                # Użytkownik zalogowany pomyślnie
                session['user_id'] = user[0]
                session['username'] = user[1]
                flash('Zalogowano pomyślnie!', 'success')
                return redirect('/')

    return render_template('login.html')

@app.route('/')
def index():
    if 'user_id' not in session:
        flash('Musisz być zalogowany, aby zobaczyć tę stronę.', 'warning')
        return redirect('/login')

    selected_date = request.args.get('date')  # Opcjonalnie: wybór daty
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM reservations')
        reservations = cursor.fetchall()

    return render_template('reservations.html', username=session['username'], reservations=reservations)

# Rezerwacja
@app.route('/reserve', methods=['POST'])
def reserve():
    if 'user_id' not in session:
        flash('Musisz być zalogowany, aby dokonać rezerwacji.', 'warning')
        return redirect('/login')

    # Pobranie danych z formularza
    date = request.form['date']
    time = request.form['time']
    username = session['username']

    # Sprawdzanie, czy dany termin jest już zajęty
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM reservations 
            WHERE reservation_date = ? AND reservation_time = ?
        ''', (date, time))
        existing_reservation = cursor.fetchone()

        if existing_reservation:
            flash('Ten termin jest już zajęty. Wybierz inny.', 'danger')
            return redirect('/')

        # Jeśli termin jest wolny, zapisujemy rezerwację
        cursor.execute('''
            INSERT INTO reservations (user_id, reservation_date, reservation_time) 
            VALUES (?, ?, ?)
        ''', (session['user_id'], date, time))
        conn.commit()

    flash('Rezerwacja została pomyślnie dokonana!', 'success')
    return redirect('/')





# Wylogowanie
@app.route('/logout')
def logout():
    session.clear()
    flash('Wylogowano pomyślnie.', 'info')
    return redirect('/login')

if __name__ == '__main__':
    init_db()  # Inicjalizacja bazy danych
    app.run(host='0.0.0.0', port=5000, debug=True)
