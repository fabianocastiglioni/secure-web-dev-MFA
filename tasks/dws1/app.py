from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import pyotp
import qrcode
from io import BytesIO
import base64

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DATABASE = 'example.db'

# Função para inicializar o banco de dados
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            task TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
# Adicione mfa_enabled e mfa_secret separadamente
    try:
        c.execute('ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT 1')
        c.execute('ALTER TABLE users ADD COLUMN mfa_secret TEXT')
    except sqlite3.OperationalError:
        print('As colunas mfa_enabled e mfa_secret já podem existir na tabela users.')

    # Inserir um usuário administrador padrão
    admin_username = 'admin'
    admin_password = generate_password_hash('admin123')  # Lembre-se de usar uma senha segura na produção
    admin_role = 'admin'
    c.execute('SELECT * FROM users WHERE username = ?', (admin_username,))
    if not c.fetchone():
        c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                  (admin_username, admin_password, admin_role))
    conn.commit()
    conn.close()

# Função para obter o banco de dados
def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn

# Página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        
        if user and check_password_hash(user[2], password):  # Verificando hash da senha
            
            if user[4]:

                # Verificar se o usuário já possui um segredo OTP
                if not user[5]:  # user[5] é o índice da coluna mfa_secret
                    
                    # Gerar um novo segredo OTP
                    otp_secret = pyotp.random_base32()
                    
                    # Salvar o segredo OTP no banco de dados
                    c.execute('UPDATE users SET mfa_secret = ? WHERE id = ?', (otp_secret, user[0]))
                    conn.commit()
                    conn.close()
                    # Gerar o QR code para registro no dispositivo do usuário
                    otp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(username, issuer_name='Flask MFA Example')
                    img = qrcode.make(otp_uri)
                    img_bytes = BytesIO()
                    img.save(img_bytes, format='PNG')
                    img_bytes.seek(0)
                    qr_code_data = img_bytes.read()
                    
                    # Renderizar o template com o QR code
                    return render_template('setup_mfa.html', qr_code=base64.b64encode(qr_code_data).decode())

                else:
                    # MFA está habilitado e usuário possui segredo, redirecionar para inserir o código de MFA
                    session['partial_auth'] = True
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    session['role'] = user[3]
                    return redirect(url_for('verify_mfa'))
            else:
                # MFA não está habilitado, autenticação completa
                session['user_id'] = user[0]
                session['username'] = user[1]
                session['role'] = user[3]
                return redirect(url_for('index'))
        
        conn.close()    
        return 'Login Failed'
    
    return render_template('login.html')

# Página de logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Página inicial
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM tasks WHERE user_id = ?', (session['user_id'],))
    tasks = c.fetchall()
    conn.close()
    return render_template('index.html', tasks=tasks)

# Página para adicionar tarefas
@app.route('/add', methods=['GET', 'POST'])
def add():
    if 'user_id' not in session or session.get('role') != 'comum':
        return redirect(url_for('login'))
    if request.method == 'POST':
        task = request.form['task']
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO tasks (user_id, task) VALUES (?, ?)', (session['user_id'], task))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    return render_template('add.html')

# Rota para excluir tarefa
@app.route('/delete-task/<int:task_id>', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session or session.get('role') != 'comum':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        conn = get_db()
        c = conn.cursor()
        c.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', (task_id, session['user_id']))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    return render_template('add.html')

# Página de gerenciamento de usuários (somente para administradores)
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    conn = get_db()
    c = conn.cursor()
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])  # Usando hashing seguro
        role = request.form['role']
        c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, password, role))
        conn.commit()
    c.execute('SELECT * FROM users')
    users = c.fetchall()
    conn.close()
    return render_template('admin.html', users=users)


# Página para verificar código de MFA
@app.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    if 'partial_auth' not in session or not session['partial_auth']:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        mfa_code = request.form['mfa_code']
        
        # Verificar se o usuário está autenticado e recuperar o segredo OTP do banco de dados
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('login'))
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT mfa_secret FROM users WHERE id = ?', (user_id,))
        mfa_secret = c.fetchone()[0]  
        
        # Verificar o código de MFA
        if mfa_secret:
            totp = pyotp.TOTP(mfa_secret)
            if totp.verify(mfa_code):
                session.pop('partial_auth', None)
                return redirect(url_for('index'))
        
        conn.close()
        return 'Código de MFA inválido'
    
    return render_template('verify_mfa.html')


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
