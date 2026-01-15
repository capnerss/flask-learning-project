import os
from flask import Flask, request, jsonify, session, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_key_for_local_testing')

# --- НАСТРОЙКА БАЗЫ ДАННЫХ ---
basedir = os.path.abspath(os.path.dirname(__file__))

# 1. Пробуем получить адрес базы из переменных окружения (это сработает на Render)
database_url = os.environ.get('DATABASE_URL')

if database_url:
    # --- МЫ НА СЕРВЕРЕ (Render) ---

    # Исправление для SQLAlchemy:
    # Render/Neon часто дают адрес, начинающийся с 'postgres://',
    # а библиотека требует 'postgresql://'. Меняем это вручную:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    print("✅ Используется удаленная база данных (PostgreSQL)")

else:
    # --- МЫ ЛОКАЛЬНО (Ваш компьютер) ---
    # Переменной нет, значит работаем по-старому с SQLite
    db_path = os.path.join(basedir, 'it_materials.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
    print(f"⚠️ Переменная DATABASE_URL не найдена. Используется локальная SQLite: {db_path}")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# --- МОДЕЛИ ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    # Роли: Guest (в коде), User, Curator, Admin
    role = db.Column(db.String(20), default='User')


class Material(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50))
    link = db.Column(db.String(500))
    keywords = db.Column(db.String(200))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # НОВОЕ ПОЛЕ: Статус подтверждения
    is_confirmed = db.Column(db.Boolean, default=False)

    author = db.relationship('User', backref=db.backref('materials', lazy=True))


# --- ИНИЦИАЛИЗАЦИЯ ДАННЫХ ---
with app.app_context():
    db.create_all()

    # 1. Создаем Админа (Admin)
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@kool.ee', role='Admin',
                     password_hash=generate_password_hash('admin123', method='pbkdf2:sha256'))
        db.session.add(admin)

    # 2. Создаем Куратора (Curator) для теста
    if not User.query.filter_by(username='curator').first():
        curator = User(username='curator', email='curator@kool.ee', role='Curator',
                       password_hash=generate_password_hash('curator123', method='pbkdf2:sha256'))
        db.session.add(curator)

    db.session.commit()
    print("База данных обновлена. Пользователи: admin@kool.ee, curator@kool.ee")


# --- МАРШРУТЫ ---

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if User.query.filter_by(email=data.get('email')).first():
        return jsonify({"error": "E-mail on juba süsteemis"}), 400

    # Обычный пользователь получает роль 'User'
    hashed_pw = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_pw, role='User')

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "Kasutaja loodud"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data.get('email')).first()
    if user and check_password_hash(user.password_hash, data.get('password')):
        session['user_id'] = user.id
        session['role'] = user.role
        return jsonify({"message": "Sisse logitud", "role": user.role}), 200
    return jsonify({"error": "Vale andmed"}), 401


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Välja logitud"}), 200


# Получение материалов
@app.route('/materials', methods=['GET'])
def get_materials():
    keyword = request.args.get('keyword', '').lower()
    category = request.args.get('category')

    # Получаем текущую роль пользователя
    user_role = session.get('role', 'Guest')

    query = Material.query
    if category:
        query = query.filter_by(category=category)

    # ЛОГИКА ОТОБРАЖЕНИЯ [cite: 19, 21, 24]
    # Если это просто поиск - показываем только ПОДТВЕРЖДЕННЫЕ (is_confirmed=True)
    # Но если запрашивает Куратор или Админ специально список "на проверку", логика может быть сложнее.
    # Для простоты: Куратор и Админ видят ВСЕ (и отмечаем в JSON, подтверждено или нет).
    # Гость и Юзер видят только is_confirmed=True.

    if user_role in ['Curator', 'Admin']:
        materials = query.all()  # Видят всё
    else:
        materials = query.filter_by(is_confirmed=True).all()  # Только одобренное

    results = []
    for m in materials:
        if keyword and keyword not in m.title.lower():
            continue

        results.append({
            "id": m.id,
            "title": m.title,
            "description": m.description,
            "category": m.category,
            "link": m.link,
            "author": m.author.username,
            "is_confirmed": m.is_confirmed  # Отправляем статус на фронтенд
        })
    return jsonify(results), 200


# Добавление материала
@app.route('/materials', methods=['POST'])
def add_material():
    # 1. Проверка авторизации
    if 'user_id' not in session:
        return jsonify({"error": "Palun logige sisse"}), 401

    role = session.get('role')

    # 2. Блокировка Гостей (на всякий случай, если сессия кривая)
    if role == 'Guest':
        return jsonify({"error": "Külaline ei saa lisada"}), 403

    data = request.json
    if not data.get('title') or len(data['title']) > 100:
        return jsonify({"error": "Pealkiri vigane"}), 400

    # 3. Логика статуса [cite: 21]
    # Куратор и Админ -> Сразу подтверждено (True)
    # Пользователь (User) -> На модерацию (False)
    auto_approve = (role in ['Curator', 'Admin'])

    new_material = Material(
        title=data['title'],
        description=data['description'],
        category=data.get('category'),
        link=data.get('link'),
        keywords=data.get('keywords'),
        author_id=session['user_id'],
        is_confirmed=auto_approve
    )

    db.session.add(new_material)
    db.session.commit()

    msg = "Materjal lisatud!" if auto_approve else "Materjal saadetud kinnitamiseks!"
    return jsonify({"message": msg}), 201


# Подтверждение материала (Только для Curator/Admin)
@app.route('/materials/<int:id>/approve', methods=['POST'])
def approve_material(id):
    if session.get('role') not in ['Curator', 'Admin']:
        return jsonify({"error": "Puuduvad õigused"}), 403

    material = Material.query.get(id)
    if not material:
        return jsonify({"error": "Ei leitud"}), 404

    material.is_confirmed = True
    db.session.commit()
    return jsonify({"message": "Kinnitatud"}), 200


# Удаление (Admin может всё, User/Curator только свои)
@app.route('/materials/<int:id>', methods=['DELETE'])
def delete_material(id):
    if 'user_id' not in session:
        return jsonify({"error": "Logi sisse"}), 401

    material = Material.query.get(id)
    if not material:
        return jsonify({"error": "Ei leitud"}), 404

    user_id = session['user_id']
    role = session['role']

    # [cite: 24, 75]
    if role == 'Admin' or material.author_id == user_id:
        db.session.delete(material)
        db.session.commit()
        return jsonify({"message": "Kustutatud"}), 200

    return jsonify({"error": "Puuduvad õigused"}), 403


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)