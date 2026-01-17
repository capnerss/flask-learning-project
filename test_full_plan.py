import pytest
from unittest.mock import patch, MagicMock
from app import app, db, User, Material, Category
from werkzeug.security import generate_password_hash


# ==========================================
# 1. НАСТРОЙКА ОКРУЖЕНИЯ (Fixtures)
# ==========================================

@pytest.fixture
def client():
    """Создает изолированное окружение для тестов с БД в памяти."""
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False  # Отключаем CSRF для большинства тестов
    app.config['SECRET_KEY'] = 'test_secret'

    with app.test_client() as client:
        with app.app_context():
            db.create_all()

            # Проверяем, существует ли категория, прежде чем добавлять
            if not Category.query.filter_by(name='Programmeerimine').first():
                db.session.add(Category(name='Programmeerimine'))
                db.session.commit()

        yield client

        with app.app_context():
            db.session.remove()
            db.drop_all()


@pytest.fixture
def auth(client):
    """Помощник для авторизации."""

    def _login(email='user@test.ee', password='password123', role='User', username='Tester'):
        with app.app_context():
            if not User.query.filter_by(email=email).first():
                u = User(username=username, email=email, role=role,
                         password_hash=generate_password_hash(password, method='pbkdf2:sha256'))
                db.session.add(u)
                db.session.commit()
        return client.post('/login', data={'email': email, 'password': password}, follow_redirects=True)

    return _login


# ==========================================
# 2. ТЕСТИРОВАНИЕ МОДЕЛЕЙ (Data Layer)
# Источник: SDD Раздел 3 (Andmemudel)
# ==========================================

def test_model_user_creation(client):
    """[SDD 3] Проверка создания пользователя и хеширования."""
    with app.app_context():
        u = User(username='Juri', email='juri@kool.ee', role='Admin')
        u.password_hash = generate_password_hash('secret', method='pbkdf2:sha256')
        db.session.add(u)
        db.session.commit()

        fetched = User.query.filter_by(email='juri@kool.ee').first()
        assert fetched.username == 'Juri'
        assert fetched.role == 'Admin'
        assert fetched.password_hash != 'secret'  # Пароль должен быть захеширован


def test_model_material_constraints(client):
    """[SDD 3] Материал обязан иметь title и author_id."""
    with app.app_context():
        # Попытка создать материал без обязательных полей
        m = Material(description="No title")
        db.session.add(m)
        # Ожидаем ошибку целостности БД
        with pytest.raises(Exception):
            db.session.commit()


# ==========================================
# 3. ВАЛИДАЦИЯ ФОРМ (Validation)
# Источник: SDD Раздел 4.1, 4.2
# ==========================================

def test_registration_password_complexity(client):
    """
    [SDD 4.1] Пароль должен содержать минимум 8 знаков и 1 цифру.
    """
    # 1. Слишком короткий пароль
    response = client.post('/register', data={
        'username': 'WeakUser',
        'email': 'weak@test.ee',
        'password': '123'
    }, follow_redirects=True)

    # Если валидация работает, мы НЕ должны увидеть "Konto loodud"
    assert b'Konto loodud' not in response.data, "FAIL: Система пропустила слабый пароль (Short)"

    # 2. Пароль без цифр
    response = client.post('/register', data={
        'username': 'NoDigit',
        'email': 'nodigit@test.ee',
        'password': 'passwordlong'
    }, follow_redirects=True)
    assert b'Konto loodud' not in response.data, "FAIL: Система пропустила пароль без цифр"


def test_material_content_validation(client, auth):
    """
    [SDD 4.2] Должен быть заполнен или файл (которого нет в коде) или ссылка.
    """
    auth(role='User')
    # Отправляем форму без ссылки
    response = client.post('/add', data={
        'title': 'Empty Material',
        'description': 'Test',
        'category': 'Programmeerimine',
        'link': ''  # Пусто
    }, follow_redirects=True)

    # Если бы валидация была, материал бы не создался
    with app.app_context():
        m = Material.query.filter_by(title='Empty Material').first()
        assert m is None, "FAIL: Создан материал без ссылки (Content URL)"


# ==========================================
# 4. БИЗНЕС-ЛОГИКА И УТИЛИТЫ
# Источник: SDD Раздел 4.2 (Link Checking)
# ==========================================

@patch('requests.head')  # Мокаем внешний запрос
def test_link_checker_logic(mock_head, client, auth):
    """
    [SDD 4.2] LinkChecker: Предупреждение если ссылка возвращает 404.
    """
    auth(role='User')

    # Настраиваем Mock на возврат 404 Not Found
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_head.return_value = mock_response

    response = client.post('/add', data={
        'title': 'Broken Link',
        'description': 'Test',
        'category': 'Programmeerimine',
        'link': 'http://broken-site.com'
    }, follow_redirects=True)

    # Проверяем, что система выдала предупреждение (Flash message)
    # В app.py сообщение: 'Hoiatus: Link ei vasta (404), aga materjal salvestati.'
    assert b'Link ei vasta' in response.data or b'404' in response.data, \
        "FAIL: Система не предупредила о битой ссылке"


# ==========================================
# 5. КОНТРОЛЬ ДОСТУПА (Access Control)
# Источник: SDD Раздел 4.1 (Roles)
# ==========================================

def test_delete_permissions(client, auth):
    """[SDD 4.1] Удаление: Автор может свое, Админ все, Чужой ничего."""

    # Подготовка данных
    with app.app_context():
        u1 = User(username='Author', email='author@ee', role='User', password_hash='x')
        u2 = User(username='Stranger', email='stranger@ee', role='User', password_hash='x')
        admin = User(username='Admin', email='admin@ee', role='Admin', password_hash='x')
        db.session.add_all([u1, u2, admin])
        db.session.commit()

        m = Material(title='MyWork', description='x', author_id=u1.id, category='Programmeerimine')
        db.session.add(m)
        db.session.commit()
        m_id = m.id

    # 1. Посторонний (Stranger) пытается удалить
    with client.session_transaction() as sess:
        sess['user_id'] = 2  # ID Stranger
        sess['role'] = 'User'

    client.post(f'/materials/{m_id}/delete', follow_redirects=True)

    with app.app_context():
        # Используем db.session.get вместо Material.query.get
        assert db.session.get(Material, m_id) is not None, "FAIL: Посторонний смог удалить чужой материал"

    # 2. Админ пытается удалить
    with client.session_transaction() as sess:
        sess['user_id'] = 3  # ID Admin
        sess['role'] = 'Admin'

    client.post(f'/materials/{m_id}/delete', follow_redirects=True)

    with app.app_context():
        # Используем db.session.get вместо Material.query.get
        assert db.session.get(Material, m_id) is None, "FAIL: Админ не смог удалить материал"


# ==========================================
# 6. БЕЗОПАСНОСТЬ
# Источник: SDD Раздел 7 (Turvalisus)
# ==========================================

def test_csrf_protection(client):
    """
    [SDD 7] Все формы должны иметь CSRF токен.
    """
    # Включаем проверку CSRF в конфиге
    app.config['WTF_CSRF_ENABLED'] = True

    # Пытаемся отправить POST без токена
    response = client.post('/login', data={'email': 'a', 'password': 'b'})

    # Ожидаем 400 Bad Request или ошибку "Missing CSRF token"
    assert response.status_code == 400 or b'CSRF' in response.data, \
        "FAIL: Отсутствует защита CSRF на формах"


# ==========================================
# 7. ПОИСК И ФИЛЬТРАЦИЯ
# Источник: SDD Раздел 4.3
# ==========================================

def test_search_functionality(client, auth):
    """[SDD 4.3] Поиск по ключевому слову (ILIKE логика)."""
    with app.app_context():
        u = User(username='S', email='s@s.ee', password_hash='x')
        db.session.add(u)
        db.session.commit()
        m1 = Material(title='Python intro', description='x', author_id=u.id, is_confirmed=True,
                      category='Programmeerimine')
        m2 = Material(title='Java basics', description='x', author_id=u.id, is_confirmed=True,
                      category='Programmeerimine')
        db.session.add_all([m1, m2])
        db.session.commit()

    # Поиск "Python"
    response = client.get('/?keyword=Python')
    assert b'Python intro' in response.data
    assert b'Java basics' not in response.data