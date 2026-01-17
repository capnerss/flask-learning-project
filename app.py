import os
import requests
from flask import Flask, request, session, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, TextAreaField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Length, Regexp, URL, ValidationError

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_key_for_local_testing')

# --- NASTROJKA BAZY DANNYH ---
basedir = os.path.abspath(os.path.dirname(__file__))
database_url = os.environ.get('DATABASE_URL')

if database_url:
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    db_path = os.path.join(basedir, 'it_materials.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

# --- MODELI ---
class User(db.Model):#
    id = db.Column(db.Integer, primary_key=True)#
    username = db.Column(db.String(80), nullable=False)#
    email = db.Column(db.String(120), unique=True, nullable=False)#
    password_hash = db.Column(db.String(200), nullable=False)#
    role = db.Column(db.String(20), default='User')#

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Material(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50))
    link = db.Column(db.String(500))
    keywords = db.Column(db.String(200))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_confirmed = db.Column(db.Boolean, default=False)
    author = db.relationship('User', backref=db.backref('materials', lazy=True))

# --- FORMS (FLASK-WTF) ---

class RegistrationForm(FlaskForm):
    username = StringField('Kasutajanimi', validators=[DataRequired(), Length(min=3)])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Parool', validators=[
        DataRequired(),
        Length(min=8, message="Parool peab olema vähemalt 8 märki"),
        Regexp(r'.*\d.*', message="Parool peab sisaldama numbrit")
    ])
    submit = SubmitField('Registreeri')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('See e-mail on juba kasutusel.')

class LoginForm(FlaskForm):
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    password = PasswordField('Parool', validators=[DataRequired()])
    submit = SubmitField('Logi sisse')

class MaterialForm(FlaskForm):
    title = StringField('Pealkiri', validators=[DataRequired()])
    description = TextAreaField('Kirjeldus', validators=[DataRequired()])
    category = SelectField('Kategooria', choices=[], validators=[DataRequired()])
    link = StringField('Link materjalile', validators=[DataRequired(), URL(message="Vigane URL")])
    submit = SubmitField('Lisa materjal')

# --- INICIALIZACIJA DANNYH ---
with app.app_context():
    db.create_all()
    
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@kool.ee', role='Admin',
                     password_hash=generate_password_hash('admin123', method='pbkdf2:sha256'))
        db.session.add(admin)
    if not User.query.filter_by(username='curator').first():
        curator = User(username='curator', email='curator@kool.ee', role='Curator',
                       password_hash=generate_password_hash('curator123', method='pbkdf2:sha256'))
        db.session.add(curator)
    
    if not Category.query.first():
        db.session.add(Category(name='Programmeerimine'))
        db.session.add(Category(name='Riistvara'))
        
    db.session.commit()

# --- MARSHRUTY ---

@app.route('/')
def index():
    keyword = request.args.get('keyword', '').lower()
    category = request.args.get('category')
    user_role = session.get('role', 'Guest')

    categories = Category.query.all()

    query = Material.query
    if category:
        query = query.filter_by(category=category)

    if user_role in ['Curator', 'Admin']:
        materials = query.all()
    else:
        materials = query.filter_by(is_confirmed=True).all()

    final_materials = []
    for m in materials:
        if keyword and keyword not in m.title.lower():
            continue
        final_materials.append(m)

    return render_template('index.html', materials=final_materials, categories=categories)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            flash('Sisse logitud!', 'success')
            return redirect(url_for('index'))
        flash('Vale e-mail või parool', 'danger')
    return render_template('auth/login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, email=form.email.data, password_hash=hashed_pw, role='User')
        db.session.add(new_user)
        db.session.commit()
        flash('Konto loodud! Palun logi sisse.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/register.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('Välja logitud', 'info')
    return redirect(url_for('index'))

@app.route('/add', methods=['GET', 'POST'])
def add_material():
    if 'user_id' not in session:
        flash('Palun logi sisse', 'warning')
        return redirect(url_for('login'))
    
    form = MaterialForm()
    form.category.choices = [(c.name, c.name) for c in Category.query.all()]

    if form.validate_on_submit():
        try:
            resp = requests.head(form.link.data, timeout=3, allow_redirects=True)
            if resp.status_code == 404:
                flash('Hoiatus: Link ei vasta (404), aga materjal salvestati.', 'warning')
        except:
            flash('Hoiatus: Linki ei õnnestunud kontrollida.', 'warning')

        role = session.get('role')
        auto_approve = (role in ['Curator', 'Admin'])
        
        new_material = Material(
            title=form.title.data,
            description=form.description.data,
            category=form.category.data,
            link=form.link.data,
            author_id=session['user_id'],
            is_confirmed=auto_approve
        )
        db.session.add(new_material)
        db.session.commit()
        
        msg = "Materjal lisatud!" if auto_approve else "Materjal saadetud kinnitamiseks!"
        flash(msg, 'success')
        return redirect(url_for('index'))
        
    return render_template('material/add.html', form=form)

@app.route('/materials/<int:id>/approve', methods=['POST'])
def approve_material(id):
    if session.get('role') not in ['Curator', 'Admin']:
        flash('Puuduvad õigused', 'danger')
        return redirect(url_for('index'))
        
    material = db.session.get(Material, id)
    if not material:
        return redirect(url_for('index'))

    material.is_confirmed = True
    db.session.commit()
    flash('Materjal kinnitatud', 'success')
    return redirect(url_for('index'))

@app.route('/materials/<int:id>/delete', methods=['POST'])
def delete_material(id):
    if 'user_id' not in session:
        flash('Palun logi sisse', 'warning')
        return redirect(url_for('login'))
        
    material = db.session.get(Material, id)
    if not material:
        return redirect(url_for('index'))

    user_id = session['user_id']
    role = session['role']
    
    if role == 'Admin' or material.author_id == user_id:
        db.session.delete(material)
        db.session.commit()
        flash('Materjal kustutatud', 'success')
    else:
        flash('Puuduvad õigused', 'danger')
        
    return redirect(url_for('index'))

# --- ADMIN PANEL ---

@app.route('/admin')
def admin_dashboard():
    if session.get('role') != 'Admin':
        flash('Ainult administraatorile', 'danger')
        return redirect(url_for('index'))
    
    categories = Category.query.all()
    users = User.query.all()
    return render_template('admin/dashboard.html', categories=categories, users=users)

@app.route('/admin/category/add', methods=['POST'])
def admin_add_category():
    if session.get('role') != 'Admin':
        return redirect(url_for('index'))
        
    name = request.form.get('name')
    if name:
        if not Category.query.filter_by(name=name).first():
            db.session.add(Category(name=name))
            db.session.commit()
            flash('Kategooria lisatud', 'success')
        else:
            flash('Selline kategooria juba eksisteerib', 'warning')
            
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:user_id>/role', methods=['POST'])
def admin_toggle_role(user_id):
    if session.get('role') != 'Admin':
        return redirect(url_for('index'))
        
    user = db.session.get(User, user_id)
    if not user:
        return redirect(url_for('admin_dashboard'))

    if user.role == 'Admin':
        flash('Ei saa muuta administraatori rolli', 'danger')
    elif user.role == 'User':
        user.role = 'Curator'
        flash(f'{user.username} on nüüd Kuraator', 'success')
    elif user.role == 'Curator':
        user.role = 'User'
        flash(f'{user.username} on nüüd Tavakasutaja', 'info')
        
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
def admin_delete_user(user_id):
    if session.get('role') != 'Admin':
        return redirect(url_for('index'))
    
    # Защита от удаления самого себя
    if user_id == session.get('user_id'):
        flash('Ei saa iseennast kustutada', 'danger')
        return redirect(url_for('admin_dashboard'))

    user = db.session.get(User, user_id)
    if user:
        # Сначала удаляем все материалы пользователя, чтобы не было ошибки БД
        Material.query.filter_by(author_id=user.id).delete()
        
        db.session.delete(user)
        db.session.commit()
        flash(f'Kasutaja {user.username} ja tema materjalid kustutatud', 'success')
    else:
        flash('Kasutajat ei leitud', 'warning')

    return redirect(url_for('admin_dashboard'))

if __name__ == "__main__":
    app.run(debug=True)