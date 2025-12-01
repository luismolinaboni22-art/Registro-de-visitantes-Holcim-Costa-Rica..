import os
from datetime import datetime, date
from io import BytesIO
from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from functools import wraps

# ---------- App Setup ----------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-me')

# Detecta si se usa DATABASE_URL de Render, si no usa SQLite local
db_url = os.getenv('DATABASE_URL')
if db_url and db_url.startswith("postgres://"):
    # PostgreSQL en Render necesita reemplazar 'postgres://' por 'postgresql://'
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///visitas.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ---------- Models ----------
class Site(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    location = db.Column(db.String(300))
    active = db.Column(db.Boolean, default=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    name = db.Column(db.String(200))
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='oficial')  # superadmin, admin, oficial
    active = db.Column(db.Boolean, default=True)
    site_id = db.Column(db.Integer, db.ForeignKey('site.id'), nullable=True)
    site = db.relationship('Site', backref='users')

class Visitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(250), nullable=False)
    cedula = db.Column(db.String(100))
    empresa = db.Column(db.String(200))
    motivo = db.Column(db.String(400))
    persona_visitada = db.Column(db.String(200))
    hora_entrada = db.Column(db.DateTime, default=datetime.utcnow)
    hora_salida = db.Column(db.DateTime, nullable=True)
    fecha = db.Column(db.Date, default=date.today)
    site_id = db.Column(db.Integer, db.ForeignKey('site.id'), nullable=True)
    site = db.relationship('Site', backref='visitors')
    registrado_por = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

# ---------- Login ----------
@login_manager.user_loader
def load_user(uid):
    return User.query.get(int(uid))

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role == role or current_user.role == 'superadmin':
                return f(*args, **kwargs)
            flash('Acceso denegado.', 'danger')
            return redirect(url_for('index'))
        return wrapped
    return decorator

# ---------- Routes (login, logout, index, registrar, salida, admin, reports, export) ----------
# ... Aquí puedes copiar todo tu código de rutas existente (login, logout, index, registrar, salida, listar, reports, export, admin) ...

# ---------- DB Init Function ----------
def init_db():
    with app.app_context():
        db.create_all()

        # Crear superadmin si la tabla y usuario existen
        if 'user' in db.engine.table_names():
            if not User.query.filter_by(email='jorgemolinabonilla@gmail.com').first():
                u = User(
                    email='jorgemolinabonilla@gmail.com',
                    name='Super Admin',
                    password_hash=generate_password_hash('Jo70156938'),
                    role='superadmin',
                    active=True
                )
                db.session.add(u)

        # Crear sitios predeterminados si la tabla existe
        if 'site' in db.engine.table_names():
            default_sites = [
                "Planta Cemento Cartago",
                "Geocycle Administracion",
                "Geocycle Plataforma",
                "Mina La Chilena",
                "Logistica Cartago",
                "Holcim Modular Solutions Alajuela",
                "Holcim Modular Solutions Guapiles",
                "AMCO Heredia",
                "AMCO Guanacaste"
            ]
            for n in default_sites:
                if not Site.query.filter_by(name=n).first():
                    db.session.add(Site(name=n, location='', active=True))
        db.session.commit()

# ---------- App Runner ----------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)


