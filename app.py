import os
from datetime import datetime, date
from io import BytesIO
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from functools import wraps

# ---------- App Setup ----------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///visitas.db')
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

# ---------- Routes ----------
@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method=='POST':
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        user = User.query.filter_by(email=email).first()
        if user and user.active and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Credenciales inválidas.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Sesión cerrada.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    if current_user.role in ('superadmin','admin'):
        base = Visitor.query
    else:
        base = Visitor.query.filter_by(site_id=current_user.site_id)

    activos = base.filter(Visitor.hora_salida.is_(None)).order_by(Visitor.hora_entrada.desc()).all()
    cantidad_activos = len(activos)
    ultimos = base.order_by(Visitor.hora_entrada.desc()).limit(15).all()

    alertas = []
    for v in activos:
        if v.hora_entrada:
            delta = (datetime.utcnow() - v.hora_entrada).total_seconds()/3600.0
            if delta >= 8:
                alertas.append({'id':v.id,'nombre':v.nombre,'horas':int(delta),'site': v.site.name if v.site else ''})

    sites = Site.query.order_by(Site.name).all()
    return render_template('index.html', activos=activos, cantidad_activos=cantidad_activos, ultimos=ultimos, alertas=alertas, sites=sites)

@app.route('/registrar', methods=['GET','POST'])
@login_required
def registrar():
    sites = Site.query.filter_by(active=True).order_by(Site.name).all()
    if request.method=='POST':
        nombre = request.form.get('nombre','').strip()
        if not nombre:
            flash('Nombre requerido.', 'danger')
            return redirect(url_for('registrar'))
        site_id = request.form.get('site_id') or current_user.site_id
        v = Visitor(
            nombre=nombre,
            cedula=request.form.get('cedula','').strip(),
            empresa=request.form.get('empresa','').strip(),
            motivo=request.form.get('motivo','').strip(),
            persona_visitada=request.form.get('persona_visitada','').strip(),
            hora_entrada=datetime.utcnow(),
            fecha=date.today(),
            site_id=int(site_id) if site_id else None,
            registrado_por=current_user.id
        )
        db.session.add(v)
        db.session.commit()
        flash('Visitante registrado.', 'success')
        return redirect(url_for('index'))
    return render_template('registrar.html', sites=sites)

@app.route('/salida/<int:vid>', methods=['POST'])
@login_required
def salida(vid):
    v = Visitor.query.get_or_404(vid)
    if current_user.role not in ('superadmin','admin') and v.site_id != current_user.site_id:
        flash('No tiene permiso.', 'danger')
        return redirect(url_for('index'))
    if v.hora_salida is None:
        v.hora_salida = datetime.utcnow()
        db.session.commit()
        flash('Salida registrada.', 'success')
    else:
        flash('Salida ya registrada.', 'info')
    return redirect(request.referrer or url_for('index'))

# ---------- Admin routes (simplified) ----------
@app.route('/admin/users')
@login_required
@role_required('superadmin')
def admin_users():
    users = User.query.order_by(User.email).all()
    sites = Site.query.order_by(Site.name).all()
    return render_template('admin_users.html', users=users, sites=sites)

@app.route('/admin/users/create', methods=['GET','POST'])
@login_required
@role_required('superadmin')
def admin_users_create():
    sites = Site.query.order_by(Site.name).all()
    if request.method=='POST':
        email=request.form.get('email','').strip().lower()
        name=request.form.get('name','').strip()
        role=request.form.get('role','oficial')
        pwd=request.form.get('password','').strip()
        site_id=request.form.get('site_id') or None
        if not email or not pwd or not name: flash('Email, nombre y pwd obligatorios','danger'); return redirect(url_for('admin_users_create'))
        if User.query.filter_by(email=email).first(): flash('Usuario ya existe','danger'); return redirect(url_for('admin_users_create'))
        u=User(email=email,name=name,role=role,password_hash=generate_password_hash(pwd),active=True,site_id=int(site_id) if site_id else None)
        db.session.add(u); db.session.commit(); flash('Usuario creado','success'); return redirect(url_for('admin_users'))
    return render_template('admin_user_form.html', sites=sites, action='create', user=None)

@app.route('/admin/sites')
@login_required
@role_required('admin')
def admin_sites():
    sites = Site.query.order_by(Site.name).all()
    users = User.query.order_by(User.name).all()
    return render_template('admin_sites.html', sites=sites, users=users)

@app.route('/admin/sites/create', methods=['GET','POST'])
@login_required
@role_required('admin')
def admin_sites_create():
    if request.method=='POST':
        name=request.form.get('name','').strip()
        location=request.form.get('location','').strip()
        if not name: flash('Nombre obligatorio','danger'); return redirect(url_for('admin_sites_create'))
        s=Site(name=name, location=location, active=True)
        db.session.add(s); db.session.commit(); flash('Sitio creado','success'); return redirect(url_for('admin_sites'))
    return render_template('admin_site_form.html', action='create', site=None)

# ---------- Reports / Export ----------
@app.route('/listar')
@login_required
def listar():
    q = request.args.get('q','').strip()
    site_filter = request.args.get('site','')
    base = Visitor.query
    if current_user.role == 'oficial':
        base = base.filter_by(site_id=current_user.site_id)
    if q:
        like = f'%{q}%'
        base = base.filter((Visitor.nombre.ilike(like)) | (Visitor.cedula.ilike(like)) | (Visitor.empresa.ilike(like)))
    if site_filter and current_user.role in ('superadmin','admin'):
        try: base = base.filter_by(site_id=int(site_filter))
        except: pass
    visitas = base.order_by(Visitor.hora_entrada.desc()).all()
    sites = Site.query.order_by(Site.name).all()
    return render_template('listar.html', visitas=visitas, sites=sites, q=q, site_filter=site_filter)

@app.route('/reports')
@login_required
def reports():
    nombre = request.args.get('nombre','').strip()
    empresa = request.args.get('empresa','').strip()
    desde = request.args.get('desde','').strip()
    hasta = request.args.get('hasta','').strip()
    site_filter = request.args.get('site','').strip()
    query = Visitor.query
    if current_user.role == 'oficial':
        query = query.filter_by(site_id=current_user.site_id)
    if nombre: query = query.filter(Visitor.nombre.ilike(f'%{nombre}%'))
    if empresa: query = query.filter(Visitor.empresa.ilike(f'%{empresa}%'))
    if site_filter and current_user.role in ('superadmin','admin'):
        try: query = query.filter_by(site_id=int(site_filter))
        except: pass
    if desde:
        try: d = datetime.fromisoformat(desde); query = query.filter(Visitor.hora_entrada >= d)
        except: flash('Formato desde inválido','warning')
    if hasta:
        try: h = datetime.fromisoformat(hasta); query = query.filter(Visitor.hora_entrada <= h)
        except: flash('Formato hasta inválido','warning')
    results = query.order_by(Visitor.hora_entrada.desc()).all()
    sites = Site.query.order_by(Site.name).all()
    return render_template('reports.html', visitantes=results, sites=sites, nombre=nombre, empresa=empresa, desde=desde, hasta=hasta, site_filter=site_filter)

@app.route('/export')
@login_required
def export():
    if current_user.role not in ('superadmin','admin'):
        flash('Acceso denegado', 'danger'); return redirect(url_for('index'))
    sitio = request.args.get('site'); desde = request.args.get('desde'); hasta = request.args.get('hasta')
    query = Visitor.query
    if sitio:
        try: query = query.filter_by(site_id=int(sitio))
        except: pass
    if desde:
        try: query = query.filter(Visitor.hora_entrada >= datetime.fromisoformat(desde))
        except: pass
    if hasta:
        try: query = query.filter(Visitor.hora_entrada <= datetime.fromisoformat(hasta))
        except: pass
    rows=[]
    for v in query.order_by(Visitor.hora_entrada).all():
        rows.append({
            'ID':v.id,
            'Nombre':v.nombre,
            'Cedula':v.cedula,
            'Empresa':v.empresa,
            'Motivo':v.motivo,
            'Persona':v.persona_visitada,
            'Entrada':v.hora_entrada.isoformat() if v.hora_entrada else '',
            'Salida':v.hora_salida.isoformat() if v.hora_salida else '',
            'Sitio':v.site.name if v.site else ''
        })
    df = pd.DataFrame(rows)
    bio=BytesIO(); df.to_excel(bio,index=False); bio.seek(0)
    return send_file(bio, as_attachment=True, download_name='export_visitas.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')


# ---------- App runner (Render-ready) ----------
if __name__ == '__main__':
    with app.app_context():
        # Crear todas las tablas si no existen
        db.create_all()

        # Crear superadmin si no existe
        if not User.query.filter_by(email='jorgemolinabonilla@gmail.com').first():
            u = User(
                email='jorgemolinabonilla@gmail.com',
                name='Super Admin',
                password_hash=generate_password_hash('Jo70156938'),
                role='superadmin',
                active=True
            )
            db.session.add(u)

        # Crear sitios predeterminados
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

    app.run(debug=True)

