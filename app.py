from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev_key')
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(basedir, "instance", "app.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Modelos do DB
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome_completo = db.Column(db.String(100), nullable=False)
    cpf = db.Column(db.String(14), unique=True, nullable=False)
    data_nascimento = db.Column(db.String(10), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash = db.Column(db.String(128), nullable=False)
    dependentes = db.relationship('Dependente', backref='user', lazy=True)

class Dependente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    data_nascimento = db.Column(db.String(10), nullable=False)
    tem_mesada = db.Column(db.Boolean, default=False)
    valor_mesada = db.Column(db.Float, default=0.0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    metas = db.relationship('Meta', backref='dependente', lazy=True)

class Gasto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    descricao = db.Column(db.String(200), nullable=False)
    valor = db.Column(db.Float, nullable=False)
    categoria = db.Column(db.String(50), nullable=False)
    data = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    dependente_id = db.Column(db.Integer, db.ForeignKey('dependente.id'), nullable=True)

class Meta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    meta_valor = db.Column(db.Float, nullable=False)
    atual_valor = db.Column(db.Float, default=0.0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    dependente_id = db.Column(db.Integer, db.ForeignKey('dependente.id'), nullable=True)

# Rotas
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.senha_hash, senha):
            session['user_id'] = user.id
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        flash('Email ou senha inválidos.', 'error')
    return render_template('login.html')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form['nome']
        cpf = request.form['cpf']
        data_nasc = request.form['data_nasc']
        email = request.form['email']
        senha = generate_password_hash(request.form['senha'])
        new_user = User(nome_completo=nome, cpf=cpf, data_nascimento=data_nasc, email=email, senha_hash=senha)
        db.session.add(new_user)
        db.session.commit()
        flash('Cadastro realizado! Faça login.', 'success')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    gastos = Gasto.query.filter_by(user_id=user.id).all()
    return render_template('dashboard.html', user=user, gastos=gastos)

@app.route('/gastos', methods=['GET', 'POST'])
def gastos():
    if 'user_id' not in session: return redirect(url_for('login'))
    if request.method == 'POST':
        descricao = request.form['descricao']
        valor = float(request.form['valor'])
        categoria = request.form['categoria']
        new_gasto = Gasto(descricao=descricao, valor=valor, categoria=categoria, user_id=session['user_id'])
        db.session.add(new_gasto)
        db.session.commit()
        flash('Gasto cadastrado!', 'success')
    user_gastos = Gasto.query.filter_by(user_id=session['user_id']).all()
    return render_template('gastos.html', gastos=user_gastos)

@app.route('/gastos/<int:id>/excluir', methods=['POST'])
def excluir_gasto(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    gasto = Gasto.query.get_or_404(id)
    if gasto.user_id != user.id:
        flash('Acesso negado. Gasto não pertence a você.', 'error')
        return redirect(url_for('gastos'))
    db.session.delete(gasto)
    db.session.commit()
    flash('Gasto excluído com sucesso!', 'success')
    return redirect(url_for('gastos'))

@app.route('/cofrinho', methods=['GET', 'POST'])
def cofrinho():
    if 'user_id' not in session: return redirect(url_for('login'))
    metas = Meta.query.filter_by(user_id=session['user_id']).all()
    if request.method == 'POST':
        nome = request.form['nome']
        meta_valor = float(request.form['meta_valor'])
        new_meta = Meta(nome=nome, meta_valor=meta_valor, user_id=session['user_id'])
        db.session.add(new_meta)
        db.session.commit()
    return render_template('cofrinho.html', metas=metas)

@app.route('/cofrinho/<int:id>/excluir', methods=['POST'])
def excluir_meta(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    meta = Meta.query.get_or_404(id)
    if meta.user_id != user.id:
        flash('Acesso negado.', 'error')
        return redirect(url_for('cofrinho'))
    db.session.delete(meta)
    db.session.commit()
    flash('Meta excluída com sucesso!', 'success')
    return redirect(url_for('cofrinho'))

@app.route('/editar', methods=['GET', 'POST'])
def editar():
    if 'user_id' not in session: return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        senha_atual = request.form['senha_atual']
        if check_password_hash(user.senha_hash, senha_atual):
            user.nome_completo = request.form['nome']
            user.email = request.form['email']
            db.session.commit()
            flash('Informações atualizadas!', 'success')
        else:
            flash('Senha atual inválida.', 'error')
    return render_template('editar.html', user=user)

@app.route('/editar/excluir_conta', methods=['POST'])
def excluir_conta():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    senha_atual = request.form['senha_atual']
    if check_password_hash(user.senha_hash, senha_atual):
        # Deleta dados relacionados (gastos, metas, dependentes)
        Gasto.query.filter_by(user_id=user.id).delete()
        Meta.query.filter_by(user_id=user.id).delete()
        Dependente.query.filter_by(user_id=user.id).delete()
        # Deleta user
        db.session.delete(user)
        db.session.commit()
        # Limpa sessão e logout
        session.pop('user_id', None)
        flash('Conta excluída com sucesso. Obrigado por usar o app!', 'success')
        return redirect(url_for('login'))
    else:
        flash('Senha inválida. Conta não excluída.', 'error')
        return redirect(url_for('editar'))

@app.route('/dependentes', methods=['GET', 'POST'])
def dependentes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        try:
            nome = request.form['nome']
            data_nasc = request.form['data_nasc']
            tem_mesada = 'tem_mesada' in request.form
            valor_mesada = float(request.form.get('valor_mesada', 0)) if tem_mesada else 0.0
            new_dep = Dependente(nome=nome, data_nascimento=data_nasc, tem_mesada=tem_mesada, valor_mesada=valor_mesada, user_id=user.id)
            db.session.add(new_dep)
            db.session.commit()
            flash('Dependente cadastrado!', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Erro ao cadastrar. Tente novamente.', 'error')
    deps = user.dependentes
    return render_template('dependentes.html', dependentes=deps)

@app.route('/dependentes/<int:id>/editar', methods=['POST'])
def editar_dependente(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    dep = Dependente.query.get_or_404(id)
    if dep.user_id != user.id:
        flash('Acesso negado.', 'error')
        return redirect(url_for('dependentes'))
    try:
        senha_atual = request.form['senha_atual']
        if check_password_hash(user.senha_hash, senha_atual):
            dep.nome = request.form['nome']
            dep.data_nascimento = request.form['data_nasc']
            dep.tem_mesada = 'tem_mesada' in request.form
            dep.valor_mesada = float(request.form.get('valor_mesada', 0)) if dep.tem_mesada else 0.0
            db.session.commit()
            flash('Dependente atualizado!', 'success')
        else:
            flash('Senha inválida.', 'error')
    except Exception as e:
        db.session.rollback()
        flash('Erro ao atualizar. Tente novamente.', 'error')
    return redirect(url_for('dependentes'))

@app.route('/dependentes/<int:id>/excluir', methods=['POST'])
def excluir_dependente(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    dep = Dependente.query.get_or_404(id)
    if dep.user_id != user.id:
        flash('Acesso negado.', 'error')
        return redirect(url_for('dependentes'))
    try:
        db.session.delete(dep)
        db.session.commit()
        flash('Dependente excluído com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Erro ao excluir. Tente novamente.', 'error')
    return redirect(url_for('dependentes'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Cria todas as tabelas aqui (substitui o before_first_request)
    app.run(debug=True)