import os
import io
import csv
import uuid
import locale
from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, send_from_directory, Response, abort
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from sqlalchemy import func, or_
from flask_bcrypt import Bcrypt

# Importações para o gerador de PDF
from reportlab.lib.pagesizes import letter, landscape, A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, BaseDocTemplate, Frame, PageTemplate
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.units import cm, inch

# Importação da biblioteca para escrever números por extenso
from num2words import num2words

# Configura o locale para o português do Brasil para formatar datas
try:
    locale.setlocale(locale.LC_TIME, 'pt_BR.UTF-8')
except locale.Error:
    print("Locale pt_BR.UTF-8 não encontrado, usando o padrão do sistema.")


# --- CONFIGURAÇÃO DA APLICAÇÃO ---
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
# Tenta pegar a URL do banco de dados do ambiente online, se não encontrar, usa o SQLite local.
database_url = os.environ.get('DATABASE_URL')

if database_url:
    # Corrige a URL do PostgreSQL para ser compatível com SQLAlchemy CV
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///' + os.path.join(basedir, 'servidores.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'uma-chave-secreta-muito-dificil-de-adivinhar'
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


# --- MODELOS DO BANCO DE DADOS ---
class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    username = db.Column(db.String(80), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='operador')
    notas = db.relationship('Nota', backref='autor', lazy=True, cascade="all, delete-orphan")

class Servidor(db.Model):
    __tablename__ = 'servidor'
    num_contrato = db.Column(db.String(50), primary_key=True)
    nome = db.Column(db.String(200), nullable=False)
    cpf = db.Column(db.String(14), unique=True, nullable=True) 
    rg = db.Column(db.String(20))
    nacionalidade = db.Column(db.String(50), default='brasileira')
    estado_civil = db.Column(db.String(50), default='solteiro(a)')
    telefone = db.Column(db.String(20))
    endereco = db.Column(db.String(250))
    funcao = db.Column(db.String(100))
    lotacao = db.Column(db.String(100))
    carga_horaria = db.Column(db.String(50))
    remuneracao = db.Column(db.Float)
    dados_bancarios = db.Column(db.String(200))
    data_inicio = db.Column(db.Date, nullable=True)
    data_saida = db.Column(db.Date, nullable=True)
    observacoes = db.Column(db.Text, nullable=True)
    foto_filename = db.Column(db.String(100), nullable=True)
    num_contrato_gerado = db.Column(db.String(10), unique=True, nullable=True)
    documentos = db.relationship('Documento', backref='servidor', lazy=True, cascade="all, delete-orphan")
    
class Nota(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(120), nullable=False)
    conteudo = db.Column(db.Text, nullable=True)
    data_criacao = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Documento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    servidor_id = db.Column(db.String(50), db.ForeignKey('servidor.num_contrato'), nullable=False)

class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    expiration_date = db.Column(db.DateTime, nullable=False)
    renewal_key = db.Column(db.String(100), unique=True, nullable=True)


# --- COMANDOS DE BANCO DE DADOS ---
@app.cli.command("init-db")
def init_db_command():
    db.create_all()
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'documentos'), exist_ok=True)
    print("Banco de dados e pastas de uploads inicializados.")

@app.cli.command("create-admin")
def create_admin_command():
    with app.app_context():
        username = input("Digite o nome de usuário para o admin: ")
        password = input("Digite a senha para o admin: ")
        user = User.query.filter_by(username=username).first()
        if user:
            print(f"Usuário '{username}' já existe.")
            return
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password_hash=hashed_password, role='admin')
        db.session.add(new_user)
        db.session.commit()
        print(f"Usuário administrador '{username}' criado com sucesso!")

@app.cli.command("init-license")
def init_license_command():
    """Cria a licença inicial do sistema."""
    with app.app_context():
        license_exists = License.query.first()
        if not license_exists:
            initial_expiration = datetime.utcnow() + timedelta(days=30)
            new_license = License(id=1, expiration_date=initial_expiration)
            db.session.add(new_license)
            db.session.commit()
            print(f"Licença inicial criada com sucesso! Expira em: {initial_expiration.strftime('%d/%m/%Y')}")
        else:
            print("A licença já existe no sistema.")

# --- FUNÇÕES GLOBAIS E DECORADORES ---
@app.context_processor
def inject_year():
    return {'current_year': datetime.utcnow().year}

def registrar_log(action):
    try:
        if 'logged_in' in session:
            username = session.get('username', 'Anônimo')
            ip_address = request.remote_addr
            log_entry = Log(username=username, action=action, ip_address=ip_address)
            db.session.add(log_entry)
            db.session.commit()
    except Exception as e:
        print(f"Erro ao registrar log: {e}")
        db.session.rollback()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Por favor, faça login para acessar esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Você não tem permissão para acessar esta página.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def check_license(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        allowed_routes = ['login', 'logout', 'renovar_licenca', 'admin_licenca', 'static', 'uploaded_file']
        if request.endpoint in allowed_routes:
            return f(*args, **kwargs)

        licenca = License.query.first()
        if not licenca or licenca.expiration_date < datetime.utcnow():
            # Permite acesso ao admin mesmo com licença expirada, exceto para a página de renovação
            if session.get('role') == 'admin':
                return f(*args, **kwargs)
            flash('Sua licença de uso do sistema expirou. Por favor, renove sua assinatura para continuar.', 'warning')
            return redirect(url_for('renovar_licenca'))
        return f(*args, **kwargs)
    return decorated_function

def cabecalho_e_rodape(canvas, doc):
    canvas.saveState()
    image_path = os.path.join(basedir, 'static', 'timbre.jpg')
    if os.path.exists(image_path):
        canvas.drawImage(image_path, 2*cm, A4[0] - 2.5*cm if doc.pagesize == A4 else landscape(A4)[1] - 2.5*cm, width=17*cm, height=2.2*cm, preserveAspectRatio=True, mask='auto')
    canvas.setFont('Helvetica', 9)
    canvas.drawString(2*cm, 1.5*cm, f"Emitido em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    canvas.drawRightString(doc.width + doc.leftMargin, 1.5*cm, f"Página {doc.page}")
    canvas.restoreState()


# --- ROTAS DE AUTENTICAÇÃO E LICENÇA ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('usuario')
        password = request.form.get('senha')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            session['logged_in'] = True
            session['username'] = user.username
            session['role'] = user.role
            registrar_log('Fez login no sistema.')
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuário ou senha inválidos.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    registrar_log('Fez logout do sistema.')
    session.clear()
    flash('Você saiu do sistema.', 'info')
    return redirect(url_for('login'))

@app.route('/admin/licenca', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_licenca():
    licenca = License.query.first_or_404()
    if request.method == 'POST':
        nova_chave = str(uuid.uuid4())
        licenca.renewal_key = nova_chave
        db.session.commit()
        registrar_log(f'Gerou uma nova chave de renovação.')
        flash(f'Nova chave de renovação gerada com sucesso!', 'success')
        return redirect(url_for('admin_licenca'))
    return render_template('admin_licenca.html', licenca=licenca)

@app.route('/renovar', methods=['GET', 'POST'])
@login_required
def renovar_licenca():
    licenca = License.query.first_or_404()
    if request.method == 'POST':
        chave_inserida = request.form.get('renewal_key')
        if licenca.renewal_key and licenca.renewal_key == chave_inserida:
            licenca.expiration_date = datetime.utcnow() + timedelta(days=31)
            licenca.renewal_key = None
            db.session.commit()
            registrar_log('Renovou a licença do sistema com sucesso.')
            flash('Licença renovada com sucesso! Obrigado.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Chave de renovação inválida ou já utilizada.', 'danger')
    
    if licenca.expiration_date >= datetime.utcnow() and session.get('role') != 'admin':
        return redirect(url_for('dashboard'))
         
    return render_template('renovar_licenca.html')


# --- ROTAS PRINCIPAIS DA APLICAÇÃO ---
@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/')
@login_required
@check_license
def dashboard():
    total_servidores = db.session.query(func.count(Servidor.num_contrato)).scalar()
    remuneracao_media = db.session.query(func.avg(Servidor.remuneracao)).scalar()
    servidores_por_funcao = db.session.query(Servidor.funcao, func.count(Servidor.funcao)).group_by(Servidor.funcao).order_by(func.count(Servidor.funcao).desc()).all()
    servidores_por_lotacao = db.session.query(Servidor.lotacao, func.count(Servidor.lotacao)).group_by(Servidor.lotacao).order_by(func.count(Servidor.lotacao).desc()).all()
    funcao_labels = [item[0] or "Não Especificado" for item in servidores_por_funcao]
    funcao_data = [item[1] for item in servidores_por_funcao]
    lotacao_labels = [item[0] or "Não Especificado" for item in servidores_por_lotacao]
    lotacao_data = [item[1] for item in servidores_por_lotacao]
    hoje = datetime.now().date()
    data_limite = hoje + timedelta(days=60)
    contratos_a_vencer = Servidor.query.filter(Servidor.data_saida.isnot(None), Servidor.data_saida >= hoje, Servidor.data_saida <= data_limite).order_by(Servidor.data_saida.asc()).all()
    servidores_incompletos = Servidor.query.filter(or_(Servidor.cpf == None, Servidor.cpf == '', Servidor.rg == None, Servidor.rg == '', Servidor.endereco == None, Servidor.endereco == '')).order_by(Servidor.nome).all()
    return render_template('dashboard.html', total_servidores=total_servidores, remuneracao_media=remuneracao_media, contratos_a_vencer=contratos_a_vencer, funcao_labels=funcao_labels, funcao_data=funcao_data, lotacao_labels=lotacao_labels, lotacao_data=lotacao_data, servidores_incompletos=servidores_incompletos)

@app.route('/logs')
@login_required
@admin_required
@check_license
def ver_logs():
    page = request.args.get('page', 1, type=int)
    logs_pagination = Log.query.order_by(Log.timestamp.desc()).paginate(page=page, per_page=25, error_out=False)
    return render_template('logs.html', logs=logs_pagination)

@app.route('/usuarios')
@login_required
@admin_required
@check_license
def lista_usuarios():
    usuarios = User.query.order_by(User.username).all()
    return render_template('usuarios.html', usuarios=usuarios)

@app.route('/usuarios/add', methods=['POST'])
@login_required
@admin_required
@check_license
def add_usuario():
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role', 'operador')
    if not username or not password:
        flash('Nome de usuário e senha são obrigatórios.', 'warning')
        return redirect(url_for('lista_usuarios'))
    user_exists = User.query.filter_by(username=username).first()
    if user_exists:
        flash('Este nome de usuário já existe.', 'danger')
        return redirect(url_for('lista_usuarios'))
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, password_hash=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()
    registrar_log(f'Criou o usuário: "{username}" com o papel "{role}".')
    flash(f'Usuário "{username}" criado com sucesso!', 'success')
    return redirect(url_for('lista_usuarios'))

@app.route('/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
@check_license
def editar_usuario(id):
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        if user.role == 'admin' and User.query.filter_by(role='admin').count() == 1 and request.form.get('role') == 'operador':
            flash('Não é possível remover o status de administrador do último admin do sistema.', 'danger')
            return redirect(url_for('editar_usuario', id=id))
        new_username = request.form.get('username')
        user_exists = User.query.filter(User.username == new_username, User.id != id).first()
        if user_exists:
            flash('Este nome de usuário já está em uso.', 'danger')
            return render_template('editar_usuario.html', user=user)
        user.username = new_username
        user.role = request.form.get('role')
        new_password = request.form.get('password')
        if new_password:
            user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()
        registrar_log(f'Editou o usuário: "{user.username}".')
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('lista_usuarios'))
    return render_template('editar_usuario.html', user=user)

@app.route('/usuarios/delete/<int:id>')
@login_required
@admin_required
@check_license
def delete_usuario(id):
    if User.query.count() <= 1:
        flash('Não é possível excluir o último usuário do sistema.', 'danger')
        return redirect(url_for('lista_usuarios'))
    user_to_delete = User.query.get_or_404(id)
    if user_to_delete.username == session.get('username'):
        flash('Você não pode excluir seu próprio usuário.', 'danger')
        return redirect(url_for('lista_usuarios'))
    username_deleted = user_to_delete.username
    db.session.delete(user_to_delete)
    db.session.commit()
    registrar_log(f'Excluiu o usuário: "{username_deleted}".')
    flash(f'Usuário "{username_deleted}" excluído.', 'success')
    return redirect(url_for('lista_usuarios'))
    
@app.route('/bloco_de_notas')
@login_required
@check_license
def bloco_de_notas():
    user = User.query.filter_by(username=session['username']).first_or_404()
    notas = Nota.query.filter_by(user_id=user.id).order_by(Nota.data_criacao.desc()).all()
    return render_template('bloco_de_notas.html', notas=notas)

@app.route('/notas/add', methods=['POST'])
@login_required
@check_license
def add_nota():
    user = User.query.filter_by(username=session['username']).first_or_404()
    titulo = request.form.get('titulo')
    conteudo = request.form.get('conteudo')
    if not titulo:
        flash('O título da anotação é obrigatório.', 'warning')
        return redirect(url_for('bloco_de_notas'))
    nova_nota = Nota(titulo=titulo, conteudo=conteudo, autor=user)
    db.session.add(nova_nota)
    db.session.commit()
    registrar_log(f'Criou a anotação: "{titulo}"')
    flash('Anotação criada com sucesso!', 'success')
    return redirect(url_for('bloco_de_notas'))

@app.route('/notas/update/<int:id>', methods=['POST'])
@login_required
@check_license
def update_nota(id):
    nota = Nota.query.get_or_404(id)
    if nota.autor.username != session['username']:
        abort(403)
    nota.titulo = request.form.get('titulo')
    nota.conteudo = request.form.get('conteudo')
    db.session.commit()
    registrar_log(f'Editou a anotação: "{nota.titulo}"')
    flash('Anotação atualizada com sucesso!', 'success')
    return redirect(url_for('bloco_de_notas'))

@app.route('/notas/delete/<int:id>')
@login_required
@check_license
def delete_nota(id):
    nota = Nota.query.get_or_404(id)
    if nota.autor.username != session['username']:
        abort(403)
    titulo_nota = nota.titulo
    db.session.delete(nota)
    db.session.commit()
    registrar_log(f'Excluiu a anotação: "{titulo_nota}"')
    flash('Anotação excluída com sucesso!', 'success')
    return redirect(url_for('bloco_de_notas'))

@app.route('/servidores')
@login_required
@check_license
def lista_servidores():
    termo_busca = request.args.get('termo')
    funcao_filtro = request.args.get('funcao')
    lotacao_filtro = request.args.get('lotacao')
    query = Servidor.query
    if termo_busca:
        search_pattern = f"%{termo_busca}%"
        query = query.filter(or_(Servidor.nome.ilike(search_pattern), Servidor.cpf.ilike(search_pattern), Servidor.num_contrato.ilike(search_pattern)))
    if funcao_filtro:
        query = query.filter(Servidor.funcao == funcao_filtro)
    if lotacao_filtro:
        query = query.filter(Servidor.lotacao == lotacao_filtro)
    servidores = query.order_by(Servidor.nome).all()
    funcoes_disponiveis = [r[0] for r in db.session.query(Servidor.funcao).distinct().order_by(Servidor.funcao).all() if r[0]]
    lotacoes_disponiveis = [r[0] for r in db.session.query(Servidor.lotacao).distinct().order_by(Servidor.lotacao).all() if r[0]]
    return render_template('index.html', servidores=servidores, funcoes_disponiveis=funcoes_disponiveis, lotacoes_disponiveis=lotacoes_disponiveis)

@app.route('/add', methods=['POST'])
@login_required
@check_license
def add_server():
    try:
        foto = request.files.get('foto')
        foto_filename = None
        if foto and foto.filename != '':
            foto_filename = secure_filename(foto.filename)
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_filename))
        data_inicio_str = request.form.get('data_inicio')
        data_saida_str = request.form.get('data_saida')
        data_inicio_obj = datetime.strptime(data_inicio_str, '%Y-%m-%d').date() if data_inicio_str else None
        data_saida_obj = datetime.strptime(data_saida_str, '%Y-%m-%d').date() if data_saida_str else None
        remuneracao_str = request.form.get('remuneracao', '0').replace('.', '').replace(',', '.')
        remuneracao_val = float(remuneracao_str) if remuneracao_str else 0.0
        novo_servidor = Servidor(num_contrato=request.form.get('num_contrato'), nome=request.form.get('nome'), cpf=request.form.get('cpf'), rg=request.form.get('rg'), nacionalidade=request.form.get('nacionalidade'), estado_civil=request.form.get('estado_civil'), telefone=request.form.get('telefone'), endereco=request.form.get('endereco'), funcao=request.form.get('funcao'), lotacao=request.form.get('lotacao'), carga_horaria=request.form.get('carga_horaria'), remuneracao=remuneracao_val, dados_bancarios=request.form.get('dados_bancarios'), data_inicio=data_inicio_obj, data_saida=data_saida_obj, observacoes=request.form.get('observacoes'), foto_filename=foto_filename)
        db.session.add(novo_servidor)
        db.session.commit()
        registrar_log(f'Cadastrou o servidor: "{novo_servidor.nome}" (Vínculo: {novo_servidor.num_contrato}).')
        flash('Servidor cadastrado com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        registrar_log(f'Falha ao tentar cadastrar servidor. Erro: {e}')
        flash(f'Erro ao cadastrar servidor: {e}', 'danger')
    return redirect(url_for('lista_servidores'))

@app.route('/editar/<path:id>', methods=['GET', 'POST'])
@login_required
@check_license
def editar_servidor(id):
    servidor = Servidor.query.get_or_404(id)
    if request.method == 'POST':
        try:
            foto = request.files.get('foto')
            if foto and foto.filename != '':
                if servidor.foto_filename and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], servidor.foto_filename)):
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], servidor.foto_filename))
                foto_filename = secure_filename(foto.filename)
                foto.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_filename))
                servidor.foto_filename = foto_filename
            data_inicio_str = request.form.get('data_inicio')
            data_saida_str = request.form.get('data_saida')
            servidor.data_inicio = datetime.strptime(data_inicio_str, '%Y-%m-%d').date() if data_inicio_str else None
            servidor.data_saida = datetime.strptime(data_saida_str, '%Y-%m-%d').date() if data_saida_str else None
            remuneracao_str = request.form.get('remuneracao', '0').replace('.', '').replace(',', '.')
            servidor.remuneracao = float(remuneracao_str) if remuneracao_str else 0.0
            servidor.nome = request.form.get('nome')
            servidor.cpf = request.form.get('cpf')
            servidor.rg = request.form.get('rg')
            servidor.nacionalidade = request.form.get('nacionalidade')
            servidor.estado_civil = request.form.get('estado_civil')
            servidor.telefone = request.form.get('telefone')
            servidor.endereco = request.form.get('endereco')
            servidor.funcao = request.form.get('funcao')
            servidor.lotacao = request.form.get('lotacao')
            servidor.carga_horaria = request.form.get('carga_horaria')
            servidor.dados_bancarios = request.form.get('dados_bancarios')
            servidor.observacoes = request.form.get('observacoes')
            db.session.commit()
            registrar_log(f'Atualizou os dados do servidor: "{servidor.nome}".')
            flash('Dados do servidor atualizados com sucesso!', 'success')
            return redirect(url_for('lista_servidores'))
        except Exception as e:
            db.session.rollback()
            registrar_log(f'Falha ao tentar atualizar o servidor "{servidor.nome}". Erro: {e}')
            flash(f'Erro ao atualizar servidor: {e}', 'danger')
            return redirect(url_for('editar_servidor', id=id))
    return render_template('editar.html', servidor=servidor)

@app.route('/delete/<path:id>')
@login_required
@admin_required
@check_license
def delete_server(id):
    servidor = Servidor.query.get_or_404(id)
    nome_servidor = servidor.nome
    try:
        if servidor.foto_filename and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], servidor.foto_filename)):
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], servidor.foto_filename))
        for doc in servidor.documentos:
            doc_path = os.path.join(app.config['UPLOAD_FOLDER'], 'documentos', doc.filename)
            if os.path.exists(doc_path):
                os.remove(doc_path)
        db.session.delete(servidor)
        db.session.commit()
        registrar_log(f'Excluiu o servidor: "{nome_servidor}".')
        flash('Servidor excluído com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        registrar_log(f'Falha ao tentar excluir o servidor "{nome_servidor}". Erro: {e}')
        flash(f'Erro ao excluir servidor: {e}', 'danger')
    return redirect(url_for('lista_servidores'))

# --- ROTAS DE DOCUMENTOS, RELATÓRIOS E CONTRATOS ---
@app.route('/documentos/upload/<path:servidor_id>', methods=['POST'])
@login_required
@check_license
def upload_documento(servidor_id):
    servidor = Servidor.query.get_or_404(servidor_id)
    if 'documento' not in request.files:
        flash('Nenhum arquivo enviado.', 'danger')
        return redirect(url_for('editar_servidor', id=servidor_id))
    file = request.files['documento']
    description = request.form.get('descricao')
    if file.filename == '' or not description:
        flash('A descrição e o arquivo são obrigatórios.', 'warning')
        return redirect(url_for('editar_servidor', id=servidor_id))
    if file:
        filename = str(uuid.uuid4().hex) + '_' + secure_filename(file.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], 'documentos')
        os.makedirs(upload_path, exist_ok=True)
        file.save(os.path.join(upload_path, filename))
        novo_documento = Documento(filename=filename, description=description, servidor_id=servidor_id)
        db.session.add(novo_documento)
        db.session.commit()
        registrar_log(f'Anexou o documento "{description}" para o servidor "{servidor.nome}".')
        flash('Documento anexado com sucesso!', 'success')
    return redirect(url_for('editar_servidor', id=servidor_id))

@app.route('/documentos/download/<int:documento_id>')
@login_required
@check_license
def download_documento(documento_id):
    documento = Documento.query.get_or_404(documento_id)
    docs_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'documentos')
    return send_from_directory(docs_folder, documento.filename, as_attachment=True)

@app.route('/documentos/delete/<int:documento_id>')
@login_required
@admin_required
@check_license
def delete_documento(documento_id):
    documento = Documento.query.get_or_404(documento_id)
    servidor_id = documento.servidor_id
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'documentos', documento.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    desc_documento = documento.description
    nome_servidor = documento.servidor.nome
    db.session.delete(documento)
    db.session.commit()
    registrar_log(f'Excluiu o documento "{desc_documento}" do servidor "{nome_servidor}".')
    flash('Documento excluído com sucesso!', 'success')
    return redirect(url_for('editar_servidor', id=servidor_id))

@app.route('/baixar_modelo_csv')
@login_required
def baixar_modelo_csv():
    header = ['Nº CONTRATO', 'NOME', 'FUNÇÃO', 'LOTAÇÃO', 'CARGA HORÁRIA', 'REMUNERAÇÃO', 'VIGÊNCIA']
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    writer.writerow(header)
    csv_content = output.getvalue()
    response = Response(csv_content.encode('utf-8-sig'), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=modelo_importacao_servidores.csv'})
    return response

@app.route('/importar_servidores', methods=['POST'])
@login_required
@admin_required
@check_license
def importar_servidores():
    if 'csv_file' not in request.files:
        flash('Nenhum arquivo enviado.', 'danger')
        return redirect(url_for('lista_servidores'))
    file = request.files['csv_file']
    if file.filename == '':
        flash('Nenhum arquivo selecionado.', 'danger')
        return redirect(url_for('lista_servidores'))
    if file and file.filename.endswith('.csv'):
        try:
            file_content = file.stream.read().decode("utf-8-sig")
            dialect = csv.Sniffer().sniff(file_content[:1024])
            stream = io.StringIO(file_content)
            csv_input = csv.DictReader(stream, dialect=dialect)
            novos_servidores = []
            skipped_count = 0
            for row in csv_input:
                num_contrato = row.get('Nº CONTRATO')
                if not num_contrato:
                    skipped_count += 1
                    continue
                servidor_existente = Servidor.query.get(num_contrato)
                if servidor_existente:
                    skipped_count += 1
                    continue
                data_inicio_obj, data_saida_obj = None, None
                vigencia = row.get('VIGÊNCIA', '').strip()
                if ' a ' in vigencia:
                    try:
                        inicio_str, fim_str = vigencia.split(' a ')
                        data_inicio_obj = datetime.strptime(inicio_str.strip(), '%d/%m/%Y').date()
                        data_saida_obj = datetime.strptime(fim_str.strip(), '%d/%m/%Y').date()
                    except ValueError:
                        pass
                remuneracao_str = row.get('REMUNERAÇÃO', '0').replace('R$', '').replace('.', '').replace(',', '.').strip()
                remuneracao_val = float(remuneracao_str) if remuneracao_str else 0.0
                novo_servidor = Servidor(num_contrato=num_contrato, nome=row.get('NOME'), funcao=row.get('FUNÇÃO'), lotacao=row.get('LOTAÇÃO'), carga_horaria=row.get('CARGA HORÁRIA'), remuneracao=remuneracao_val, data_inicio=data_inicio_obj, data_saida=data_saida_obj, cpf=None)
                novos_servidores.append(novo_servidor)
            if novos_servidores:
                db.session.add_all(novos_servidores)
                db.session.commit()
            added_count = len(novos_servidores)
            registrar_log(f'Importou {added_count} novos servidores via CSV.')
            flash(f'Importação concluída! {added_count} servidores adicionados. {skipped_count} registros ignorados (duplicados ou inválidos).', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Ocorreu um erro ao processar o arquivo: {e}', 'danger')
        return redirect(url_for('lista_servidores'))
    else:
        flash('Formato de arquivo inválido. Por favor, envie um arquivo .csv.', 'warning')
        return redirect(url_for('lista_servidores'))

@app.route('/exportar_csv')
@login_required
@check_license
def exportar_csv():
    query = Servidor.query
    termo_busca = request.args.get('termo')
    funcao_filtro = request.args.get('funcao')
    lotacao_filtro = request.args.get('lotacao')
    if termo_busca:
        search_pattern = f"%{termo_busca}%"
        query = query.filter(or_(Servidor.nome.ilike(search_pattern), Servidor.cpf.ilike(search_pattern), Servidor.num_contrato.ilike(search_pattern)))
    if funcao_filtro:
        query = query.filter(Servidor.funcao == funcao_filtro)
    if lotacao_filtro:
        query = query.filter(Servidor.lotacao == lotacao_filtro)
    servidores = query.order_by(Servidor.nome).all()
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    header = ['Nº CONTRATO', 'NOME', 'FUNÇÃO', 'LOTAÇÃO', 'CARGA HORÁRIA', 'REMUNERAÇÃO', 'VIGÊNCIA']
    writer.writerow(header)
    for s in servidores:
        vigencia = ''
        if s.data_inicio: vigencia += s.data_inicio.strftime('%d/%m/%Y')
        if s.data_saida: vigencia += f" a {s.data_saida.strftime('%d/%m/%Y')}"
        remuneracao = f"{s.remuneracao:.2f}".replace('.', ',') if s.remuneracao else '0,00'
        writer.writerow([s.num_contrato, s.nome, s.funcao, s.lotacao, s.carga_horaria, remuneracao, vigencia])
    csv_content = output.getvalue()
    response = Response(csv_content.encode('utf-8-sig'), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=relatorio_servidores.csv'})
    registrar_log('Exportou dados de servidores para CSV.')
    return response

@app.route('/relatorio/html')
@login_required
@check_license
def gerar_relatorio_html():
    servidores = Servidor.query.order_by(Servidor.nome).all()
    data_emissao = datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    registrar_log('Gerou um relatório de servidores em HTML.')
    return render_template('relatorio_template.html', servidores=servidores, data_emissao=data_emissao)

@app.route('/relatorio/pdf')
@login_required
@check_license
def gerar_relatorio_pdf():
    servidores = Servidor.query.order_by(Servidor.nome).all()
    buffer = io.BytesIO()
    doc = BaseDocTemplate(buffer, pagesize=landscape(A4), leftMargin=1.5*cm, rightMargin=1.5*cm, topMargin=3*cm, bottomMargin=2.5*cm)
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id='normal')
    template = PageTemplate(id='main_template', frames=[frame], onPage=cabecalho_e_rodape)
    doc.addPageTemplates([template])
    styles = getSampleStyleSheet()
    p_style = ParagraphStyle(name='CustomNormal', parent=styles['Normal'], alignment=TA_CENTER, fontSize=8)
    header_style = ParagraphStyle(name='CustomHeader', parent=styles['Normal'], alignment=TA_CENTER, fontSize=9, fontName='Helvetica-Bold')
    
    story = [Paragraph("Relatório Geral de Servidores", styles['h1']), Spacer(1, 1*cm)]
    
    table_data = [[Paragraph(h, header_style) for h in ["Nº VÍNCULO", "NOME", "FUNÇÃO", "LOTAÇÃO", "REMUNERAÇÃO", "VIGÊNCIA"]]]
    for servidor in servidores:
        row = [
            Paragraph(servidor.num_contrato or '', p_style),
            Paragraph(servidor.nome or '', p_style),
            Paragraph(servidor.funcao or '', p_style),
            Paragraph(servidor.lotacao or '', p_style),
            Paragraph(f"R$ {servidor.remuneracao:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".") if servidor.remuneracao else 'N/A', p_style),
            Paragraph(f"{servidor.data_inicio.strftime('%d/%m/%Y') if servidor.data_inicio else ''} a {servidor.data_saida.strftime('%d/%m/%Y') if servidor.data_saida else ''}", p_style)
        ]
        table_data.append(row)
        
    table = Table(table_data, colWidths=[3*cm, 7*cm, 4*cm, 4*cm, 3*cm, 4.5*cm])
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#004d40')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ])
    for i, row in enumerate(table_data[1:], 1):
        if i % 2 == 0:
            style.add('BACKGROUND', (0, i), (-1, i), colors.HexColor('#E0E0E0'))
    table.setStyle(style)
    story.append(table)
    doc.build(story)
    buffer.seek(0)
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=relatorio_servidores_{datetime.now().strftime("%Y-%m-%d")}.pdf'
    registrar_log('Gerou um relatório de servidores em PDF.')
    return response
    
@app.route('/servidor/<path:id>/gerar-contrato')
@login_required
@check_license
def gerar_contrato(id):
    servidor = Servidor.query.get_or_404(id)
    ano_atual = datetime.now().year
    if not servidor.num_contrato_gerado:
        ultimo_contrato = db.session.query(func.max(Servidor.num_contrato_gerado)).filter(Servidor.num_contrato_gerado.like(f'%/{ano_atual}')).scalar()
        novo_num = int(ultimo_contrato.split('/')[0]) + 1 if ultimo_contrato else 1
        servidor.num_contrato_gerado = f"{novo_num:02d}/{ano_atual}"
        db.session.commit()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, leftMargin=2*cm, rightMargin=2*cm, topMargin=1.5*cm, bottomMargin=1.5*cm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CenterBold', alignment=TA_CENTER, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='Center', alignment=TA_CENTER, fontName='Helvetica'))
    styles.add(ParagraphStyle(name='Justify', alignment=TA_JUSTIFY, firstLineIndent=2*cm, spaceBefore=4, spaceAfter=4, leading=14))
    styles.add(ParagraphStyle(name='Justify_NoIndent', alignment=TA_JUSTIFY, spaceBefore=4, spaceAfter=4, leading=14))
    styles.add(ParagraphStyle(name='Clausula', alignment=TA_JUSTIFY, firstLineIndent=2*cm, spaceBefore=8, spaceAfter=4, leading=14, fontName='Helvetica-Bold'))
    story = []
    image_path = os.path.join(basedir, 'static', 'timbre.jpg')
    if os.path.exists(image_path):
        img = Image(image_path, width=17*cm, height=2.2*cm)
        story.append(img)
        story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph(f"CONTRATO ADMINISTRATIVO Nº {servidor.num_contrato_gerado}", styles['CenterBold']))
    story.append(Spacer(1, 1*cm))
    partes_texto = f"""Pelo presente instrumento particular, de um lado o <b>MUNICÍPIO DE VALENÇA DO PIAUI - SECRETARIA DE EDUCAÇÃO</b>, CNPJ de N° 06.095.146/0001-44, com sede na Rua Epaminondas Nogueira, n°1425, Bairro São Francisco, na cidade de Valença do Piauí, representada neste ato pela Secretária Municipal de Educação a Sr.ª <b>ANTONIA IARA DA COSTA</b>, brasileira, portadora do RG nº 1287967 SSP/PI e inscrita no CPF nº 566.312.943-04, doravante denominado <b>CONTRATANTE</b>, e de outro lado a Sr.ª <b>{servidor.nome.upper()}</b>, nacionalidade {servidor.nacionalidade or 'brasileira'}, piauiense, com RG nº {servidor.rg or '(não informado)'} SSP/PI, inscrita no CPF nº {servidor.cpf or '(não informado)'}, residente e domiciliada na {servidor.endereco or '(não informado)'}, doravante denominada <b>CONTRATADA</b> têm, entre si, justo e contratada, com base no que dispõe o Art. 37, inciso IX da Constituição Federal, mediante as cláusulas e condições que seguem:"""
    story.append(Paragraph(partes_texto, styles['Justify']))
    story.append(Paragraph("<b><u>1-DO OBJETO</u></b>", styles['Clausula']))
    story.append(Paragraph(f"<b>CLÁUSULA PRIMEIRA</b> - O objeto do presente contrato é a contratação de Servidor Temporário para atender ao Excepcional Interesse Público para a prestação de serviços na função de {servidor.funcao}, atendido as determinações da Secretaria Municipal de Educação, conforme Constituição Federal, artigo 37, inciso IX.", styles['Justify']))
    story.append(Paragraph("<b>PARÁGRAFO ÚNICO</b> - Os trabalhos serão desenvolvidos em estrita observância às cláusulas deste contrato, principalmente no tocante às obrigações da CONTRATADA.", styles['Justify']))
    story.append(Paragraph("<b><u>2-DO PREÇO</u></b>", styles['Clausula']))
    remuneracao_valor = servidor.remuneracao or 0.0
    remuneracao_extenso = num2words(remuneracao_valor, lang='pt_BR', to='currency')
    story.append(Paragraph(f"<b>CLÁUSULA SEGUNDA</b> - O CONTRATANTE pagará a CONTRATADA o valor mensal de <b>R$ {remuneracao_valor:,.2f} ({remuneracao_extenso.title()})</b>.", styles['Justify']))
    story.append(Paragraph("Pelos serviços contratados, estando incluídos nos mesmos todos os insumos, taxas, encargos e demais despesas;", styles['Justify_NoIndent']))
    story.append(Paragraph("<b><u>3-DA JORNADA DE TRABALHO</u></b>", styles['Clausula']))
    story.append(Paragraph(f"<b>CLÁUSULA TERCEIRA</b> - A jornada de trabalho da CONTRATADA durante a vigência do presente contrato é de {servidor.carga_horaria or '40 (quarenta)'} horas semanais, regime de dedicação exclusiva, sob pena de rescisão contratual;", styles['Justify']))
    story.append(Paragraph("<b><u>4-DO PRAZO</u></b>", styles['Clausula']))
    data_inicio_str = servidor.data_inicio.strftime('%d de %B de %Y') if servidor.data_inicio else '(Data de início não informada)'
    data_saida_str = servidor.data_saida.strftime('%d de %B de %Y') if servidor.data_saida else '(Data de término não informada)'
    story.append(Paragraph(f"<b>CLÁUSULA QUARTA</b> - A contratada trabalhará em caráter de excepcionalidade, contados a partir de {data_inicio_str} a {data_saida_str}.", styles['Justify']))
    story.append(Spacer(1, 2*cm))
    data_hoje = datetime.now()
    story.append(Paragraph(f"Valença do Piauí/PI, {data_hoje.day} de {data_hoje.strftime('%B')} de {data_hoje.year}.", styles['Center']))
    story.append(Spacer(1, 2*cm))
    story.append(Paragraph("________________________________________", styles['Center']))
    story.append(Paragraph("ANTONIA IARA DA COSTA", styles['Center']))
    story.append(Paragraph("CONTRATANTE", styles['Center']))
    story.append(Spacer(1, 2*cm))
    story.append(Paragraph("________________________________________", styles['Center']))
    story.append(Paragraph(servidor.nome.upper(), styles['Center']))
    story.append(Paragraph("CONTRATADO(A)", styles['Center']))
    doc.build(story)
    buffer.seek(0)
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=Contrato_{servidor.nome.replace(" ", "_")}.pdf'
    registrar_log(f'Gerou o contrato em PDF para o servidor: "{servidor.nome}".')
    return response

# --- BLOCO PRINCIPAL ---
if __name__ == '__main__':
    app.run(debug=True)