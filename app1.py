import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import datetime
from werkzeug.utils import secure_filename

# --- CONFIGURAÇÃO DA APLICAÇÃO ---
app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'servidores.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'uma-chave-secreta-muito-dificil-de-adivinhar'
app.config['UPLOAD_FOLDER'] = 'uploads' # Pasta para salvar as fotos

db = SQLAlchemy(app)

@app.context_processor
def inject_year():
    return {'current_year': datetime.utcnow().year}

# --- USUÁRIO E SENHA PARA LOGIN ---
USUARIO_VALIDO = "admin"
SENHA_VALIDA = "educacao2025"


# --- MODELO DO BANCO DE DADOS (COM NOVOS CAMPOS) ---
class Servidor(db.Model):
    num_contrato = db.Column(db.String(50), primary_key=True)
    nome = db.Column(db.String(200), nullable=False)
    cpf = db.Column(db.String(14), unique=True, nullable=False)
    rg = db.Column(db.String(20))
    telefone = db.Column(db.String(20))
    endereco = db.Column(db.String(250))
    funcao = db.Column(db.String(100))
    lotacao = db.Column(db.String(100))
    carga_horaria = db.Column(db.String(50))
    remuneracao = db.Column(db.Float)
    dados_bancarios = db.Column(db.String(200))
    data_inicio = db.Column(db.Date, nullable=True)
    data_saida = db.Column(db.Date, nullable=True)
    observacoes = db.Column(db.Text, nullable=True) # NOVO CAMPO
    foto_filename = db.Column(db.String(100), nullable=True) # NOVO CAMPO

    def __repr__(self):
        return f'<Servidor {self.nome}>'

# --- FUNÇÃO DECORADORA PARA EXIGIR LOGIN ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Por favor, faça login para acessar esta página.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- ROTA PARA SERVIR AS FOTOS SALVAS ---
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- ROTAS DA APLICAÇÃO ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form.get('usuario')
        senha = request.form.get('senha')
        if usuario == USUARIO_VALIDO and senha == SENHA_VALIDA:
            session['logged_in'] = True
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Usuário ou senha inválidos. Tente novamente.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('Você saiu do sistema.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    servidores = Servidor.query.order_by(Servidor.nome).all()
    return render_template('index.html', servidores=servidores)

@app.route('/add', methods=['POST'])
@login_required
def add_server():
    try:
        # Lógica da foto
        foto = request.files.get('foto')
        foto_filename = None
        if foto and foto.filename != '':
            foto_filename = secure_filename(foto.filename)
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_filename))

        # Lógica das datas
        data_inicio_str = request.form.get('data_inicio')
        data_saida_str = request.form.get('data_saida')
        data_inicio_obj = datetime.strptime(data_inicio_str, '%Y-%m-%d').date() if data_inicio_str else None
        data_saida_obj = datetime.strptime(data_saida_str, '%Y-%m-%d').date() if data_saida_str else None

        remuneracao_str = request.form.get('remuneracao').replace('.', '').replace(',', '.')
        remuneracao_val = float(remuneracao_str) if remuneracao_str else 0.0
        
        novo_servidor = Servidor(
            num_contrato=request.form.get('num_contrato'),
            nome=request.form.get('nome'),
            cpf=request.form.get('cpf'),
            rg=request.form.get('rg'),
            telefone=request.form.get('telefone'),
            endereco=request.form.get('endereco'),
            funcao=request.form.get('funcao'),
            lotacao=request.form.get('lotacao'),
            carga_horaria=request.form.get('carga_horaria'),
            remuneracao=remuneracao_val,
            dados_bancarios=request.form.get('dados_bancarios'),
            data_inicio=data_inicio_obj,
            data_saida=data_saida_obj,
            observacoes=request.form.get('observacoes'),
            foto_filename=foto_filename
        )
        db.session.add(novo_servidor)
        db.session.commit()
        flash('Servidor cadastrado com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao cadastrar servidor: {e}', 'danger')
    return redirect(url_for('index'))

@app.route('/editar/<path:id>')
@login_required
def editar(id):
    servidor = Servidor.query.get_or_404(id)
    return render_template('editar.html', servidor=servidor)

@app.route('/update/<path:id>', methods=['POST'])
@login_required
def update_server(id):
    servidor = Servidor.query.get_or_404(id)
    try:
        # Lógica da foto
        foto = request.files.get('foto')
        if foto and foto.filename != '':
            # Apaga a foto antiga se existir
            if servidor.foto_filename:
                old_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], servidor.foto_filename)
                if os.path.exists(old_photo_path):
                    os.remove(old_photo_path)
            
            # Salva a nova foto
            foto_filename = secure_filename(foto.filename)
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_filename))
            servidor.foto_filename = foto_filename
            
        # Lógica das datas
        data_inicio_str = request.form.get('data_inicio')
        data_saida_str = request.form.get('data_saida')
        servidor.data_inicio = datetime.strptime(data_inicio_str, '%Y-%m-%d').date() if data_inicio_str else None
        servidor.data_saida = datetime.strptime(data_saida_str, '%Y-%m-%d').date() if data_saida_str else None

        remuneracao_str = request.form.get('remuneracao').replace('.', '').replace(',', '.')
        remuneracao_val = float(remuneracao_str) if remuneracao_str else 0.0
        
        servidor.nome = request.form.get('nome')
        servidor.cpf = request.form.get('cpf')
        servidor.rg = request.form.get('rg')
        servidor.telefone = request.form.get('telefone')
        servidor.endereco = request.form.get('endereco')
        servidor.funcao = request.form.get('funcao')
        servidor.lotacao = request.form.get('lotacao')
        servidor.carga_horaria = request.form.get('carga_horaria')
        servidor.remuneracao = remuneracao_val
        servidor.dados_bancarios = request.form.get('dados_bancarios')
        servidor.observacoes = request.form.get('observacoes')
        
        db.session.commit()
        flash('Dados do servidor atualizados com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao atualizar servidor: {e}', 'danger')
    return redirect(url_for('index'))

@app.route('/delete/<path:id>')
@login_required
def delete_server(id):
    servidor = Servidor.query.get_or_404(id)
    try:
        # Apaga a foto do servidor antes de apagar o registro
        if servidor.foto_filename:
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], servidor.foto_filename)
            if os.path.exists(photo_path):
                os.remove(photo_path)
        
        db.session.delete(servidor)
        db.session.commit()
        flash('Servidor excluído com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir servidor: {e}', 'danger')
    return redirect(url_for('index'))

# ... as rotas de search e gerar_relatorio_pdf continuam aqui, sem alterações...
# (Omitidas por brevidade, não precisam ser alteradas para esta funcionalidade)
# Mas para garantir, aqui está o código completo do restante do arquivo

@app.route('/search')
@login_required
def search():
    termo = request.args.get('termo')
    if not termo:
        return redirect(url_for('index'))
    
    search_pattern = f"%{termo}%"
    resultados = Servidor.query.filter(
        db.or_(
            Servidor.nome.ilike(search_pattern),
            Servidor.cpf.ilike(search_pattern),
            Servidor.num_contrato.ilike(search_pattern)
        )
    ).order_by(Servidor.nome).all()
    
    flash(f'Exibindo resultados para "{termo}"', 'info')
    return render_template('index.html', servidores=resultados)

@app.route('/relatorio/pdf')
@login_required
def gerar_relatorio_pdf():
    import io
    from reportlab.lib.pagesizes import letter, landscape
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch

    servidores = Servidor.query.order_by(Servidor.nome).all()
    data_emissao = datetime.now().strftime('%d/%m/%Y %H:%M:%S')

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter), topMargin=40, bottomMargin=40)
    
    elements = []
    styles = getSampleStyleSheet()
    styles['h1'].alignment = 1
    styles['h2'].alignment = 1

    logo_path = os.path.join(basedir, 'static', 'logo.png')
    if os.path.exists(logo_path):
        logo_image = Image(logo_path, width=1.6*inch, height=1.6*inch)
        
        p_title = Paragraph("Relatório de Servidores Comissionados", styles['h1'])
        p_subtitle = Paragraph("Secretaria Municipal de Educação de Valença do Piauí", styles['h2'])
        
        header_data = [[logo_image, [p_title, p_subtitle]]]
        header_table = Table(header_data, colWidths=[1.8*inch, 8.2*inch])
        header_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (0, 0), 'CENTER'),
        ]))
        elements.append(header_table)
    else:
        elements.append(Paragraph("Relatório de Servidores Comissionados", styles['h1']))
        elements.append(Paragraph("Secretaria Municipal de Educação de Valença do Piauí", styles['h2']))

    elements.append(Paragraph(f"<i>Emitido em: {data_emissao}</i>", styles['Normal']))
    elements.append(Spacer(1, 0.25 * inch))

    header = ["Nº CONTRATO", "NOME", "FUNÇÃO", "LOTAÇÃO", "CARGA HORÁRIA", "REMUNERAÇÃO (R$)", "VIGÊNCIA"]
    table_data = [header]
    for servidor in servidores:
        remuneracao = f"R$ {servidor.remuneracao:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".") if servidor.remuneracao else 'N/A'
        
        vigencia_str = ""
        if servidor.data_inicio:
            vigencia_str += servidor.data_inicio.strftime('%d/%m/%Y')
        if servidor.data_saida:
            vigencia_str += f" a {servidor.data_saida.strftime('%d/%m/%Y')}"

        row = [
            servidor.num_contrato,
            servidor.nome,
            servidor.funcao or '',
            servidor.lotacao or '',
            servidor.carga_horaria or '',
            remuneracao,
            vigencia_str or ''
        ]
        table_data.append(row)

    table = Table(table_data, colWidths=[1*inch, 2.5*inch, 1.5*inch, 1.5*inch, 1.2*inch, 1.3*inch, 2*inch])
    style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#004d40")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f0f0f0")),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
    ])
    table.setStyle(style)
    elements.append(table)

    doc.build(elements)
    
    buffer.seek(0)
    
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=relatorio_servidores_{datetime.now().strftime("%Y-%m-%d")}.pdf'
    return response

if __name__ == '__main__':
    app.run(debug=True)