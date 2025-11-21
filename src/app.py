from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask import redirect, url_for, render_template, request, flash, jsonify
from database import Database, Config, User, Passwords
from typing import Dict, Any, List, Optional
from cryptograph import Cryptograph
from ntfy import notifications_bp
from dataclasses import dataclass
from functools import wraps

import requests, json, os, traceback, sys

try:
    from werkzeug.urls import url_parse
except ImportError:
    from urllib.parse import urlparse as url_parse


database = Database()
cryptograph = Cryptograph()
app = Config.app
login_manager = LoginManager(app)
login_manager.login_view = 'login'
current_user : User | None
ITEM_CONFIGS = json.load(open('./src/config.json', 'r'))


app.register_blueprint(notifications_bp)

@dataclass
class Field:
    name: str
    label: str
    type: str
    required: bool = False
    placeholder: str = ''
    options: Optional[List[Dict]] = None
    checked: bool = False
    dataSource: str = ''
    searchable: bool = False
    tab: str = ''
    regex: Optional[str] = None
    maxLength: Optional[int] = None
    regexCondition: Optional[str] = None
    responsiveForm: bool = False
    step: str = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Field':
        """Cria uma instância Field a partir de um dicionário, preenchendo campos faltantes com valores padrão"""
        # Filtra apenas os campos que existem na dataclass
        field_names = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in field_names}
        
        return cls(**filtered_data)
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte a instância para dicionário"""
        return {
            'name': self.name,
            'label': self.label,
            'type': self.type,
            'required': self.required,
            'placeholder': self.placeholder,
            'options': self.options,
            'checked': self.checked,
            'dataSource': self.dataSource,
            'searchable': self.searchable,
            'tab': self.tab,
            'regex': self.regex,
            'maxLength': self.maxLength,
            'regexCondition': self.regexCondition,
            'responsiveForm': self.responsiveForm,
        }

# Função para processar JSON e padronizar
def padronizar_json_para_field(json_data: str) -> Field:
    """Converte JSON string para objeto Field padronizado"""
    data = json.loads(json_data) if isinstance(json_data, str) else json_data
    return Field.from_dict(data)


def padronizar_lista_fields(json_list: List[Dict]) -> List[Field]:
    """Converte lista de dicts para lista de Fields padronizados"""
    return [Field.from_dict(item) for item in json_list]

def onlySys(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.role == 'sysadmin':
            return f(*args, **kwargs)
        else:
            return redirect(url_for('login'))
        
    return wrapper


@login_manager.user_loader
def load_user(user_id):
    success, user = database.getUser(user_id)
    if success == False:
        return None
    return user


def setup_error_handlers(app):
    """Configura todos os error handlers da aplicação"""
    
    @app.errorhandler(Exception)
    def handleException(e):
        """Handler para todas as exceções não tratadas"""
        
        # Obtém informações detalhadas do traceback
        excType, excValue, excTraceback = sys.exc_info()
        
        # Extrai informações do último frame (onde ocorreu o erro)
        if excTraceback:
            lastFrame = traceback.extract_tb(excTraceback)[-1]
            errorFile = lastFrame.filename
            errorLine = lastFrame.lineno
            errorFunction = lastFrame.name
            errorCode = lastFrame.line if lastFrame.line else "N/A"
        else:
            errorFile = "Desconhecido"
            errorLine = "N/A"
            errorFunction = "N/A"
            errorCode = "N/A"
        
        # Formata o traceback completo como string
        fullTraceback = ''.join(traceback.format_exception(excType, excValue, excTraceback))
        
        # Log completo do erro com informações extras
        app.logger.error(f'Exceção não tratada: {e}')
        app.logger.error(f'Arquivo: {errorFile}')
        app.logger.error(f'Linha: {errorLine}')
        app.logger.error(f'Função: {errorFunction}')
        app.logger.error(f'Código: {errorCode}')
        app.logger.error(f'Traceback completo:\n{fullTraceback}')
        
        # Em desenvolvimento, inclui detalhes do erro
        errorDetails = None
        debugInfo = None
        
        if app.config.get('DEBUG') or current_user.role in ['sysadmin', 'super']:
            errorDetails = str(e)
            debugInfo = {
                'file': errorFile.split('/')[-1] if errorFile else 'N/A',  # Apenas nome do arquivo
                'line': errorLine,
                'function': errorFunction,
                'code': errorCode,
                'fullPath': errorFile,
                'traceback': fullTraceback
            }
        
        # Verifica se é uma exceção HTTP
        if hasattr(e, 'code'):
            return render_template('error/generic.html',
                                errorCode=e.code,
                                errorMessage=getattr(e, 'description', 'Erro desconhecido'),
                                errorDetails=errorDetails,
                                debugInfo=debugInfo), e.code
        
        # Para exceções não-HTTP, retorna erro 500
        return render_template('error/generic.html',
                            errorCode=500,
                            erroMessage="Ocorreu um erro inesperado. Nossa equipe foi notificada.",
                            errorDetails=errorDetails,
                            debugInfo=debugInfo), 500


@app.route('/', methods=['GET', 'POST'])
def index():
        if current_user.is_authenticated:
            match request.method:
                case 'GET':
                    next_page = request.args.get('next')
                    if not next_page or url_parse(next_page).netloc != '':
                        headers = ITEM_CONFIGS['headers']['sysadmin']['users'] if current_user.role == 'sysadmin' else ITEM_CONFIGS['headers']['user']['passwords']
                        success, statistcs = database.getDashboardInfo(headers=headers, userId=current_user.id)
                        if not success:
                            return redirect(url_for('internalError'))
                        if current_user.role == 'sysadmin':
                            users = database.getUsers(userId=current_user.id, method='get', itemType='user')
                            if not users:
                                return redirect(url_for('internalError'))   
                            else:
                                return render_template('index.html', deashboardInfo=statistcs, users=users)
                        else:
                            passwords = database.getPasswords(userId=current_user.id)
                            if not passwords:
                                return redirect(url_for('internalError'))
                            else:
                                return render_template('index.html', deashboardInfo=statistcs, passwords=passwords)
                    else:
                        return redirect(next_page)
                case 'POST':
                    ... #TODO: POST logic
                case _:
                    return redirect(url_for('notFound'))
        else:
            match request.method:
                case 'GET':
                    return render_template('login.html')
                case 'POST':
                    login = request.form.get('login')
                    password = request.form.get('password')
                    
                    if login and password:
                        success, user = database.validUser(login, password)
                        
                        if success:
                            login_user(user)
                            flash('Login successful', 'success')
                            return redirect(url_for('index'))
                        else:
                            flash(user, 'danger')
                            return redirect(url_for('login'))
                    else:
                        flash('Login failed', 'danger')
                        return redirect(url_for('login'))
                case _:
                    return redirect(url_for('notFound'))


@app.route('/login/', methods=['GET', 'POST'])
def login():
    match request.method:
        case 'GET':
            return render_template('login.html')
        case 'POST':
            login_form = request.form
            
            if login_form.get('login') and login_form.get('password'):
                success, user = database.validUser(login_form.get('login'), login_form.get('password'))
                
                if success:
                    login_user(user)
                    flash('Sussesful login', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Login failed', 'danger')
                    return redirect(url_for('login'))
            else:
                flash('Login failed', 'danger')
                return redirect(url_for('login'))
        case _:
            return redirect(url_for('notFound'))
        

@app.route('/logout/', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/forgotPassword/', methods=['GET', 'POST'])
def forgotPassword():
    match request.method:
        case 'GET':
            return render_template('forgotPassword.html')
        case 'POST':
            login = request.form.get('login')
            
            if login:
                success, user = database.findUserLogin(login)
                
                if success == False:
                    flash(user, 'danger')
                    return redirect(url_for('forgotPassword'))
                else:
                    return redirect(url_for('forgotPassword'))
            else:
                flash('Login is required.', 'danger')
                return redirect(url_for('forgotPassword'))


@app.route('/signup/', methods=['GET', 'POST'])
def signup():
    match request.method:
        case 'GET':
            return render_template('signup.html')
        case 'POST':
            login = request.form.get('login')
            password = request.form.get('password')
            passwordConfirm = request.form.get('passwordConfirm')
            
            if None not in [login, password, passwordConfirm]:
                if password == passwordConfirm:
                    success, user = database.createUser(login=login, password=password)
                    
                    if success == False:
                        flash(user, 'danger')
                        return redirect(url_for('signup'))
                    else:
                        login_user(user, remember=True)
                        flash(user, 'success')
                        return redirect(url_for('index'))
                else:
                    flash('Passwords are not the same.', 'danger')
                    return redirect(url_for('signup'))
                

@app.route('/account/', methods=['GET', 'POST'])
@login_required
def account():
    match request.method:
        case 'GET':
            user, success = database.getUserById(current_user.id)
            if not success:
                return redirect(url_for('internalError'))
            
            return render_template('account.html', user=user)
        case 'POST':
            login = request.form.get('login')
            password = request.form.get('password')
            passwordConfirm = request.form.get('passwordConfirm')
            profilePic = request.form.get('profilePic')
            
            if password == passwordConfirm:
                success, user = database.updateUser(current_user.id, login=login, password=password, profilePic=profilePic)
                
                if success == False:
                    flash(user, 'danger')
                    return redirect(url_for('account'))
                else:
                    flash(user, 'success')
                    return redirect(url_for('index'))
            else:
                flash('Passwords are not the same.', 'danger')
                return redirect(url_for('account'))
            
@app.route('/home/', methods=['GET', 'POST'])
@login_required
def home():
    match request.method:
        case 'GET':
            return render_template('index.html', tempo='20')
        case 'POST':
            if current_user.role == "sysadmin":
                pass
            else:
                success, passwords = database.getPasswords(userId=current_user.id)
                if success == False:
                    flash(passwords, 'danger')
                    return redirect(render_template('index.html'))
                elif success == 2:
                    return redirect(url_for('internalError', error=passwords))
                return render_template('index.html', passwords=passwords)
        case _:
            return redirect(url_for('notFound'))
        

@app.route('/stats/', methods=['GET', 'POST'])
@login_required
def stats():
    match request.method:
        case 'GET':
            success, stats = database.getStats(userId=current_user.id)
            if success == False:
                flash(stats, 'danger')
                return redirect(render_template('stats.html'))
            elif success == 2:
                return redirect(url_for('internalError', error=stats))
            return render_template('stats.html', stats=stats)
        case 'POST':
            return render_template('stats.html')
        

@app.route('/moreInfo', methods=['GET', 'DELETE'])
@login_required
def moreInfo():
    match request.method:
        case 'GET':
            passwordId = request.args.get('passwordId')
            success, passwordInfo = database.getPasswordLogs(passwordId=passwordId, userId=current_user.id, itemType='password')
            if not success:
                return redirect(url_for('internalError'))
            
            return render_template('moreInfo.html', passwordInfo=passwordInfo)
        case 'DELETE':
            logs = list(request.form.getlist('logs'))
            
            success, msg = database.deletePasswordLogs(logs=logs, userId=current_user.id, itemType='password')
            if not success:
                return redirect(url_for('internalError'))
            
            jsonify({'success': True, 'msg': msg})
        case _:
            return redirect(url_for('notFound'))

        
def generateForm(itemType: str, customForm: str | None = None, hidden: bool = False, hiddenValue: str = '', hiddenId: str = '', customTitle: str | None = None, products: list = [], rpis: list = [], integrations: list = [], stores: list = [], account: bool = False, user: User | None = None, hasTitle: bool = True, title: str | None = None) -> str:
    config = ITEM_CONFIGS[itemType]
    final = ''
    hasImg = False
    if customForm:
        config = customForm[itemType]


    def getUserValue(fieldName: str, account: bool = False, user: User | None = None) -> str:
        """Retorna o valor do campo do usuário se account for True"""
        if not account or not user:
            return ""
        
        # Mapear nomes de campos para diferentes possibilidades
        field_mappings = {
            'product': ['productId', 'selectedProduct', 'product_id'],
            'store': ['storeId', 'selectedStore', 'store_id'],
            'rpi': ['rpiId', 'selectedRpi', 'rpi_id'],
            # 'integration': ['integrationId', 'selectedIntegration', 'integration_id'] TODO: FEATURE CUSTOM INTEGRATION
        }
        
        # Primeiro tenta o nome direto do campo
        if fieldName in user:
            return str(user[fieldName])
        
        # Depois tenta os mapeamentos
        for field_type, possible_fields in field_mappings.items():
            if fieldName.lower().startswith(field_type):
                for possible_field in possible_fields:
                    if possible_field in user and user[possible_field]:
                        return str(user[possible_field])
        
        return ""
    
    
    def genCheckbox(field: Field, account: bool = False, user: User | None = None):
        # Para checkbox, verifica se o valor do usuário é True/truthy
        isChecked = field.checked
        if account and user and field.name in user:
            isChecked = bool(user[field.name])
        
        checkbox = render_template('components/_switch.html', 
                                 required=field.required,
                                 label=field.label, 
                                 id=field.name, 
                                 checked=isChecked)
        return checkbox
    
    
    def genClientIdInput():
        return """<input type="hidden" name="client_id" id="clientIdInput">
                <script>document.getElementById('clientIdInput').value = window.notificationSystem.getClientId();</script>"""
    

    def genPassword(field: Field, account: bool = False, user: User | None = None):
        # Password nunca deve ser preenchido automaticamente
        return render_template('components/_passwordInput.html', 
                             placeholder=field.placeholder, 
                             to=field.name, 
                             autocomplete='off',
                             required=field.required)
    
    
    def genSelect(field: Field, account: bool = False, user: User | None = None):
        match field.options:
            case 'integrations':
                field.options = integrations
                for option in field.options:
                    option['value'] = option['integrationId']
            case 'stores':
                field.options = stores
                for option in field.options:
                    option['value'] = option['storeId']
                    if 'cardType' not in option:
                        option['cardType'] = 'prepaid'
            case 'rpis':
                field.options = rpis
                for option in field.options:
                    option['value'] = option['rpiId']

        selectedValue = getUserValue(field.name, account, user)
        
        options = ''
        for opt in field.options:
            selected = 'selected' if str(opt['value']) == selectedValue else ''
            
            dataAttributes = ''
            if 'cardType' in opt:
                dataAttributes += f' data-payment-type="{opt["cardType"]}"'
            if 'storeId' in opt:
                dataAttributes += f' data-store-id="{opt["storeId"]}"'
            
            options += f'<option value="{opt["value"]}" {selected}{dataAttributes}>{opt["name"]}</option>'
        
        template = f'''
            <div class="form-group my-3 select-container">
                <label for="{field.name}">{field.label} {"*" if field.required else ""}</label>
                <select class="form-control form-input select-input" id="{field.name}" name="{field.name}" {"required" if field.required else ""}>
                    <option value="" disabled="" {"selected" if not selectedValue else ""}>Selecione uma opção...</option>
                    {options}
                </select>
            </div>
        '''
        return template

    
    def genText(field: Field, account: bool = False, user: User | None = None):
        fieldValue = getUserValue(field.name, account, user)
        
        if field.regex:
            text = render_template('components/_regexText.html',
                                 field=field, 
                                 value=fieldValue)
        else:
            text = f'''
                <div class="form-group my-3">
                    <label for="{field.name}">{field.label} {"*" if field.required else ""}</label>
                    <input type="text" class="form-control form-input" id="{field.name}" name="{field.name}" 
                           placeholder="{field.placeholder}" value="{fieldValue}" 
                           {"required" if field.required else ""} autocomplete="off">
                </div>
            '''
        return text
    
    def genUrl(field: Field, account: bool = False, user: User | None = None):
        fieldValue = getUserValue(field.name, account, user)
        
        url = f'''
            <div class="form-group my-3">
                <label for="{field.name}">{field.label} {"*" if field.required else ""}</label>
                <input type="url" class="form-control form-input" id="{field.name}" name="{field.name}" 
                       placeholder="{field.placeholder}" value="{fieldValue}" 
                       {"required" if field.required else ""}>
            </div>
        '''
        return url
    
    def genTitle(title: str):
        if not customTitle:
            return f'''
                <h2 class="text-center mb-4 fw-bold">{ title }</h2>
            '''
        else:
            return f'''
                <h2 class="text-center mb-4 fw-bold">{ customTitle }</h2>
            '''
    
    def genTabs(tabs: list[dict]):
        tabsHtml = ''
        for tab in tabs:
            tabsHtml += f'''
                <li class="nav-item" role="presentation">
                    <button class="nav-link {'active' if tab['active'] else ''}" 
                            onclick="openTab(event, '{tab['name']}')">
                        {tab['name']}
                    </button>
                </li>
            '''
        return f'''
            <ul class="nav nav-tabs mb-4" id="adminTabs" role="tablist">
                {tabsHtml}
            </ul>
        '''
    
    def genForm(post: str, form):
        if post.startswith('url_for('):
            post = eval(post)
            
        header = f'''
            <form id="form" action="{post}" method="POST" enctype={"application/x-www-form-urlencoded" if not hasImg else "multipart/form-data"} autocomplete="off">
        '''
        footer = f'''
                <div class="d-flex flex-wrap gap-2 mt-4 form-btns">
                    <button type="submit" class="btn btn-primary">{'Adicionar' if not account else 'Salvar'} {itemType.title()}</button>
                    <a href="{url_for('home')}" class="btn btn-secondary">Cancelar</a>
                    {f'<a href="{url_for("resetPassword", user_id=user['user_id'])}" class="btn btn-danger">Resetar Senha</a>' if ( user and user.get('userType') in ['User', 'Store']) and (current_user.role in ['sysAdmin', 'super']) and account else ''}
                </div>
            </form>
        '''
        
        form = f"""
            <div class="form-grid">
                {form}
            </div>
        
        """
        
        return str(header+form+footer)
    
    def genImageInput(field: Field, account: bool = False, user: User | None = None):
        fieldValue = getUserValue(field.name, account, user)
        
        imageInput = render_template('components/_imageInput.html', 
                                    field=field, 
                                    value=fieldValue)
        return imageInput
    
    def genNumberInput(field: Field, account: bool = False, user: User | None = None):
        fieldValue = getUserValue(field.name, account, user)
        
        if field.regex:
            numberInput = render_template('components/_regexText.html', 
                                        field=field, 
                                        value=fieldValue)
        else:
            numberInput = f'''
                <div class="form-group my-3">
                    <label for="{field.name}">{field.label} {"*" if field.required else ""}</label>
                    <input type="number" class="form-control" id="{field.name}" name="{field.name}" 
                           placeholder="{field.placeholder}" step="{field.step if field.step else ''}" value="{fieldValue}" required>
                </div>
            '''
        return numberInput
    
    def genHidden(name: str, value: str):
        return f"""
                <div class="form-group my-3">
                    <input type="hidden" name="{name}" value="{value}">
                </div>
                """
    
    def genResponsiveForm(field: Field, account: bool = False, user: User | None = None):
        fieldValue = getUserValue(field.name, account, user)
        resp = render_template('components/_responsiveForm.html',
                             field=field,
                             value=fieldValue,
                             account=account,
                             user=user)
        return resp
       
    if hasTitle:
        title = genTitle(config['title'])
        final += title
    
    if config['tabs']:
        tabs = genTabs(config['tabs'])
        final += tabs
    
    form = ''
    for field in config['fields']:
        field = Field.from_dict(field)
        match field.type:
            case 'checkbox':
                if field.responsiveForm:
                    ret = genResponsiveForm(field, account, user)
                else:
                    ret = genCheckbox(field, account, user)
                form += ret
            case 'password':
                ret = genPassword(field, account, user)
                form += ret
            case 'select':
                if field.responsiveForm:
                    ret = genResponsiveForm(field, account, user)
                else:
                    ret = genSelect(field, account, user)
                form += ret
            case 'text':
                ret = genText(field, account, user)
                form += ret
            case 'url':
                ret = genUrl(field, account, user)
                form += ret
            case 'number':
                ret = genNumberInput(field, account, user)
                form += ret
            case 'image':
                hasImg = True
                ret = genImageInput(field, account, user)
                form += ret
            case _:
                raise ValueError(f'Tipo de campo desconhecido: {field.type}')
    
    if hidden:
        form += genHidden(hiddenId, hiddenValue)
            
    final += genForm(post=config['postUrl'], form=form)
    
    return final


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)