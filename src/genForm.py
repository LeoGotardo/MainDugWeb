from database import User, Passwords
from app import ITEM_CONFIGS
from dataclasses import dataclass
from typing import Optional, List, Dict, Any
from flask import render_template
import json

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

class genForm:
    def __init__(self, itemType: str, passwords: list[Passwords] = [], users: list[User] = [], account: bool = False, user: User | None = None, hasValues: bool = False, hasTitle: bool = True) -> None:
        self.itemType = itemType
        self.passwords = passwords
        self.account = account
        self.user = user
        self.hasValues = hasValues
        self.hasTitle = hasTitle
        self.users = users
        
    def getForm(self) -> str:
        config = ITEM_CONFIGS[self.itemType]

        form = f""
        
        for field in config['fields']:
            field: Field = Field.from_dict(field)
            match field.type:
                case 'checkbox':
                    if field.responsiveForm:
                        form += self._genResponsiveForm(field)
                    else:
                        form += self._genCheckbox(field)
                case 'dropdown_card':
                    form += self._genDropdownCard(field)
                case 'password':
                    form += self._genPassword(field)
                case 'select':
                    if field.responsiveForm:
                        form += self._genResponsiveForm(field)
                    else:
                        form += self._genSelect(field)
                case 'text':
                    form += self._genText(field)
                case 'url':
                    form += self._genUrl(field)
                case 'number':
                    form += self._genNumberInput(field)
                case _:
                    raise ValueError(f'Tipo de campo desconhecido: {field.type}')
        
        form = self._compileForm(form, config)
        
        return form
        
    def _genResponsiveForm(form: str, field: Field):
        return render_template('components/_responsiveForm.html', field=field)
    
    def _genCheckbox(form: str, field: Field) -> None:
        return render_template('components/_checkbox.html', field=field)
    
    def _genDropdown(self, field: Field) -> None:
        match field.dataSource:
            case 'users':
                items = self.users
            case 'passwords':
                items = self.passwords
                
        return render_template('components/_dropdown.html', field=field, items=items)
        
    def _genPassword(form: str, field: Field) -> None:
        return render_template('components/_passwordInput.html', field=field)
        
    def _genSelect(self, form: str, field: Field) -> None:
        match field.dataSource:
            case 'users':
                items = self.users
            case 'passwords':
                items = self.passwords
                
        return render_template('components/_select.html', field=field, items=items)
    
    def _genText(form: str, field: Field) -> None:
        return render_template('components/_textInput.html', field=field)
        
    def _genUrl(form: str, field: Field) -> None:
        return render_template('components/_urlInput.html', field=field)
    
    def _genNumberInput(form: str, field: Field) -> None:
        return render_template('components/_numberInput.html', field=field)
    
    def _compileForm(self, form: str, config: dict) -> str:
        header = render_template('components/_formHeader.html', form=form, title=config['title'] if self.hasTitle else None)
        
        footer = render_template('components/_formFooter.html', form=form, postUrl=config['postUrl'] if self.hasValues else None, cancel=bool(config['cancel']))
    
        form = f'{header}{form}{footer}'
        
        return form