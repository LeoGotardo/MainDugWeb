from flask import Blueprint, request, jsonify, Response
import json
import time
import threading
from collections import defaultdict
from datetime import datetime

# Blueprint para as notificações
notifications_bp = Blueprint('notifications', __name__)

# Armazenamento em memória das conexões SSE
sse_connections = defaultdict(list)
connection_lock = threading.Lock()

class NotificationManager:
    def __init__(self):
        self.connections = defaultdict(list)
        self.lock = threading.Lock()
    
    def add_connection(self, client_id, connection):
        """Adiciona uma nova conexão SSE"""
        with self.lock:
            self.connections[client_id].append(connection)
    
    def remove_connection(self, client_id, connection):
        """Remove uma conexão SSE"""
        with self.lock:
            if client_id in self.connections:
                try:
                    self.connections[client_id].remove(connection)
                    if not self.connections[client_id]:
                        del self.connections[client_id]
                except ValueError:
                    pass
    
    def send_to_client(self, client_id, notification_data):
        """Envia notificação para um cliente específico"""
        with self.lock:
            if client_id in self.connections:
                dead_connections = []
                for connection in self.connections[client_id]:
                    try:
                        connection.put(notification_data)
                    except:
                        dead_connections.append(connection)
                
                # Remove conexões mortas
                for dead_conn in dead_connections:
                    self.remove_connection(client_id, dead_conn)
    
    def broadcast(self, notification_data):
        """Envia notificação para todos os clientes conectados"""
        with self.lock:
            dead_connections = []
            for client_id, connections in self.connections.items():
                for connection in connections:
                    try:
                        connection.put(notification_data)
                    except:
                        dead_connections.append((client_id, connection))
            
            # Remove conexões mortas
            for client_id, dead_conn in dead_connections:
                self.remove_connection(client_id, dead_conn)

# Instância global do gerenciador
notification_manager = NotificationManager()

class SSEConnection:
    def __init__(self, client_id):
        self.client_id = client_id
        self.queue = []
        self.is_alive = True
    
    def put(self, data):
        if self.is_alive:
            self.queue.append(data)
    
    def get_messages(self):
        messages = self.queue[:]
        self.queue.clear()
        return messages
    
    def close(self):
        self.is_alive = False

def format_sse_message(data):
    """Formata mensagem no padrão SSE"""
    return f"data: {json.dumps(data)}\n\n"

@notifications_bp.route('/notifications/<client_id>')
def stream_notifications(client_id):
    """Endpoint SSE para receber notificações"""
    def event_stream():
        connection = SSEConnection(client_id)
        notification_manager.add_connection(client_id, connection)
        
        try:
            while connection.is_alive:
                messages = connection.get_messages()
                for message in messages:
                    yield format_sse_message(message)
                
                # Heartbeat para manter conexão ativa
                if not messages:
                    yield format_sse_message({
                        'type': 'heartbeat',
                        'timestamp': time.time()
                    })
                
                time.sleep(1)
        finally:
            notification_manager.remove_connection(client_id, connection)
    
    response = Response(event_stream(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['Connection'] = 'keep-alive'
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@notifications_bp.route('/send_notification', methods=['POST'])
def send_notification():
    """Endpoint para enviar notificação para um cliente específico"""
    data = request.get_json()
    
    client_id = data.get('client_id')
    notification_data = {
        'type': data.get('type', 'info'),
        'title': data.get('title', ''),
        'message': data.get('message', ''),
        'duration': data.get('duration', 5000),
        'timestamp': datetime.now().isoformat()
    }
    
    notification_manager.send_to_client(client_id, notification_data)
    return jsonify({'status': 'success'})

@notifications_bp.route('/broadcast_notification', methods=['POST'])
def broadcast_notification():
    """Endpoint para fazer broadcast de notificação"""
    data = request.get_json()
    
    notification_data = {
        'type': data.get('type', 'info'),
        'title': data.get('title', ''),
        'message': data.get('message', ''),
        'duration': data.get('duration', 5000),
        'timestamp': datetime.now().isoformat()
    }
    
    notification_manager.broadcast(notification_data)
    return jsonify({'status': 'success'})

# Funções utilitárias para usar em outros módulos
def send_notification_to_user(client_id, notification_type='info', title='', message='', duration=5000):
    """Função utilitária para enviar notificação para um usuário específico"""
    notification_data = {
        'type': notification_type,
        'title': title,
        'message': message,
        'duration': duration,
        'timestamp': datetime.now().isoformat()
    }
    notification_manager.send_to_client(client_id, notification_data)

def broadcast_notification_to_all(notification_type='info', title='', message='', duration=5000):
    """Função utilitária para fazer broadcast de notificação"""
    notification_data = {
        'type': notification_type,
        'title': title,
        'message': message,
        'duration': duration,
        'timestamp': datetime.now().isoformat()
    }
    notification_manager.broadcast(notification_data)

# Exemplos de uso (opcional - pode ser removido)
@notifications_bp.route('/exemplo_login', methods=['POST'])
def exemplo_login():
    """Exemplo de como usar notificações em um login"""
    data = request.get_json()
    client_id = data.get('client_id')
    username = data.get('username')
    
    # Simula processo de login
    send_notification_to_user(
        client_id,
        'success',
        'Login realizado!',
        f'Bem-vindo, {username}!',
        3000
    )
    
    return jsonify({'status': 'success'})

@notifications_bp.route('/exemplo_operacao', methods=['POST'])
def exemplo_operacao():
    """Exemplo de como usar notificações em operações"""
    data = request.get_json()
    client_id = data.get('client_id')
    operacao = data.get('operacao')
    
    if operacao == 'erro':
        send_notification_to_user(
            client_id,
            'error',
            'Erro na operação!',
            'Algo deu errado. Tente novamente.',
            5000
        )
    else:
        send_notification_to_user(
            client_id,
            'success',
            'Operação concluída!',
            'A operação foi realizada com sucesso.',
            3000
        )
    
    return jsonify({'status': 'success'})