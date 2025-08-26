from flask import Blueprint, request, jsonify, Response
from collections import defaultdict
from datetime import datetime

import json, time, threading, queue

# Blueprint para as notificações
notifications_bp = Blueprint('notifications', __name__)

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
        # Coleta conexões em uma lista separada para evitar modificação durante iteração
        connections_to_process = []
        
        with self.lock:
            if client_id in self.connections:
                connections_to_process = self.connections[client_id].copy()
        
        # Processa conexões fora do lock para evitar deadlock
        dead_connections = []
        for connection in connections_to_process:
            try:
                # Timeout para evitar travamento
                connection.put(notification_data, timeout=0.1)
            except queue.Full:
                print(f"⚠️  Queue cheia para conexão {client_id}")
                dead_connections.append(connection)
            except Exception as e:
                print(f"❌ Erro ao enviar para {client_id}: {e}")
                dead_connections.append(connection)
        
        # Remove conexões mortas
        for dead_conn in dead_connections:
            self.remove_connection(client_id, dead_conn)
    
    def broadcast(self, notification_data):
        """Envia notificação para todos os clientes conectados"""
        # Coleta todas as conexões em uma estrutura separada
        all_connections = []
        
        with self.lock:
            for client_id, connections in self.connections.items():
                for connection in connections:
                    all_connections.append((client_id, connection))
        
        # Processa conexões fora do lock
        dead_connections = []
        for client_id, connection in all_connections:
            try:
                connection.put(notification_data, timeout=0.1)
            except queue.Full:
                print(f"⚠️  Queue cheia para conexão {client_id}")
                dead_connections.append((client_id, connection))
            except Exception as e:
                print(f"❌ Erro ao enviar para {client_id}: {e}")
                dead_connections.append((client_id, connection))
        
        # Remove conexões mortas
        for client_id, dead_conn in dead_connections:
            self.remove_connection(client_id, dead_conn)

# Instância global do gerenciador
notification_manager = NotificationManager()

class SSEConnection:
    def __init__(self, client_id):
        self.client_id = client_id
        # Usar Queue com tamanho limitado para evitar acúmulo excessivo
        self.queue = queue.Queue(maxsize=100)
        self.is_alive = True
        self.last_ping = time.time()
    
    def put(self, data, timeout=None):
        """Adiciona dados à queue com timeout"""
        if self.is_alive:
            if timeout is not None:
                self.queue.put(data, timeout=timeout)
            else:
                self.queue.put(data, block=False)  # Non-blocking por padrão
    
    def get_messages(self):
        """Recupera todas as mensagens disponíveis"""
        messages = []
        try:
            while True:
                message = self.queue.get_nowait()
                messages.append(message)
        except queue.Empty:
            pass
        
        self.last_ping = time.time()
        return messages
    
    def close(self):
        """Fecha a conexão e limpa a queue"""
        self.is_alive = False
        # Limpa a queue para liberar memória
        try:
            while True:
                self.queue.get_nowait()
        except queue.Empty:
            pass

def format_sse_message(data):
    """Formata mensagem no padrão SSE"""
    return f"data: {json.dumps(data)}\n\n"

@notifications_bp.route('/notifications/<client_id>')
def stream_notifications(client_id):
    print(f"🔌 Nova conexão SSE para: {client_id}")
    
    def event_stream():
        connection = SSEConnection(client_id)
        notification_manager.add_connection(client_id, connection)
        
        try:
            while connection.is_alive:
                messages = connection.get_messages()
                
                for message in messages:
                    data = format_sse_message(message)
                    print(f"📤 Enviando: {message}")
                    yield data
                    # IMPORTANTE: Forçar flush dos dados
                    yield ""  # Linha vazia para flush
                
                # Heartbeat com verificação de timeout
                current_time = time.time()
                if current_time - connection.last_ping > 30:  # 30 segundos timeout
                    print(f"⏰ Timeout para cliente {client_id}")
                    break
                
                heartbeat = {
                    'type': 'heartbeat',
                    'timestamp': current_time
                }
                yield format_sse_message(heartbeat)
                yield ""  # Linha vazia para flush
                
                time.sleep(1)
                
        except GeneratorExit:
            print(f"Cliente {client_id} desconectou normalmente")
        except Exception as e:
            print(f"❌ Erro na conexão: {e}")
        finally:
            print(f"🔌 Limpando conexão: {client_id}")
            connection.close()
            notification_manager.remove_connection(client_id, connection)
    
    response = Response(event_stream(), mimetype='text/event-stream')
    
    # Headers críticos para SSE estável
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Connection'] = 'keep-alive'
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Cache-Control'
    
    # MUITO IMPORTANTE: Desabilitar buffering
    response.headers['X-Accel-Buffering'] = 'no'  # Para Nginx
    response.headers['X-Sendfile-Type'] = 'X-Accel-Redirect'  # Para Apache
    
    return response

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
    
    try:
        notification_manager.send_to_client(client_id, notification_data)
    except Exception as e:
        print(f"❌ Erro ao enviar notificação para {client_id}: {e}")

def broadcast_notification_to_all(notification_type='info', title='', message='', duration=5000):
    """Função utilitária para fazer broadcast de notificação"""
    notification_data = {
        'type': notification_type,
        'title': title,
        'message': message,
        'duration': duration,
        'timestamp': datetime.now().isoformat()
    }
    
    try:
        notification_manager.broadcast(notification_data)
    except Exception as e:
        print(f"❌ Erro ao fazer broadcast: {e}")

# Função para limpeza periódica (opcional)
def cleanup_dead_connections():
    """Limpa conexões mortas periodicamente"""
    current_time = time.time()
    
    with notification_manager.lock:
        clients_to_remove = []
        for client_id, connections in notification_manager.connections.items():
            dead_connections = []
            for connection in connections:
                if not connection.is_alive or (current_time - connection.last_ping) > 60:
                    dead_connections.append(connection)
            
            # Remove conexões mortas
            for dead_conn in dead_connections:
                notification_manager.remove_connection(client_id, dead_conn)

# # Exemplos de uso (opcional - pode ser removido)
# @notifications_bp.route('/exemplo_login', methods=['POST'])
# def exemplo_login():
#     """Exemplo de como usar notificações em um login"""
#     data = request.get_json()
#     client_id = data.get('client_id')
#     username = data.get('username')
    
#     # Simula processo de login
#     send_notification_to_user(
#         client_id,
#         'success',
#         'Login realizado!',
#         f'Bem-vindo, {username}!',
#         3000
#     )
    
#     return jsonify({'status': 'success'})

# @notifications_bp.route('/exemplo_operacao', methods=['POST'])
# def exemplo_operacao():
#     """Exemplo de como usar notificações em operações"""
#     data = request.get_json()
#     client_id = data.get('client_id')
#     operacao = data.get('operacao')
    
#     if operacao == 'erro':
#         send_notification_to_user(
#             client_id,
#             'error',
#             'Erro na operação!',
#             'Algo deu errado. Tente novamente.',
#             5000
#         )
#     else:
#         send_notification_to_user(
#             client_id,
#             'success',
#             'Operação concluída!',
#             'A operação foi realizada com sucesso.',
#             3000
#         )
    
#     return jsonify({'status': 'success'})


# @notifications_bp.route('/ntfyExemple', methods=['GET'])
# def ntfyExemple():
#     """Exemplo de como usar notificações em operações"""
#     clientId = request.args.get('client_id')
    
#     send_notification_to_user(
#         clientId,
#         'success',
#         'Notificação de exemplo',
#         'Essa é uma notificação de exemplo.',
#         3000
#     )
    
#     return {'status': 'success'}