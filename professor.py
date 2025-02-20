import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
import pickle
import hashlib
import shutil


class ServerGUI:
    def __init__(self):
        self.host = '0.0.0.0'
        self.port = 65433
        self.valid_credentials = {
            'alvaro': '123',
            '456': '456'
        }
        
        self.root = tk.Tk()
        self.root.title("Sistema Professor")
        
        # Interface
        self.btn_send = tk.Button(self.root, text="Enviar Prova", command=self.send_exam)
        self.btn_receive = tk.Button(self.root, text="Receber Respostas", command=self.receive_answers)
        self.log = tk.Listbox(self.root, width=80, height=20)
        
        # Layout
        self.btn_send.pack(pady=5)
        self.btn_receive.pack(pady=5)
        self.log.pack(padx=10, pady=10)
        
        self.start_server()


    def start_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        self.log.insert(tk.END, "Servidor iniciado...")
        accept_thread = threading.Thread(target=self.accept_connections, daemon=True)
        accept_thread.start()


    def accept_connections(self):
        while True:
            try:
                client, addr = self.server.accept()
                threading.Thread(target=self.handle_client, args=(client,), daemon=True).start()
            except Exception as e:
                self.log.insert(tk.END, f"Erro na conexão: {str(e)}")


    def handle_client(self, client):
        try:
            credentials = pickle.loads(self.reliable_recv(client))
            username = credentials['username']
            password = credentials['password']
            
            if password != self.valid_credentials.get(username):
                client.send(pickle.dumps({'status': 'error', 'message': 'Credenciais inválidas'}))
                client.close()
                return
                
            client.send(pickle.dumps({'status': 'ok'}))
            self.log.insert(tk.END, f"{username} conectado")
            
            while True:
                data = pickle.loads(self.reliable_recv(client))
                
                if data['action'] == 'download_exam':
                    self.send_file(client, username)
                elif data['action'] == 'upload_answer':
                    self.receive_file(client, username, data)  # Passa os metadados diretamente
                    
        except Exception as e:
            self.log.insert(tk.END, f"Erro: {str(e)}")
            client.close()


    def send_file(self, client, username):
        try:
            file_path = f"provas/{username}.pdf"
            if not os.path.exists(file_path):
                client.send(pickle.dumps({'status': 'error', 'message': 'Arquivo não encontrado'}))
                return
            
            with open(file_path, 'rb') as file:
                file_data = file.read()
            
            file_hash = hashlib.sha256(file_data).hexdigest()
            meta = {'status': 'ok', 'size': len(file_data), 'hash': file_hash}
            client.send(pickle.dumps(meta))
            client.sendall(file_data)
            self.log.insert(tk.END, f"Prova enviada para {username}")
            
        except Exception as e:
            self.log.insert(tk.END, f"Erro no envio: {str(e)}")
            client.send(pickle.dumps({'status': 'error', 'message': str(e)}))


    def receive_file(self, client, username, meta):
        try:
            file_data = b''
            if meta.get('status') != 'ok' or 'size' not in meta or 'hash' not in meta:
                raise Exception("Metadados inválidos ou ausentes")
            
            total_size = meta['size']
            expected_hash = meta['hash']
            
            while len(file_data) < total_size:
                chunk = client.recv(4096)
                if not chunk:
                    break
                file_data += chunk
                
            if hashlib.sha256(file_data).hexdigest() != expected_hash:
                raise Exception("Hash de verificação inválido")
            
            os.makedirs('respostas', exist_ok=True)
            with open(f"respostas/{username}_resposta.pdf", 'wb') as file:
                file.write(file_data)
            
            self.log.insert(tk.END, f"Resposta recebida de {username}")
            client.send(pickle.dumps({'status': 'ok'}))
            
        except Exception as e:
            self.log.insert(tk.END, f"Erro ao receber resposta: {str(e)}")
            client.send(pickle.dumps({'status': 'error', 'message': str(e)}))


    def reliable_recv(self, sock):
        data = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(chunk) < 4096:
                break
        return data


    def send_exam(self):
        file_path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
        if file_path:
            username = simpledialog.askstring("Usuário", "Digite o username do aluno:")
            if username:
                dest_path = f"provas/{username}.pdf"
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                shutil.copy(file_path, dest_path)
                self.log.insert(tk.END, f"Prova carregada para {username}")


    def receive_answers(self):
        answers_dir = "respostas"
        os.makedirs(answers_dir, exist_ok=True)
        self.log.insert(tk.END, "Respostas armazenadas em: " + os.path.abspath(answers_dir))


if __name__ == "__main__":
    ServerGUI().root.mainloop()
