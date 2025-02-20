import socket
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pickle
import os
import hashlib

class ClientGUI:
    def __init__(self):
        self.server_ip = '192.168.112.13'
        self.port = 65433
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.root = tk.Tk()
        self.root.title("Sistema Aluno")
        
        self.lbl_user = tk.Label(self.root, text="Usuário:")
        self.ent_user = tk.Entry(self.root)
        self.lbl_pass = tk.Label(self.root, text="Senha:")
        self.ent_pass = tk.Entry(self.root, show="*")
        self.btn_connect = tk.Button(self.root, text="Conectar", command=self.connect)
        self.btn_download = tk.Button(self.root, text="Baixar Prova", state=tk.DISABLED, command=self.download_exam)
        self.btn_upload = tk.Button(self.root, text="Enviar Resposta", state=tk.DISABLED, command=self.upload_answer)
        self.status = ttk.Label(self.root, text="Desconectado")
        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, length=200, mode='determinate')

        self.lbl_user.grid(row=0, column=0, padx=5, pady=5)
        self.ent_user.grid(row=0, column=1, padx=5, pady=5)
        self.lbl_pass.grid(row=1, column=0, padx=5, pady=5)
        self.ent_pass.grid(row=1, column=1, padx=5, pady=5)
        self.btn_connect.grid(row=2, column=0, columnspan=2, pady=5)
        self.btn_download.grid(row=3, column=0, padx=5, pady=5)
        self.btn_upload.grid(row=3, column=1, padx=5, pady=5)
        self.status.grid(row=4, column=0, columnspan=2)
        self.progress.grid(row=5, column=0, columnspan=2, pady=5)

    def connect(self):
        try:
            self.sock.connect((self.server_ip, self.port))
            credentials = {
                'username': self.ent_user.get(),
                'password': self.ent_pass.get()
            }
            self.sock.sendall(pickle.dumps(credentials))
            response = pickle.loads(self.reliable_recv())
            
            if response.get('status') != 'ok':
                messagebox.showerror("Erro", response.get('message', 'Credenciais inválidas'))
                return
                
            self.btn_download.config(state=tk.NORMAL)
            self.btn_upload.config(state=tk.NORMAL)
            self.status.config(text="Conectado", foreground="green")
            
        except Exception as e:
            self.status.config(text=f"Erro: {str(e)}", foreground="red")
            messagebox.showerror("Erro", f"Falha na conexão:\n{str(e)}")

    def download_exam(self):
        def download_thread():
            try:
                request = {'action': 'download_exam'}
                self.sock.sendall(pickle.dumps(request))
                meta = pickle.loads(self.reliable_recv())
                
                if meta.get('status') != 'ok':
                    self.root.after(0, lambda: messagebox.showerror("Erro", meta.get('message')))
                    return

                total_size = meta['size']
                received = 0
                file_data = b''
                
                while received < total_size:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        break
                    file_data += chunk
                    received += len(chunk)
                    progress = (received / total_size) * 100
                    self.root.after(0, lambda: self.progress.configure(value=progress))

                if hashlib.sha256(file_data).hexdigest() != meta['hash']:
                    raise ValueError("Arquivo corrompido")

                os.makedirs("provas_aluno", exist_ok=True)
                filename = f"provas_aluno/{self.ent_user.get()}_prova.pdf"
                with open(filename, 'wb') as file:
                    file.write(file_data)

                self.root.after(0, lambda: [
                    self.status.config(text="Prova baixada com sucesso!", foreground="green"),
                    messagebox.showinfo("Sucesso", f"Arquivo salvo em:\n{filename}")
                ])
                
            except Exception as e:
                self.root.after(0, lambda: [
                    self.status.config(text=f"Erro: {str(e)}", foreground="red"),
                    messagebox.showerror("Erro", str(e))
                ])

        threading.Thread(target=download_thread, daemon=True).start()

    def upload_answer(self):
        def upload_thread():
            try:
                file_path = filedialog.askopenfilename(filetypes=[("PDF Files", "*.pdf")])
                if not file_path:
                    return

                with open(file_path, 'rb') as file:
                    file_data = file.read()

                file_hash = hashlib.sha256(file_data).hexdigest()
                request = {
                    'action': 'upload_answer',
                    'size': len(file_data),
                    'hash': file_hash
                }

                self.sock.sendall(pickle.dumps(request))
                self.sock.sendall(file_data)
                
                response = pickle.loads(self.reliable_recv())
                if response.get('status') != 'ok':
                    raise ValueError(response.get('message'))

                self.root.after(0, lambda: [
                    self.status.config(text="Resposta enviada!", foreground="green"),
                    messagebox.showinfo("Sucesso", "Arquivo enviado com sucesso")
                ])
                
            except Exception as e:
                self.root.after(0, lambda: [
                    self.status.config(text=f"Erro: {str(e)}", foreground="red"),
                    messagebox.showerror("Erro", str(e))
                ])

        threading.Thread(target=upload_thread, daemon=True).start()

    def reliable_recv(self, length=4096):
        data = b''
        while True:
            chunk = self.sock.recv(length)
            if not chunk:
                break
            data += chunk
            if len(chunk) < length:
                break
        return data

if __name__ == "__main__":
    ClientGUI().root.mainloop()
