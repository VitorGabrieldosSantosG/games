import random
from locust import HttpUser, task, between
import time

class PlataformaUser(HttpUser):
    # Simula o tempo que um usuário real leva entre uma ação e outra
    wait_time = between(1, 2)
    token = ""

    def on_start(self):
        """Ocorre assim que o usuário virtual entra no sistema"""
        self.fluxo_autenticacao()

    def fluxo_autenticacao(self):
        user_id = random.randint(1000, 99999)
        username = f"joao_{user_id}"
        
        # Dados para o Registro (conforme seu DTO)
        payload_reg = {
            "nomeUsuario": username, 
            "email": f"joao_{user_id}@teste.com",
            "senha": "123", 
            "nomeCompleto": f"Joao Rafael {user_id}"
        }

        # 1. Registro
        self.client.post("/auth/registrar", json=payload_reg)
        
        # 2. Login para pegar o Token JWT
        res = self.client.post("/auth/login", json={"nomeUsuario": username, "senha": "123"})
        
        if res.status_code == 200:
            self.token = res.json().get("token")

    @task
    def testar_plataforma(self):
        """Tarefa principal: Criar (POST) e Ler (GET) plataforma"""
        if not self.token: 
            return
            
        headers = {
            "Authorization": f"Bearer {self.token}", 
            "Content-Type": "application/xml",
            "Accept": "application/xml"
        }
        
        # --- OPERAÇÃO 1: POST (Criação) ---
        nome_p = f"Plataforma_{int(time.time() * 1000)}_{random.randint(1, 999)}"
        xml_data = f"<plataforma><nome>{nome_p}</nome><fabricante>Teste Locust</fabricante></plataforma>"
        
        with self.client.post("/plataformas", data=xml_data, headers=headers, catch_response=True) as res_post:
            if res_post.status_code == 201:
                # --- OPERAÇÃO 2: GET (Leitura) ---
                # Se o POST deu certo, tentamos ler a lista de plataformas
                self.client.get("/plataformas", headers=headers)
                res_post.success()
            else:
                res_post.failure(f"Falha no POST: Status {res_post.status_code}")