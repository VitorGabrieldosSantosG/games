import random
from locust import HttpUser, task, between
import time

class CategoriaLoadTest(HttpUser):
    wait_time = between(1, 2)
    token = ""

    def on_start(self):
        self.fluxo_autenticacao()

    def fluxo_autenticacao(self):
        user_id = random.randint(1000, 99999)
        username = f"rafael_{user_id}"
        
        payload_reg = {
            "nomeUsuario": username, 
            "email": f"rafael_{user_id}@teste.com",
            "senha": "123", 
            "nomeCompleto": f"Rafael Ferreira {user_id}"
        }

        self.client.post("/auth/registrar", json=payload_reg)
        
        res = self.client.post("/auth/login", json={"nomeUsuario": username, "senha": "123"})
        
        if res.status_code == 200:
            self.token = res.json().get("token")

    @task
    def testar_categoria(self):
        if not self.token: 
            return
            
        headers = {
            "Authorization": f"Bearer {self.token}", 
            "Content-Type": "application/xml",
            "Accept": "application/xml"
        }
        
        nome_c = f"Categoria_{int(time.time() * 1000)}_{random.randint(1, 999)}"
        xml_data = f"<Categoria><nome>{nome_c}</nome><descricao>Teste Locust</descricao></Categoria>"
        
        with self.client.post("/categorias", data=xml_data, headers=headers, catch_response=True) as res_post:
            if res_post.status_code == 201:
                self.client.get("/categorias", headers=headers)
                res_post.success()
            else:
                res_post.failure(f"Falha no POST: Status {res_post.status_code}")