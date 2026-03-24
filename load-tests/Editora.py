from locust import HttpUser, task, between
from faker import Faker
import random
import xml.etree.ElementTree as ET 

fake = Faker('pt_BR')

class EditoraTeste(HttpUser):
    wait_time = between(1, 3)
    TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJnYW1lciIsInJvbGUiOiJDbGllbnRlIiwiaWF0IjoxNzc0MzEzNTkzLCJleHAiOjE3NzQzOTk5OTN9.jUAx3ta2_j8RYTUB68O72xVzPSHrl8FaB6LdeEpAtJ4" 
    
    def on_start(self):
        self.headers = {
            "Authorization": f"Bearer {self.TOKEN}",
            "Content-Type": "application/xml",
            "Accept": "application/xml"
        }
        
    @task
    def fluxo_criar_e_consultar(self):
        nome_faker = f"{fake.company()} {random.randint(1, 999999)}"
        site_faker = fake.url()
        pais_faker = fake.country()
        
        xml_payload = f"""
        <editora>
            <nome>{nome_faker}</nome>
            <site>{site_faker}</site>
            <pais>{pais_faker}</pais>
        </editora>
        """
        
        with self.client.post("/editoras", data=xml_payload, headers=self.headers, name="1. POST /editoras", catch_response=True) as response_post:
            
            if response_post.status_code == 201:
                response_post.success()

                try:
                    root = ET.fromstring(response_post.text)
                    elemento_id = root.find('id')
                    
                    if elemento_id is not None and elemento_id.text:
                        id_gerado = elemento_id.text
                        
                        # 3. READ (Testando o GET por ID)
                        with self.client.get(f"/editoras/{id_gerado}", headers=self.headers, name="2. GET /editoras/{id}", catch_response=True) as response_get:
                            if response_get.status_code == 200:
                                response_get.success()
                            else:
                                response_get.failure(f"Falha no GET: Status {response_get.status_code}")
                                
                    else:
                        response_post.failure("Sucesso no POST, mas a tag <id> não veio no XML!")
                except ET.ParseError:
                    response_post.failure("Erro ao tentar fazer parse do XML retornado no POST.")
            
            elif response_post.status_code == 500:
                response_post.failure("Erro 500 no POST. Possível conflito de constraint unique no nome.")
            else:
                response_post.failure(f"Erro inesperado no POST: Status {response_post.status_code}")