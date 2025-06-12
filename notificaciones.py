from google.oauth2 import service_account
import google.auth.transport.requests
import requests
import json

SERVICE_ACCOUNT_FILE = "firebase/service_account.json"
PROJECT_ID = "empleadosapp-ec63a"

def get_access_token():
    credentials = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE,
        scopes=["https://www.googleapis.com/auth/firebase.messaging"]
    )
    request = google.auth.transport.requests.Request()
    credentials.refresh(request)
    return credentials.token

def enviar_push(token, titulo, cuerpo):
    url = f"https://fcm.googleapis.com/v1/projects/{PROJECT_ID}/messages:send"
    
    headers = {
        "Authorization": f"Bearer {get_access_token()}",
        "Content-Type": "application/json"
    }

    data = {
        "message": {
            "token": token,
            "notification": {
                "title": titulo,
                "body": cuerpo
            }
        }
    }

    response = requests.post(url, headers=headers, json=data)
    return response.status_code, response.json()
