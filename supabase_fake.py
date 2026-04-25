import requests

API_URL = "https://api.somaedgex-cloud.online/"

# --- helper to mimic supabase response ---
class SessionObj:
    def __init__(self, token):
        self.access_token = token

class ResponseObj:
    def __init__(self, data):
        # mimic res.session.access_token
        token = data.get("access_token")
        self.session = SessionObj(token) if token else None
        self.user = data.get("user")
        self.raw = data  # optional: keep original

class Auth:
    def sign_in_with_password(self, creds):
        res = requests.post(f"{API_URL}/auth/v1/token", json=creds)
        data = res.json()
        return ResponseObj(data)

    def get_user(self, token):
        res = requests.get(
            f"{API_URL}/auth/v1/user",
            headers={"Authorization": f"Bearer {token}"}
        )
        return res.json()


class Table:
    def __init__(self, name, token):
        self.name = name
        self.token = token

    def select(self):
        res = requests.get(
            f"{API_URL}/rest/v1/{self.name}",
            headers={"Authorization": f"Bearer {self.token}"}
        )
        return res.json()

    def insert(self, data):
        res = requests.post(
            f"{API_URL}/rest/v1/{self.name}",
            json=data,
            headers={"Authorization": f"Bearer {self.token}"}
        )
        return res.json()


class SupabaseFake:
    def __init__(self):
        self.auth = Auth()
        self.token = None

    def set_token(self, token):
        self.token = token

    def table(self, name):
        return Table(name, self.token)


supabase = SupabaseFake()
