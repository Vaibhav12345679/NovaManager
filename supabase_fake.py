import requests

API_URL = "https://api.somaedgex-cloud.online"

# ---------- RESPONSE WRAPPER ----------
class _Resp:
    def __init__(self, data):
        self.data = data

# ---------- AUTH ----------
class SessionObj:
    def __init__(self, token):
        self.access_token = token

class ResponseObj:
    def __init__(self, data):
        token = data.get("access_token")
        self.session = SessionObj(token) if token else None
        self.user = data.get("user")
        self.raw = data

class Auth:
    def sign_in_with_password(self, creds):
        res = requests.post(f"{API_URL}/auth/v1/token", json=creds)
        return ResponseObj(res.json())

    def get_user(self, token):
        res = requests.get(
            f"{API_URL}/auth/v1/user",
            headers={"Authorization": f"Bearer {token}"}
        )
        return _Resp(res.json())

# ---------- TABLE ----------
class Table:
    def __init__(self, name, token):
        self.name = name
        self.token = token
        self._filters = []
        self._single = False
        self._data = None
        self._op = None

    def select(self, *_):
        self._op = "select"
        return self

    def insert(self, data):
        self._op = "insert"
        self._data = data
        return self

    def eq(self, key, val):
        self._filters.append((key, val))
        return self

    def maybe_single(self):
        self._single = True
        return self

    def execute(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        # ---- SELECT ----
        if self._op == "select":
            res = requests.get(f"{API_URL}/rest/v1/{self.name}", headers=headers)
            data = res.json()

            # apply filters manually
            for k, v in self._filters:
                data = [r for r in data if str(r.get(k)) == str(v)]

            if self._single:
                return _Resp(data[0] if data else None)

            return _Resp(data)

        # ---- INSERT ----
        elif self._op == "insert":
            res = requests.post(
                f"{API_URL}/rest/v1/{self.name}",
                json=self._data,
                headers=headers
            )
            data = res.json()

            # normalize response
            if isinstance(data, dict):
                return _Resp([data])
            return _Resp(data)

        return _Resp(None)

# ---------- MAIN CLIENT ----------
class SupabaseFake:
    def __init__(self):
        self.auth = Auth()
        self.token = None

    def set_token(self, token):
        self.token = token

    def table(self, name):
        return Table(name, self.token)

# instances (IMPORTANT)

sb = SupabaseFake()
sb_admin = SupabaseFake()
supabase = sb

