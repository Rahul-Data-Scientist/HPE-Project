import requests

# =========================
# ATLASSIAN OAUTH CONFIG
# =========================

CLIENT_ID = ""

CLIENT_SECRET = ""

CODE = ""
# =========================
# TOKEN REQUEST
# =========================

response = requests.post(

    "https://auth.atlassian.com/oauth/token",

    json={

        "grant_type":
        "authorization_code",

        "client_id":
        CLIENT_ID,

        "client_secret":
        CLIENT_SECRET,

        "code":
        CODE,

        "redirect_uri":
        "http://localhost:8080/callback"
    }
)

# =========================
# OUTPUT
# =========================

print("\nTOKEN RESPONSE:\n")

print(response.status_code)
print(response.text)