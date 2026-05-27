import requests
import os

from dotenv import load_dotenv

load_dotenv()

url = "https://api.atlassian.com/oauth/token/accessible-resources"

headers = {

    "Authorization":
    f"Bearer {os.getenv('ATLASSIAN_ACCESS_TOKEN')}",

    "Accept":
    "application/json"
}

response = requests.get(

    url,
    headers=headers
)

print(response.json())