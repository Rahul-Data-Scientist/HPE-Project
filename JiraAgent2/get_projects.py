import requests
import os

from dotenv import load_dotenv

load_dotenv()

cloud_id = os.getenv(
    "ATLASSIAN_CLOUD_ID"
)

url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/project"

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

projects = response.json()

for project in projects:

    print("\nPROJECT NAME:")
    print(project["name"])

    print("PROJECT KEY:")
    print(project["key"])