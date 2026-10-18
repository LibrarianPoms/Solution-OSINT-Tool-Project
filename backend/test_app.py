import requests
import json

response = requests.post("http://127.0.0.1:5000/api/scan", 
    json={"domain": "example.com"})

print(json.dumps(response.json(), indent=2))