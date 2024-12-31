import requests
import json 

aa = open("ubuntu.json", "r")
bb = json.load(aa)
aa.close()

print(bb.keys())

headers = bb["headers"]
print(headers)
headers["Content-Type"] = "text/plain"
headers["X-Vuls-OS-Family"] = "debian"
allKeys = list(headers.keys())
for key in allKeys:
    replaced = key.replace("_", "-")
    headers[replaced] = headers[key]
a = requests.post("http://localhost:5515/vuls", headers=headers, data=bb["packages"])
print(a.text)