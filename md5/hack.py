# importing the requests library 
import requests 
import hashlib
from bs4 import BeautifulSoup
  
# api-endpoint 
URL = "http://134.122.99.74:31173/"

req = requests.session()
  
r = req.get(url = URL) 

soup = BeautifulSoup(r.text, 'html.parser')
h3 = soup.find_all('h3')[0].encode_contents()

print(h3)
hash = hashlib.md5(h3).hexdigest()
request_data = dict(hash=hash)

print(request_data)

x = req.post(URL, data = request_data)

print(x.text)