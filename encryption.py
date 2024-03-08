import base64
import hashlib
import requests
from Crypto import Random
from Crypto.Cipher import AES
import json
from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
import datetime

class event(BaseModel):
    encrypt: Optional[str] = None
    doctype: Optional[str] = None
    name: Optional[str] = None
    dob: Optional[str] = None
    pan: Optional[str] = None
    decrypt_key: Optional[str] = None
    
class en(BaseModel):
    encrypt: Optional[str] = None
    doctype: Optional[str] = None
    name: Optional[str] = None
    dob: Optional[str] = None
    pan: Optional[str] = None
    
class de(BaseModel):
    encrypt: Optional[str] = None
    decrypt_key: Optional[str] = None
    
      
cype = FastAPI()

paw = 'HbT2FyC8mUNkdQk'

# Create a logger
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.INFO)
# # Create a file handler and add it to the logger
# handler = logging.FileHandler('app.log')
# handler.setLevel(logging.DEBUG)
# logger.addHandler(handler)

class AESCiper(object):
    
    def __init__(self,key):
        self.bs =16
        self.key = hashlib.sha512(key.encode("utf8")).hexdigest()[:16].encode("utf8")


    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        raw = raw.encode('utf8')
        encrypyted= cipher.encrypt(raw)
        
        return base64.b64encode(encrypyted)+":".encode("utf8")+base64.b64encode(iv)
    
    def decrypt(self, enc):
        enc = str(enc)
        enc, iv = enc.split(":")
        enc = base64.b64decode(enc)
        iv = base64.b64decode(iv)
        cipher= AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc)).decode('utf-8')
    
    def _pad(self, s):
        print(type(s))
        a = s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)
        print(f"pad****: {type(a)}")
        print(a)
        return a
        
    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
    

class verification:
    def __init__(self, password):
        self.cipher = AESCiper(password)
        
    def encryptData(self, payload):
        payload = json.dumps(payload)
        encrypted_payload = self.cipher.encrypt(payload)
        
        return encrypted_payload

    def decryptData(self, enc):
        
        decrypted_payload = self.cipher.decrypt(enc)
        return decrypted_payload


@cype.post('/')
async def handel(ev: event):
        password= paw
        print(event)
        if ev.encrypt  =="ENCRYPT":
            doctype = ev.doctype
            name = ev.name
            dob = ev.dob
            pan = ev.pan
            payload = {"doctype": doctype,"name": name,"dob": dob, "pan": pan}
            v = verification(password)
            key = v.encryptData(payload)
            print(key)
            return {
            'statCode' : 200,
            'result' :f"{key}"
        }
           
        elif ev.event == "DECRYPT":
            payload = ev.decrypt_key
            d =verification(password)
            key = d.decryptData(payload)
            print(key)
           
        return {
            'statCode' : 200,
            'result' :f"{key}"
        }

@cype.post('/api/ENCRYPT')
async def enc(ev:en):
    password= paw
    print(ev)
    doctype = ev.doctype
    name = ev.name
    dob = ev.dob
    pan = ev.pan
    if name == 'nil':
        name = None
    if dob == 'nil':
        dob = None
    payload = {"doctype": doctype,"name": name,"dob": dob, "pan": pan}
    current_time = datetime.datetime.now()
    print(f"time: {current_time}:  {payload}")
    v = verification(password)
    key = v.encryptData(payload)
    print(key.decode('utf8'))
    status= {
            'statCode' : 200,
            'result' : key.decode('utf8')
        }
    print(status)
    return status

@cype.post('/api/DECRYPT')
def dec(ev:de):
    # old pass= "VIbzI@xwhYv2Kkx"
    password= paw
    payload = ev.decrypt_key
    d =verification(password)
    key = d.decryptData(payload)
    print(key)
    
    return {
            'statCode' : 200,
            'result' : key
        }

payload ={"doctype": "aadhaar","name": "Rohit Kamraj Veer","dob": "null","pan": "BCRpv2251E"}  
v = verification(password=paw)
key = v.encryptData(payload)
# print(key)


payload = "Z35wxzTVCMWicoP0ss66xjok14OjO7kzj+5qc0NYDDqdf2GX+uvXXedRBjf8LCYpyjK7w0tgd3GZNHV99jojMN0G0laAFw0m5Jt5DKzq5JIzT0uIxiVpptwLi77Ent20:B8TT9brP2o1JeHtIwqM7PA=="
d =verification(password=paw)
key = d.decryptData(payload)
# print(key)

# Log whatever you print on console
# logger.debug("Logging whatever is printed to console...")