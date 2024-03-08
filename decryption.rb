require 'base64'
require 'digest'
require 'json'
require 'openssl'

class AESCipher
  def initialize(key)
    @key = Digest::SHA512.hexdigest(key.encode('utf-8'))[0, 16].encode('utf-8')
  end

  def encrypt(raw)
    raw = pad(raw)
    iv = OpenSSL::Random.random_bytes(16)
    cipher = OpenSSL::Cipher.new('AES-128-CBC')
    cipher.encrypt
    cipher.key = @key
    cipher.iv = iv

    encrypted = cipher.update(raw) + cipher.final
    encrypted_payload = Base64.strict_encode64(encrypted)
    encrypted_iv = Base64.strict_encode64(iv)

    "#{encrypted_payload}:#{encrypted_iv}"
  end

  def decrypt(enc)
    enc_payload, enc_iv = enc.split(':')
    encrypted_payload = Base64.strict_decode64(enc_payload)
    iv = Base64.strict_decode64(enc_iv)

    cipher = OpenSSL::Cipher.new('AES-128-CBC')
    cipher.decrypt
    cipher.key = @key
    cipher.iv = iv

    decrypted = cipher.update(encrypted_payload) + cipher.final
    unpad(decrypted)
  end

  # private

  # def pad(s)
  #   pad_length = 16 - (s.length % 16)
  #   s + pad_length.chr * pad_length
  # end

  # def unpad(s)
  #   s.sub(/[\x01-\x10]*$/, '')
  # end
end

class Verification
  def initialize(password)
    @cipher = AESCipher.new(password)
  end

  def encrypt_data(payload)
    payload = JSON.generate(payload)
    @cipher.encrypt(payload)
  end

  def decrypt_data(enc)
    @cipher.decrypt(enc)
  end
end

def handle(ev)
  password = 'HbT2FyC8mUNkdQk'
  if ev['encrypt'] == 'ENCRYPT'
    doctype = ev['doctype']
    name = ev['name']
    dob = ev['dob']
    pan = ev['pan']
    payload = { 'doctype' => doctype, 'name' => name, 'dob' => dob, 'pan' => pan }
    v = Verification.new(password)
    key = v.encrypt_data(payload)
    { 'statCode' => 200, 'result' => key }
  elsif ev['encrypt'] == 'DECRYPT'
    payload = ev['decrypt_key']
    d = Verification.new(password)
    key = d.decrypt_data(payload)
    { 'statCode' => 200, 'result' => key }
  else
    { 'statCode' => 400, 'error' => 'Invalid operation' }
  end
end

def encrypt(ev)
  password = 'HbT2FyC8mUNkdQk'
  doctype = ev['doctype']
  name = ev['name']
  dob = ev['dob']
  pan = ev['pan']
  name = nil if name == 'nil'
  dob = nil if dob == 'nil'
  payload = { 'doctype' => doctype, 'name' => name, 'dob' => dob, 'pan' => pan }
  v = Verification.new(password)
  key = v.encrypt_data(payload)
  { 'statCode' => 200, 'result' => key }
end

def decrypt(ev)
  password = 'HbT2FyC8mUNkdQk'
  payload = ev['decrypt_key']
  d = Verification.new(password)
  key = d.decrypt_data(payload)
  { 'statCode' => 200, 'result' => key }
end

# Testing the encryption and decryption

# payload = { 'doctype' => 'aadhaar', 'name' => 'Rohit Kamraj Veer', 'dob' => 'null', 'pan' => 'BCRpv2251E' }
# v = Verification.new('HbT2FyC8mUNkdQk')
# key = v.encrypt_data(payload)
# puts key

# decrypted_payload = v.decrypt_data(key)
# puts decrypted_payload

# Example usage:

ev = { 'encrypt' => 'ENCRYPT', 'doctype' => 'aadhaar', 'name' => 'Rohit Kamraj Veer', 'dob' => 'null', 'pan' => 'BCRpv2251E' }
result = handle(ev)
puts result

encrypted_ev = { 'encrypt' => 'ENCRYPT', 'doctype' => 'aadhaar', 'name' => 'Rohit Kamraj Veer', 'dob' => 'null', 'pan' => 'BCRpv2251E' }
encrypted_result = encrypt(encrypted_ev)
puts encrypted_result
# key = "LVm/s0UopF+v4q82QEMLuOG3qdqqDIajpPuA5urW9XV07fDCVI7+JNnY2VI92nOkal5tNHV9eOde8XzPiLLNNBwJ3X1kWHSopc9D9xx62hQtBLZCfyCahgQGnGchdlf+:hL8L1YDL7OAlgf8UEO4fNA=="
# decrypted_ev = { 'encrypt' => 'DECRYPT', 'decrypt_key' => key }
# decrypted_result = decrypt(decrypted_ev)
# puts decrypted_result
