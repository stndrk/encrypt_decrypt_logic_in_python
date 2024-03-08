class EncryptionController < ApplicationController
  require 'base64'
  require 'digest'
  require 'json'
  require 'openssl'

  skip_before_action :verify_authenticity_token

  def encrypt
    password = 'HbT2FyC8mUNkdQk'
    payload = {
      doctype: params[:doctype],
      name: params[:name],
      dob: params[:dob],
      pan: params[:pan]
    }

    encrypted_data = encrypt_data(payload, password)

    render json: { status: 'success', encrypted_data: encrypted_data }
  end

  def decrypt
    password = 'HbT2FyC8mUNkdQk'
    encrypted_data = params[:encrypted_data]

    decrypted_data = decrypt_data(encrypted_data, password)

    render json: { status: 'success', decrypted_data: decrypted_data }
  end

  private

  def encrypt_data(payload, password)
    cipher = AESCipher.new(password)
    cipher.encrypt(payload.to_json)
  end

  def decrypt_data(encrypted_data, password)
    cipher = AESCipher.new(password)
    decrypted_payload = cipher.decrypt(encrypted_data)
    JSON.parse(decrypted_payload)
  end
end

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

  private

  def pad(s)
    pad_length = 16 - (s.length % 16)
    s + pad_length.chr * pad_length
  end

  def unpad(s)
    s.sub(/[\x01-\x10]*$/, '')
  end
end
