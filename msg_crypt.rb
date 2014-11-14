require "openssl"
require 'digest/sha2'
require 'base64'
require 'securerandom'
require 'nokogiri'

module Wecheat
  module Socket
    extend self

    def htonl(v)
      [v].pack('N').unpack('L').first
    end

    def ntohl(v)
      [v].pack('L').unpack('N').first
    end

  end
end

module Wecheat
  module XML
    extend self

    def gen(encrypt, signature, timestamp, nonce)
          """<xml>
      <Encrypt><![CDATA[#{encrypt}]]></Encrypt>
      <MsgSignature><![CDATA[#{signature}]]></MsgSignature>
      <TimeStamp>#{timestamp}</TimeStamp>
      <Nonce><![CDATA[#{nonce}]]></Nonce>
      </xml>"""
    end

  end
end

module Wecheat

  InvalidSignature = Class.new StandardError

  class MsgCrypt

    attr_reader :appid, :key, :alg, :token

    def initialize(appid, token, encoding_aes_key, alg="AES-256-CBC")
      @appid            = appid
      @token            = token
      @alg              = alg
      @key              = Base64.decode64(encoding_aes_key+"=")
    end

    def encrypt_message(text)
      text   = SecureRandom.hex(8) + [Wecheat::Socket.htonl(text.length)].pack("I") + text + appid

      # setup the cipher
      aes = OpenSSL::Cipher::Cipher.new(alg)
      aes.encrypt
      aes.key = key
      aes.iv  = key[0..15]

      # encrypt
      cipher = aes.update(text)
      cipher << aes.final

      # encode 64
      Base64.strict_encode64(cipher)
    end

    def gen_signature(timestamp, nonce, encrypt)
      timestamp = Time.now.to_i.to_s if timestamp.nil?
      array     = [token, timestamp, nonce, encrypt].compact.sort
      Digest::SHA1.hexdigest(array.join)
    end

    def encrypt(message, nonce, timestamp = nil)
      enc = encrypt_message message
      sig = gen_signature timestamp, nonce, enc

      Wecheat::XML.gen enc, sig, timestamp, nonce
    end

    def get_encrypted_text(message, signature, nonce, timestamp)
      doc       = Nokogiri::XML(message)
      encrypt   = doc.at_xpath('//Encrypt').content

      array = [token, timestamp, nonce, encrypt].compact.sort
      dig   = Digest::SHA1.hexdigest(array.join)

      raise Wecheat::InvalidSignature if dig != signature

      Base64.decode64(encrypt)
    end

    def decrypt_message(text64)
      decode_cipher = OpenSSL::Cipher::Cipher.new(alg)
      decode_cipher.decrypt
      decode_cipher.key = key
      decode_cipher.iv  = key[0..15]
      plain = decode_cipher.update(text64)
      plain << decode_cipher.final

      content     = plain[16..plain.length-1]
      x           = content[0..3].unpack("I").first
      xml_len     = Wecheat::Socket.ntohl(x)
      xml_content = content[4..xml_len+3]
      # from_appid  = content[xml_len+4..content.length-1]

      xml_content
    end

    def decrypt(message, signature, nonce, timestamp)
      text = get_encrypted_text message, signature, nonce, timestamp
      decrypt_message text
    end

  end
end
