require "socket"
require "./x25519"
require "./hkdf"
require "./gcm"

module Util
  def Util.bytes_to_string(bytes)
    ret = ""
    bytes.each_byte do |b|
      ret = ret + sprintf("%02x", b)
    end
    ret
  end

  def Util.to_binary(str)
    [str].pack("H*")
  end

  def Util.to_hex(s)
    s.to_i.to_s(16).rjust(4, "0")
  end

  def Util.to_string(value)
    unless value.is_a?(Hash)
      return value
    end
    
    ret = ""
    
    value.each do |k, v|
      s = to_string(v)
      l = (s.bytesize / 2).to_s(16)
      
      if k[/_vl2$/] then
        ret = ret + l.rjust(4, "0") + s
      elsif k[/_vl1$/] then
        ret = ret + l.rjust(2, "0") + s
      else
        ret = ret + s
      end
    end

    return ret
  end

  def Util.headtail(m, bytes)
    return m[0, bytes * 2], m[(bytes * 2)..]
  end

  def Util.set_hash(hash, message)
    unless hash.is_a?(Hash)
      return
    end

    hash.each do |k, v|
      if v.is_a?(Hash)
        Util.set_hash(v, message)
      elsif v.is_a?(String)
      elsif v.is_a?(Symbol)
        hash[k] = hash[v].to_i(16)
        Util.set_hash(hash, message)
      elsif v.is_a?(Integer)
        head, tail = Util.headtail(message, v)
        if k[/_vl$/] then
          hash[k], tail = Util.headtail(tail, head.to_i(16))
        else
          hash[k] = head
        end
        message = tail
      else
        puts "Not Implemented"
      end
    end

    return hash
  end
end

module Keys
  # constant for testing perpose
  @@private_key="77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
  @@u          ="0900000000000000000000000000000000000000000000000000000000000000"
  @@ealy_secret = ""
  @@shared_secret = ""
  @@master_secret = ""

  def self.private_key
    @@private_key
  end

  def self.handshake_secret
    @@handshake_secret
  end

  def self.master_secret
    @@master_secret
  end

  def self.u
    @@u
  end

  def self.derive_secret(secret, label, messages)
    def self.hkdf_expand_label(secret, label, context, length)
      hkdfLabel = [length].pack("n") + "tls13 " + label + context
      hkdf_expand(secret, hkdfLabel, length)
    end

    def self.transcript_hash(messages)
      if messages == "" then
        ""
      else
        [messages.join].pack("H*")
      end
    end

    hkdf_expand_label(secret, label, transcript_hash(messages), 256/8) # not sure
  end

  def self.set_secrets(server_hello)
    server_hello[:extensions_vl].each do |ext|
      if ext[:type] == 51
        salt = ""
        ikm = ""
        @@early_secret = hkdf_extract(salt, ikm)

        salt = Keys.derive_secret(@@early_secret, "derived", "")
        ikm = [x25519(ext[:data], x25519(Keys.private_key, Keys.u))].pack("H*")
        @@handshake_secret = hkdf_extract(salt, ikm)

        salt = Keys.derive_secret(@@handshake_secret, "derived", "")
        ikm = ""
        @@master_secret = hkdf_extract(salt, ikm)

        p "early_secret = #{@@early_secret.unpack("H*")[0]}"
        p "handshake_secret = #{@@handshake_secret.unpack("H*")[0]}"
        p "master_secret = #{@@master_secret.unpack("H*")[0]}"
      end
    end
  end

  def self.get_write_key(secret)
    hkdf_expand_label(secret, "key", "", 16)
  end

  def self.get_write_iv(secret)
    hkdf_expand_label(secret, "iv", "", 12)
  end
end

module Handshake
  def Handshake.createClientHelloMessage()
    extensions = {
      :key_share => {
        :extension_type => Util.to_hex("51"),
        :extension_data_vl2 => {
          :client_shares_vl2 => {
            :group => "001d",
            :key_exchange_vl2 => x25519(Keys.private_key, Keys.u)
          }
        }
      },
      :supported_versions => {
        :extension_type => Util.to_hex("43"),
        :extension_data_vl2 => {
          :versions_vl1 => "0304"
        }
      },
      :signature_algorithms => {
        :extension_type => Util.to_hex("13"),
        :extension_data_vl2 => {
          :supported_signature_algorithms_vl2 => {
            :rsa_pkcs1_sha256 => "0401",
            :rsa_pss_rsae_sha256 => "0804",
            :ecdsa_secp256r1_sha256 => "0403"
          }
        }
      },
      :supported_groups => {
        :extension_type => Util.to_hex("10"),
        :extension_data_vl2 => {
          :named_group_list_vl2 => {
            :x25519 => "001D"
          }
        }
      }
    }

    clienthello = {
      :legacy_version => "0303",
      :random => "00"*32,
      :legacy_session_id => "00",
      :cipher_suites_vl2 => {
        :tls_aes_128_gcm_sha256 => "1301"
      },
      :legacy_compression_methods_vl1 => "00",
      :extensions_vl2 => extensions
    }

    clienthello
  end

  def Handshake.createHandshake(msg_type)
    case msg_type
    when "client_hello" then
      clienthello = createClientHelloMessage()
      return {
        :msg_type => "01",
        :length => (Util.to_string(clienthello).length / 2).to_s(16).rjust(6, "0"),
        :clienthello => clienthello
      }

    else
      puts "Not implemented"
      exit
    end
  end

  def Handshake.readServerHello(message)
    serverhello_template = {
      :legacy_version => 2,
      :random => 32,
      :legacy_session_id_vl => 1,
      :cipher_suite => 2,
      :legacy_compressiom_method => 1,
      :extensions_vl => 2
    }

    serverhello = Util.set_hash(serverhello_template, message)

    # Read extensions
    tmp = []
    extstr = serverhello[:extensions_vl]
    while extstr.length > 0
      type, tail = Util.headtail(extstr, 2)
      length, tail = Util.headtail(tail, 2)
      data, tail = Util.headtail(tail, length.to_i(16))
      tmp.append({:type => type.to_i(16), :length => length, :data => data})
      extstr = tail
    end
    serverhello[:extensions_vl] = tmp

    serverhello
  end

  def Handshake.readHandshake(fragment)
    handshake_template = {
      :msg_type => 1,
      :length => 3,
      :message => :length
    }

    Util.set_hash(handshake_template, fragment)
  end
end

module Record
  def Record.readRecord(message)
    l = []

    while message != nil do
      record_template = {
        :type => 1,
        :legacy_record_version => 2,
        :length => 2,
        :fragment => :length
      }

      h = Util.set_hash(record_template, message)
      l.append(h)

      head, tail = Util.headtail(message, h[:length].to_i(16) + 1 + 2 + 2)
      message = tail
    end

    l
  end
end

module AEAD
  def AEAD.additional_data(record)
    record[:type] + record[:legacy_record_version] + record[:length]
  end

  # def AEAD.encrypt(write_key, nonce, additional_data, plaintext)
  # end

  def AEAD.decrypt(peer_write_key, nonce, additional_data, aeadencrypted)
    set_key(peer_write_key)
    gcm_ad(nonce.bytes, [[aeadencrypted].pack("H*").bytes, ""], [additional_data].pack("H*").bytes)
  end
end

def nonce(sequence_number, client_write_iv)
  seq = sequence_number.to_s(16)
  zeros = 12*2 - seq.length
  seq = ["0"*zeros + seq].pack("H*").bytes

  iv = client_write_iv.bytes

  ret = []
  12.times do |i|
    ret << (seq[i] ^ iv[i])
  end

  ret.pack("C*")
end

# p nonce(1, ["ffffffffffffffffffffffff"].pack("H*")).unpack("H*")


class TLS
  def initialize()
    connect()
  end

  def connect()
    @socket = TCPSocket.open("example.com", 443)

    handshake_clienthello = Handshake.createHandshake("client_hello")
    transcript = []
    sequence_number = 0

    record = {
      :type => "16",
      :legacy_record_version => "0301",
      :length => (Util.to_string(handshake_clienthello).length / 2).to_s(16).rjust(4, "0"),
      :fragment => handshake_clienthello
    }

    # transcript (clienthello)
    transcript << Util.to_string(handshake_clienthello)

    @socket.write(Util.to_binary(Util.to_string(record)))
    sequence_number = sequence_number + 1

    message = Util.bytes_to_string(@socket.recv(2048))

    record_list = Record.readRecord(message)


    record_list.each do |record|
      p record
      sequence_number = sequence_number + 1

      if record[:type].hex == 22 then # handshake
        handshake = Handshake.readHandshake(record[:fragment])
        if handshake[:msg_type].hex == 2 then # server_hello
          server_hello = Handshake.readServerHello(handshake[:message])

          # transcript (serverhello)
          transcript << Util.to_string(record[:fragment])

          Keys.set_secrets(server_hello)

        else
          puts "Not Implemented handshake"
        end
      elsif record[:type].hex == 23 then
        aeadencrypted = record[:fragment]

        s_hs_traffic = Keys.derive_secret(Keys.handshake_secret, "s hs traffic", transcript)
        c_hs_traffic = Keys.derive_secret(Keys.handshake_secret, "c hs traffic", transcript)
        peer_write_key = Keys.get_write_key(s_hs_traffic).bytes.pack("C*").unpack1("H*")
        nonce = nonce(sequence_number, Keys.get_write_iv(c_hs_traffic))

        res = AEAD.decrypt(peer_write_key, nonce, AEAD.additional_data(record), aeadencrypted)
        p "RESULT = #{res.pack("C*")}"

      else
        puts "Not Implemented record"
      end
    end

  end

  def write(data)
    # TODO: Encrypt
  end

  def read()
    # TODO: Decrypt
  end
end


tls = TLS.new()
