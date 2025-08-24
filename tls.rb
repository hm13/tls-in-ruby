require "socket"

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
      else
        head, tail = Util.headtail(message, v)
        if k[/_vl$/] then
          hash[k], tail = Util.headtail(tail, head.to_i(16))
        else
          hash[k] = head
        end
        message = tail
      end
    end
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
            :key_exchange_vl2 => "11"*32
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
      :extensions_vl => 3
    }

    Util.set_hash(serverhello_template, message)
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

class Record
  def Record.readRecord(message)
    record_template = {
      :type => 1,
      :legacy_record_version => 2,
      :length => 2,
      :fragment => :length
    }

    Util.set_hash(record_template, message)
  end
end

class TLS
  def initialize()
    connect()
  end

  def connect()
    @socket = TCPSocket.open("example.com", 443)

    handshake_clienthello = Handshake.createHandshake("client_hello")

    record = {
      :type => "16",
      :legacy_record_version => "0301",
      :length => (Util.to_string(handshake_clienthello).length / 2).to_s(16).rjust(4, "0"),
      :fragment => handshake_clienthello
    }

    @socket.write(Util.to_binary(Util.to_string(record)))


    message = Util.bytes_to_string(@socket.recv(1024))

    record = Record.readRecord(message)
    pp "record:", record

    if record[:type].hex == 22 then # handshake
      handshake = Handshake.readHandshake(record[:fragment])
      pp "handshake:", handshake

      if handshake[:msg_type].hex == 2 then # server_hello
        server_hello = Handshake.readServerHello(handshake[:message])
        pp "server_hello:", server_hello
      else
        raise "Not Implemented"
      end
    else
      raise "Not Implemented"
    end

    # TODO: get connection state
  end

  def write(data)
    # TODO: Encrypt
  end

  def read()
    # TODO: Decrypt
  end
end


tls = TLS.new()
