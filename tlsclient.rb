require "socket"

def getshex(byte, socket)
  ret = ""
  byte.times do
    ret = ret + sprintf("%02x", socket.getbyte)
  end
  "0x" + ret
end


module TLSConnection

  def self.open(host, socket)
    client_shares =
      [38].pack('n') +
      [36].pack('n') +
      [0x001d].pack('n') +         # group
      [32].pack('n') +  "\x11"*32  # key_exchange<1..2^16-1>

    ext_10 = # supported_groups
      [10].pack('n') +                                   # extension_type
      [4].pack('n') + [2].pack('n') + [0x001d].pack('n') # extension_data
    ext_13 = # signature_algorithms
      [13].pack('n') +                                                       # extension_type
      [8].pack('n') + [6].pack('n') + [0x0401, 0x0804, 0x0403].pack('n n n') # extension_data
    ext_43 = # supported_versions
      [43].pack('n') +                            # extension_type
      [3].pack('n') + "\x02" + [0x0304].pack('n') # extension_data
    ext_51 = # key_share
      [51].pack('n') +  # extension_type
      client_shares     # extension_data

    extensions =
      [ext_10.length + ext_13.length + ext_43.length + ext_51.length].pack('n') +
      ext_10 + ext_13 + ext_43 + ext_51
    
    clienthello =
      [0x0303].pack('n') +            # legacy_version
      "\x00"*32 +                     # random
      "\x00" +                        # legacy_session_id
      [0x0002, 0x1301].pack('n n') +  # cipher_suites (TLS_AES_128_GCM_SHA256)
      [0x01, 0x00].pack('C C') +      # legacy_compression_methods
      extensions                      # extensions
    
    handshake =
      "\x01" +                                 # msg_type
      [0x00, clienthello.length].pack('C n') + # length (uint24)
      clienthello                              # clienthello
    
    record =
      "\x16" +                        # type
      [0x0301].pack('n') +            # legacy_record_version
      [handshake.length].pack('n') +  # length
      handshake                       # fragment

    socket.write(record)
    return true
  end
end

s = TCPSocket.open("example.com", 443)

TLSConnection.open("example.com", s)

puts "type: " + getshex(1, s)
puts "legacy_record_version: " + getshex(2, s)
tmp = getshex(2, s)
puts "length: " + tmp
puts "fragment: " + getshex(tmp.hex, s)

s.close()
