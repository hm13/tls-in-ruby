

require 'openssl'

key = "key"
data = "message-to-be-authenticated"
mac = OpenSSL::HMAC.hexdigest("SHA256", key, data)
#=> "cddb0db23f469c8bf072b21fd837149bd6ace9ab771cceef14c9e517cc93282e"

def hmac_hash_binary(key, data)
  [OpenSSL::HMAC.hexdigest("SHA256", key, data)].pack("H*")
end
