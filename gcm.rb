require './aes'

ZERO128 = [
  [0x0, 0x0, 0x0, 0x0],
  [0x0, 0x0, 0x0, 0x0],
  [0x0, 0x0, 0x0, 0x0],
  [0x0, 0x0, 0x0, 0x0]
]

# hash subkey
$h

# AES key
$key = [
  [0x2b, 0x28, 0xab, 0x09],
  [0x7e, 0xae, 0xf7, 0xcf],
  [0x15, 0xd2, 0x15, 0x4f],
  [0x16, 0xa6, 0x88, 0x3c]
]

def i_to_b128(i)
  a = i.to_s(16).reverse.scan(/.{1,2}/).map(&:reverse).reverse
  n = 16 - a.length
  ret = []
  n.times do
    a.prepend("00")
  end

  ret = [[],[],[],[]]
  4.times do |i|
    4.times do |j|
      ret[j][i] = a.shift.to_i(16)
    end
  end

  ret
end

def b128_to_i(a)
  tmp = []
  4.times do |i|
    4.times do |j|
      tmp.append(a[j][i].to_s(16).rjust(2, '0'))
    end
  end

  tmp.join.to_i(16)
end

def s_to_i(s)
  s.unpack1("B*").to_i(2)
end

def mult128(x, y)
  r = 0b11100001 << 120
  z = 0
  v = y

  (0..127).each do |i|
    if (x & 0x80000000000000000000000000000000) == 0
      z = z
    else
      z = z ^ v
    end
    x = x << 1

    if (v & 0x01) == 0
      v = v >> 1
    else
      v = (v >> 1) ^ r
    end
  end

  z
end

def inc32(cb)
  i = b128_to_i(cb)
  r = i >> 32
  l = (i + 1) & 0xffffffff
  i = (r << 32) | l
  i_to_b128(i)
end

# GCTR function
# icb: initial counter block
# x: bit string X
def gctr(icb, x)
  if x == [] then
    return x
  end

  # Split into 128bit(16byte) chunks
  x_blocks = []
  x.each_slice(16){ |b| x_blocks.append(b) }

  y = []
  cb = icb

  # Iterate for each 128 chunks
  x_blocks.each_with_index do |xb, i|
    cbi = encrypt($key, inc32(cb)).flatten

    xb.each_with_index do |b,i|
      y.append(xb[i] ^ cbi[i])
    end
    cb = inc32(cb)
  end

  y
end

# GHASH function
# x: bit string X
def ghash(x)
  # Split into 128bit(16byte) chunks
  x_blocks = []
  x.each_slice(16){ |b| x_blocks.append(b) }

  y = 0
  x_blocks.each do |b|
    m = b.each_slice(4).map(&:to_a)
    y = mult128(y ^ b128_to_i(m), b128_to_i($h))
  end

  i_to_b128(y)
end

# Authenticated Encryption
# iv: initialization vector
# p: plaintext
# a: additional authenticated data
def gcm_ae(iv, p, a)
  $h = encrypt($key, ZERO128)
  j0 = []
  3.times do
    j0 << iv.take(4)
  end
  j0 << [0x00, 0x00, 0x00, 0x01]
  c = gctr(inc32(j0), p)

  u = 16 * (c.length/16.0).ceil - c.length
  v = 16 * (a.length/16.0).ceil - a.length
  al = [a.length.to_s(16).rjust(16, '0')].pack("H*").bytes
  cl = [c.length.to_s(16).rjust(16, '0')].pack("H*").bytes
  s = ghash(a + [0x00]*v + c + [0x00]*u + al + cl)
  t = gctr(j0, s.flatten).take(96/8)

  return [c, t]
end

# Authenticated Decryption
# iv: initialization vector
# c_and_t: array of cyphertext and tag
# a: additional authenticated data
def gcm_ad(iv, c_and_t, a)
  c = c_and_t[0]
  t = c_and_t[1]
  $h = encrypt($key, ZERO128)
  j0 = []
  3.times do
    j0 << iv.take(4)
  end
  j0 << [0x00, 0x00, 0x00, 0x01]

  p = gctr(inc32(j0), c)

  u = 16 * (c.length/16.0).ceil - c.length
  v = 16 * (a.length/16.0).ceil - a.length
  al = [a.length.to_s(16).rjust(16, '0')].pack("H*").bytes
  cl = [c.length.to_s(16).rjust(16, '0')].pack("H*").bytes
  s = ghash(a + [0x00]*v + c + [0x00]*u + al + cl)
  tdash = gctr(j0, s.flatten).take(96/8)

  if t != tdash then
    puts "fail"
  end

  return p
end

def set_key(hex_str)
  key = [[], [], [], []]
  l = [hex_str].pack("H*").bytes
  4.times do |i|
    4.times do |j|
      key[j][i] = l.shift
    end
  end
  $key = key
  p "key = #{$key}"
end

def test()
  p "TEST: #{b128_to_i(i_to_b128(2222222222))}" # => 2222222222
  p "TEST: #{s_to_i("aa")}" # => {0110 0000 0110 0000} => 24929

  cb = [
    [0x0, 0x0, 0x0, 0x0],
    [0x0, 0x0, 0x0, 0x0],
    [0x0, 0x0, 0x0, 0x0],
    [0x0, 0x0, 0x0, 0x0]
  ]
  p "TEST: #{inc32(cb)}" # => [...(zeros)...,[0, 0, 0, 1]]

  iv = [0x0]*12
  plaintext = [0x01, 0x02, 0x03, 0x04, 0x05]
  data = [0x01]*4
  p "TEST: plaintext= #{gcm_ad(iv, gcm_ae(iv, plaintext, data), data)}" # => [1, 2, 3, 4, 5]

  # iv = [0x0]*16
  # plaintext = ["607e0b9cd5f7daa30967b4a368c05cac00073b63b8b1fab56b9980fe277fd54c554fa08f173969904b1f1d000ba17128dbc2167ea7"].pack("H*").bytes
  # data = ["1703030035"].pack("H*").bytes
  # p data
  # set_key("2f40100976f03bf427e26d12f3d1e9b5b6529c575d9940bced9e5f035b722c41")
  # p gcm_ad(iv, plaintext, data)
end

# test()
