$p = 2**255 - 19

def decodeLittleEndian(b)
  s = 0
  (0..31).each do |i|
    s = s + (b[i] << 8*i)
  end
  s
end

def decodeUCoordinate(u)
  bytes = u.scan(/.{2}/).map{|s|s.to_i(16)}
  bytes[31] = bytes[31] & 0x7f
  decodeLittleEndian(bytes)
end

def encodeUCoordinate(u)
  u = u % $p
  res = []
  (0..31).each do |i|
    if u > 0 then
      res.append((u & 0xff).to_s(16).rjust(2, "0"))
      u = u >> 8
    else
      res.append("00")
    end
  end
  res.join
end

def decodeScalar25519(k)
  k_list = k.scan(/.{2}/).map{|s|s.to_i(16)}
  k_list[0] &= 248
  k_list[31] &= 127
  k_list[31] |= 64
  decodeLittleEndian(k_list)
end

def cswap(swap, x_2, x_3)
  # TODO: Should be constant time
  if swap then
    tmp = x_3
    x_3 = x_2
    x_2 = tmp
  end

  [x_2, x_3]
end

def x25519(scalar, u)
  u = decodeUCoordinate(u)
  k = decodeScalar25519(scalar)


  a24 = 121665

  x_1 = u
  x_2 = 1
  z_2 = 0
  x_3 = u
  z_3 = 1
  swap = 0

  (0..255-1).reverse_each do |t|
    k_t = (k >> t) & 1
    swap ^= k_t

    if swap == 1 then
      tmp = x_3; x_3 = x_2; x_2 = tmp
    end
    if swap == 1 then
      tmp = z_3; z_3 = z_2; z_2 = tmp
    end
    swap = k_t

    a = x_2 + z_2 % $p
    aa = a**2     % $p
    b = x_2 - z_2 % $p
    bb = b**2     % $p
    e = aa - bb   % $p
    c = x_3 + z_3 % $p
    d = x_3 - z_3 % $p
    da = d * a    % $p
    cb = c * b    % $p
    x_3 = (da + cb % $p)**2 % $p
    z_3 = x_1 * ((da - cb % $p)**2 % $p) % $p
    x_2 = aa * bb % $p
    z_2 = e * (aa + ((a24  * e) % $p) % $p) % $p
  end

  if swap == 1 then
    tmp = x_3; x_3 = x_2; x_2 = tmp
  end
  if swap == 1 then
    tmp = z_3; z_3 = z_2; z_2 = tmp
  end

  ret = (x_2 * z_2.pow($p-2, $p)) % $p

  encodeUCoordinate(ret)
end

def test()
  u = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
  puts "TEST: #{decodeUCoordinate(u)}"
  # => 34426434033919594451155107781188821651316167215306631574996226621102155684838

  scalar = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
  puts "TEST: #{decodeScalar25519(scalar)}"
  # => 31029842492115040904895560451863089656472772604678260265531221036453811406496

  u = 34426434033919594451155107781188821651316167215306631574996226621102155684838
  puts "TEST: #{encodeUCoordinate(u)}"
  # => e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c

  scalar = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
  u      = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
  puts "TEST: #{x25519(scalar, u)}"
  # => c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552


  k = "0900000000000000000000000000000000000000000000000000000000000000"
  u = "0900000000000000000000000000000000000000000000000000000000000000"
  puts "TEST: #{x25519(k, u)}"
  # => 422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079
  puts "TEST: #{r = 0; 1000.times do |i| r = x25519(k, u); u = k; k = r; end; k}"
  # => 684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51
end

# test()
