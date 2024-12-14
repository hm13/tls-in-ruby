require "socket"

s = TCPSocket.open("example.com", 80)
s.write("GET / HTTP/1.1" + "\r\n".b +
        "Host: example.com" + "\r\n".b +
        "\r\n".b)

while s.gets
  print($_)
end

