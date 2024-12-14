# Overview
A toy implementation of TLS client.
I'm writing this to get a deeper understanding of the TLS protocol.

# Running
```
ruby tlsclient.rb
```
Currently, this command outputs nothing but sends an incomplete TLS 1.3 Client Hello message to a server, which results in recieving a Hello Retry Request.
![tlsclient_wip](https://github.com/user-attachments/assets/a869a14e-c183-44f3-973b-444bde3b7fb2)
