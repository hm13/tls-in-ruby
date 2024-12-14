# Overview
A toy implementation of TLS client.
I'm writing this to get a deeper understanding of the TLS protocol.

# Running
```
ruby tlsclient.rb
```
Currently, this command outputs nothing but sends an incomplete TLS 1.3 Client Hello message to a server, which results in recieving a Hello Retry Request.
![tlsclient_wip](https://gist.github.com/user-attachments/assets/1887be37-ec4a-4374-8844-b95e54e57079)
