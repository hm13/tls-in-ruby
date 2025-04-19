# Overview
A toy implementation of TLS client, inspired by [bash_tls](https://github.com/gh2o/bash_tls).
I'm writing this to get a deeper understanding of the TLS protocol.
Currently, **work in progress**.

# Running
```
ruby tlsclient.rb
```
Currently, this command sends a Client Hello message to `example.com` and receives a Server Hello message and outputs into the standard output (binary).
![tlsclient_serverhello](https://github.com/user-attachments/assets/62876060-ce78-49f2-b333-80053520bd75)
