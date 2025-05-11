# Overview
A toy implementation of TLS client, inspired by [bash_tls](https://github.com/gh2o/bash_tls).
I'm writing this to get a deeper understanding of the TLS protocol.
Currently, **work in progress**.

# Running
```
$ ruby tlsclient.rb
...
"server_hello:"
{:legacy_version=>"0303",
 :random=>"5f3a602dda001778f159b921c74ab60697f82a71e3421c19f3fc45054db6f001",
 :legacy_session_id_vl=>"",
 :cipher_suite=>"1301",
 :legacy_compressiom_method=>"00",
 :extensions_vl=>"2b0002030400330024001d00209fb833a785abdda482d4d2015cb7228d9bc570fd14d9a29d141f9112e2066171"}
```
Currently, this command sends a Client Hello message to `example.com` and receives a Server Hello message and outputs into the standard output.
![tlsclient_serverhello](https://github.com/user-attachments/assets/62876060-ce78-49f2-b333-80053520bd75)
