# Overview
A toy implementation of TLS client, inspired by [bash_tls](https://github.com/gh2o/bash_tls).
I'm writing this to get a deeper understanding of the TLS protocol.
Currently, **work in progress**.

# Current status
Crurrently, debugging. `$ ruby tls.rb` command receives (encrypted) handshake messages.
Trying to decrypt with the key derived from handshake_secret, but not working properly.
```
$ ruby tls.rb
"early_secret = b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
"handshake_secret = 777974be53ef1159bf6d0ad1eb017b387779272cb19ea8457f893ae597a3a2cf"
...
{:type=>"17", :legacy_record_version=>"0303", :length=>"0021", :fragment=>"04a832e6f94252832fbfefe8503f2a17bba2e38aa39801f9a6338f24e61629f2ab"}
...
"CYPHERTEXT = 04a832e6f94252832fbfefe8503f2a17bba2e38aa39801f9a6338f24e61629f2ab"
"PLAINTEXT = \x8F\xFB\x16\x86\x8BS\xB8Y\xBD\xC2\x1D\xDEr)\x81\xE8\xE9\xD2*q;\x95\xBD-\x89\x1Fp\xFC\xE0\x81wH\x8F"
```
