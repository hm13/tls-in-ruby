# Overview
A toy implementation of TLS client, inspired by [bash_tls](https://github.com/gh2o/bash_tls).
I'm writing this to get a deeper understanding of the TLS protocol.
Currently, **work in progress**.

# Running
```
$ ruby tlsclient.rb
type: 0x16
legacy_record_version: 0x0303
length: 0x005a
fragment: 0x02000056030395d4114d09f38bb56b1c2bdc45518223a072bab8cd7dc7cbd811de84780ed19b00130100002e002b0002030400330024001d0020a3daae8828f2eb1c3232cb69c7bb05915efabd0d2a9f50e744086e393b1d8b60
```
Currently, this command sends a Client Hello message to `example.com` and receives a Server Hello message and outputs into the standard output.
![tlsclient_serverhello](https://github.com/user-attachments/assets/62876060-ce78-49f2-b333-80053520bd75)
