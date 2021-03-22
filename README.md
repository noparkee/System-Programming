# System-Programming
KU COSE322   
with [ku-cylee](https://github.com/ku-cylee)



## hw 1: Log Structured File System Profiling   
Compare the wrtie behavior of F2FS and Ext4.
### Build and Load Module
```sh
$ make
$ sudo insmod sp-logger.ko
```

### Unload Module
```sh
$ make unload
```



## hw 2: Client-Side Socket Programming using pthread   
Making a packet receiving program using pthread.
### Build
```sh
$ make
```
### Execute
```sh
$ ./bin/client.out
input: 4 1111 2222 3333 4444
open: 1111 2222 3333 4444
close
input:
```
### Log Files
```sh
$ ls ./logs/
1111-3.txt 2222-3.txt 3333-3.txt 4444-3.txt
```



## hw 3: Custom Firewall using Netfilter Hooks and proc File System.
### Build and Load Module
```sh
$ make
$ make enable
$ route add -host 131.1.1.1 dev enp0s3
$ make load
```
### Unload Module
```sh
$ make unload
```
