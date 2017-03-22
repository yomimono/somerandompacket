Shove random input into network packet parsers.  For use with [afl-persistent](https://github.com/stedolan/afl-persistent).  I use it like this:

```
afl-fuzz -i in/udp -o out/udp _build/src/fuzz_udp.native
```
