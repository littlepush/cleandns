cleandns
========

This is a DNS proxy client/server, it will route the UDP DNS request to local or remote parent DNS server according to the querying domain via TCP request.

Install
========
    make release

Filter File Format
========
    *.*domain*.*.*component*
We can put a '*' in any part of the domain.

Usage
========
Default remote port is 11025
* Client

    `cleandns --client --filter <file> --whitelist <file> --default <filter|whitelist> --remote <remote> --port <port> --local <dns>` --socks5 <proxy_address:proxy_port>

* Server

    `cleandns --server --port <port> --local <dns>`

Example
========

    cleandns --client --filter ./filter.list --remote <your_server_ip> --local 202.96.209.133 --socks5 127.0.0.1:1080
    cleandns --server --local 8.8.8.8

Version Log
========
* v0.1    first version, rewrite. prototype is plib/pdns
* v0.2    directly support socks5 proxy in the application
* v0.3    support white list
