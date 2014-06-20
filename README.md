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
Default server port is 11025
* Client

    `cleandns --client --filter <file> --server <server> --port <port> --local <dns>`

* Server

    `cleandns --server --port <port> --local <dns>`

Example
========

    cleandns --client --filter ./filter.list --server <your_server_ip> --local 202.96.209.133
    cleandns --server --local 8.8.8.8

Version Log
========
v0.1    first version, rewrite. prototype is plib/pdns
