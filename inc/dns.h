/*
 * Copyright (c) 2014, Push Chen
 * All rights reserved.
 * File Name         : dns.h
 * Author            : Push Chen
 * Date              : 2014-06-20
*/

/*
    LGPL V3 Lisence
    This file is part of cleandns.

    cleandns is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    cleandns is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with cleandns.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
    LISENCE FOR CLEANDNS
    COPYRIGHT (c) 2014, Push Chen.
    ALL RIGHTS RESERVED.

    REDISTRIBUTION AND USE IN SOURCE AND BINARY
    FORMS, WITH OR WITHOUT MODIFICATION, ARE
    PERMITTED PROVIDED THAT THE FOLLOWING CONDITIONS
    ARE MET:

    YOU USE IT, AND YOU JUST USE IT!.
    WHY NOT USE THIS LIBRARY IN YOUR CODE TO MAKE
    THE DEVELOPMENT HAPPIER!
    ENJOY YOUR LIFE AND BE FAR AWAY FROM BUGS.
*/

#pragma once

#ifndef __CLEAN_DNS_DNS_PACKAGE_H__
#define __CLEAN_DNS_DNS_PACKAGE_H__

#include <iostream>
#include <cstdint>
#include <string>

using namespace std;

#pragma pack(push, 1)
typedef struct tag_dns_header {
    /*!
    A 16-bit field identifying a specific DNS transaction. The transaction ID is created by the message originator and is copied by the responder into its response message. Using the transaction ID, the DNS client can match responses to its requests.
    */
    uint16_t        transaction_id;
    /*!
    A 16-bit field containing various service flags that are communicated between the DNS client and the DNS server, including:
    */
    struct {
        /*!
        1-bit field set to 0 to represent a name service request or set to 1 to represent a name service response.
        */
        bool            qr:1;
        /*!
        4-bit field represents the name service operation of the packet: 0x0 is a query.
        */
        uint8_t         opcode:4;
        /*!
        1-bit field represents that the responder is authoritative for the domain name in the query message.
        */
        bool            aa:1;
        /*!
        1-bit field that is set to 1 if the total number of responses exceeded the User Datagram Protocol (UDP) datagram. Unless UDP datagrams larger than 512 bytes or EDNS0 are enabled, only the first 512 bytes of the UDP reply are returned.
        */
        bool            tc:1;
        /*!
        1-bit field set to 1 to indicate a recursive query and 0 for iterative queries. If a DNS server receives a query message with this field set to 0, it returns a list of other DNS servers that the client can contact. This list is populated from local cache data.
        */
        bool            rd:1;
        /*!
        1-bit field set by a DNS server to 1 to represent that the DNS server can handle recursive queries. If recursion is disabled, the DNS server sets the field appropriately.
        */
        bool            ra:1;
        /*!
        3-bit field that is reserved and set to 0.
        */
        uint8_t         z:3;
        /*!
        4-bit field holding the return code:
        * 0 is a successful response (query answer is in the query response).

        * 0x3 is a name error, indicating that an authoritative DNS server responded that the domain name in the query message does not exist. For more information about return codes, see DNS Reference Information.
        */
        uint8_t         rcode:4;
    }               flags;
    /*!
    A 16-bit field representing the number of entries in the question section of the DNS message.
    */
    uint16_t        qd_count;
    /*!
    A 16-bit field representing the number of entries in the answer section of the DNS message.
    */
    uint16_t        an_count;
    /*!
    A 16-bit field representing the number of authority resource records in the DNS message.
    */
    uint16_t        ns_count;
    /*!
    A 16-bit field representing the number of additional resource records in the DNS message.
    */
    uint16_t        ar_count;
} dns_header;
#pragma pack(pop)

// DNS Question Type
typedef enum {
    dns_qtype_host          = 0x01,     // Host(A) record
    dns_qtype_ns            = 0x02,     // Name server (NS) record
    dns_qtype_cname         = 0x05,     // Alias(CName) record
    dns_qtype_ptr           = 0x0C,     // Reverse-lookup(PTR) record
    dns_qtype_mx            = 0x0F,     // Mail exchange(MX) record
    dns_qtype_srv           = 0x21,     // Service(SRV) record
    dns_qtype_ixfr          = 0xFB,     // Incremental zone transfer(IXFR) record
    dns_qtype_axfr          = 0xFC,     // Standard zone transfer(AXFR) record
    dns_qtype_all           = 0xFF      // All records
} dns_qtype;

// DNS Question Class
typedef enum {
    dns_qclass_in           = 0x0001,   // Represents the IN(internet) question and is normally set to 0x0001
    dns_qclass_ch           = 0x0003,   // the CHAOS class
    dns_qclass_hs           = 0x0004    // Hesiod   
} dns_qclass;

// Get the domain from the dns querying package.
// The query domain seg will store the domain in the following format:
// [length:1Byte][component][length:1Byte][component]...
int dns_get_domain( const char *pkg, unsigned int len, std::string &domain );

// Generate a query package
int dns_generate_query_package( const string &query_name, string& buffer, dns_qtype qtype = dns_qtype_all );

// Generate a tc package
int dns_generate_tc_package( const string& incoming_pkg, string& buffer );

#endif

/*
 Push Chen.
 littlepush@gmail.com
 http://pushchen.com
 http://twitter.com/littlepush
 */