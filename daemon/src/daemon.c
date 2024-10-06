#include <linux/module.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/nfnetlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <poll.h>
#include <math.h>
#include <dns_message.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <assert.h>
#include <map.h>
#include <constants.h>
#include <pthread.h>
#include <crypto.h>

uint32_t MAXUDP = 1232;
uint32_t our_addr;
uint32_t is_resolver = false;
bool BYPASS = false;

bool turbo_dns = true;
char *turbo_dns_cookie;
bool have_cookie = false;
unsigned char old_txid[2];
unsigned char new_txid[2];
unsigned int last_data_seq = 0;

char *itoa(uint16_t in) {
    char *res = NULL;
    int num_bytes = snprintf(NULL, 0, "%hu", in) + 1;
    res = malloc(sizeof(char) * num_bytes);
    snprintf(res, num_bytes, "%hu", in);
    return res;
}

void print_ip_port(unsigned int src_ip, unsigned int dst_ip,
                   unsigned int src_port, unsigned int dst_port) {
    unsigned char bytes[4];
    bytes[0] = src_ip & 0xFF;
    bytes[1] = (src_ip >> 8) & 0xFF;
    bytes[2] = (src_ip >> 16) & 0xFF;
    bytes[3] = (src_ip >> 24) & 0xFF;
    printf("src_ip: %d.%d.%d.%d src_port: %d\n", bytes[0], bytes[1], bytes[2],
           bytes[3], src_port);
    bytes[0] = dst_ip & 0xFF;
    bytes[1] = (dst_ip >> 8) & 0xFF;
    bytes[2] = (dst_ip >> 16) & 0xFF;
    bytes[3] = (dst_ip >> 24) & 0xFF;
    printf("dst_ip: %d.%d.%d.%d dst_port: %d\n", bytes[0], bytes[1], bytes[2],
           bytes[3], dst_port);

}

void ERROR(void) {
    assert(false);
}

typedef struct RequesterMsgStore {
    DNSMessage *qry;
    struct iphdr *iphdr;
    void *transport_header;
} RequesterMsgStore;

typedef struct ResponderMsgStore {
    DNSMessage *qry;
    DNSMessage *resp;
    struct iphdr *iphdr;
    void *transport_header;
    char cookie[8];
    bool cookie_provided;
} ResponderMsgStore;

typedef struct ToSendDNSMessage {
    DNSMessage *m_arr[25];
    int m_arr_size;
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    bool is_tcp;
    bool swap_ip;
} ToSendDNSMessage;

typedef struct ToSendTCPData {
    struct iphdr *iph;
    struct tcphdr *tcph;
    char *payload;
} ToSendTCPData;

bool update_max_udp(DNSMessage *msg, uint16_t new_size) {
    bool res = false;
    // First we need to find opt. It's always located in
    // the additional section.
    uint16_t arcount = msg->arcount;
    for (uint16_t i = 0; i < arcount; i++) {
        ResourceRecord *rr = msg->additional_section[i];
        if (rr->type == OPT) {
            rr->clas = new_size;    // the class field in opt is used for max UDP size
            res = true;
            break;
        }
    }

    return res;
}

bool construct_intermediate_message(DNSMessage *in, DNSMessage **out) {
    clone_dnsmessage(in, out);
    return update_max_udp(*out, 65507U);
}


// From The Practice of Programming
uint16_t hash_16bit(unsigned char *in, size_t in_len) {
    uint16_t h;
    unsigned char *p = in;

    h = 0;
    for (size_t i = 0; i < in_len; i++) {
        h = 37 * h + p[i];
    }

    return h;
}

typedef struct shared_map {
    sem_t lock;
    hashmap *map;
} shared_map;

shared_map responder_cache;
hashmap *requester_state;
hashmap *responder_state;
shared_map connection_info;

typedef struct conn_info {
    int fd;
    void *transport_header;
    bool is_tcp;
    struct iphdr *iphdr;
    int frag_num;
    char *qname;
    ResourceRecord *rr_ct;
} conn_info;

void init_shared_map(shared_map *map) {
    sem_init(&(map->lock), 0, 1);
    map->map = hashmap_create();
}

void create_generic_socket(uint32_t dest_addr, uint16_t dest_port, bool is_tcp,
                           int *out_fd) {
    struct sockaddr_in addrinfo;
    addrinfo.sin_family = AF_INET;
    addrinfo.sin_addr.s_addr = dest_addr;
    int sock_type = -1;
    if (is_tcp) {
        sock_type = SOCK_STREAM;
    } else {
        sock_type = SOCK_DGRAM;
    }

    addrinfo.sin_port = dest_port;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addrinfo.sin_addr, ip, INET_ADDRSTRLEN);
    char *port = itoa(ntohs(addrinfo.sin_port));
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = sock_type;
    getaddrinfo(ip, port, &hints, &res);
    int fd = socket(addrinfo.sin_family, sock_type, 0);
    if (fd < 0) {
        printf("Error creating socket!\n");
        exit(-1);
    }

    connect(fd, res->ai_addr, res->ai_addrlen);
    *out_fd = fd;
}

void generic_close(int *fd) {
    close(*fd);
}

void generic_send(int fd, unsigned char *bytes, size_t byte_len) {
    int bytes_sent = send(fd, bytes, byte_len, 0);
    if (bytes_sent != byte_len) {
        printf("Error! Didn't send enough.\n");
        exit(-1);
    }
}

void generic_recv(int fd, unsigned char *buff, size_t *bufflen) {
    *bufflen = recv(fd, buff, *bufflen, 0);

}

// The internal packet functions are to get around an issue
// where netfilter queue prevents packets between the daemon
// and dns server from being sent.

bool is_internal_packet(struct iphdr *iphdr) {
    return (!is_resolver
            && (iphdr->saddr == our_addr && iphdr->daddr == our_addr));
}

// If we get an internal message that looks like a DNSMessage, then we can assume
// it is passing information between the daemon and either the requester or receiver

uint16_t csum(uint16_t *ptr, int32_t nbytes) {
    int32_t sum;
    uint16_t oddbyte;
    uint16_t answer;

    sum = 0;
    while (nbytes > 1) {
        sum += htons(*ptr);
        ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *) &oddbyte) = *(unsigned char *) ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (int16_t)
    ~sum;

    return answer;
}

bool create_raw_socket(int *fd) {
    int _fd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (_fd < 0) {
        return false;
    }

    *fd = _fd;
    return true;
}

bool raw_socket_send(int fd, unsigned char *payload, size_t payload_len,
                     uint32_t saddr, uint32_t daddr, uint16_t sport,
                     uint16_t dport, bool is_tcp) {
    unsigned char *datagram;
    if (is_tcp) {
        datagram =
                malloc(sizeof(struct iphdr) + sizeof(struct tcphdr) +
                       (sizeof(char) * payload_len));
    } else {
        datagram =
                malloc(sizeof(struct iphdr) + sizeof(struct udphdr) +
                       (sizeof(char) * payload_len));
    }

    struct iphdr *iph = (struct iphdr *) datagram;

    unsigned char *data;
    if (is_tcp) {
        data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    } else {
        data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
    }

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    if (is_tcp) {
        iph->tot_len =
                sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;
    } else {
        iph->tot_len =
                sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
    }

    iph->tot_len = htons(iph->tot_len);
    memcpy(data, payload, payload_len);
    iph->id = htons(1234);    // This is fine for POC but obviously not for deployment
    iph->frag_off = 0;
    iph->ttl = 255;
    if (is_tcp) {
        iph->protocol = IPPROTO_TCP;
    } else {
        iph->protocol = IPPROTO_UDP;
    }

    iph->check = 0;
    iph->saddr = saddr;
    iph->daddr = daddr;
    // IP checksum
    iph->check = csum((uint16_t *) datagram, sizeof(struct iphdr));
    iph->check = htons(iph->check);
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);
    sin.sin_addr.s_addr = daddr;

    unsigned char *tphdr = datagram + sizeof(struct iphdr);
    if (is_tcp) {
        // TCP is not properly implemented. Still need TCP checksum
        struct tcphdr *tcph = (struct tcphdr *) tphdr;
        tcph->source = sport;
        tcph->dest = dport;
        tcph->seq = 0;
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->fin = 0;
        tcph->syn = 1;
        tcph->rst = 0;
        tcph->psh = 0;
        tcph->ack = 0;
        tcph->urg = 0;
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;
    } else {
        struct udphdr *udph = (struct udphdr *) tphdr;
        udph->source = sport;
        udph->dest = dport;
        udph->check = 0;
        udph->len = htons(payload_len + sizeof(struct udphdr));
    }

    int value = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value))) {
        perror("Error setting IP_HDRINCL");
        exit(-1);
    }

    if (sendto(fd, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
        perror("raw socket failed to send");
        return false;
    }

    // we don't need to wait for a response for these, so just close the socket.
    close(fd);
    return true;
}

void send_dns_messsge(DNSMessage *msg, struct iphdr *iphdr,
                      void *transport_header, bool is_tcp, bool swap_ip) {

    unsigned char *msgbytes;
    size_t msgbyte_len;

    if (msg != NULL)
        dnsmessage_to_bytes(msg, &msgbytes, &msgbyte_len);
    else {
        msgbytes = NULL;
        msgbyte_len = 0;
    }

    int out_fd;
    if (!create_raw_socket(&out_fd)) {
        printf("Failed to make raw socket to send DNS Message \n");
        fflush(stdout);
        ERROR();
    }

    if (swap_ip) {
        if (is_tcp) {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, iphdr->daddr,
                            iphdr->saddr,
                            ((struct tcphdr *) transport_header)->dest,
                            ((struct tcphdr *) transport_header)->source, is_tcp);
        } else {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, iphdr->daddr,
                            iphdr->saddr,
                            ((struct udphdr *) transport_header)->dest,
                            ((struct udphdr *) transport_header)->source, is_tcp);
        }
    } else {
        if (is_tcp) {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, iphdr->saddr,
                            iphdr->daddr,
                            ((struct tcphdr *) transport_header)->source,
                            ((struct tcphdr *) transport_header)->dest, is_tcp);
        } else {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, iphdr->saddr,
                            iphdr->daddr,
                            ((struct udphdr *) transport_header)->source,
                            ((struct udphdr *) transport_header)->dest, is_tcp);
        }
    }
    generic_close(&out_fd);
    free(msgbytes);
}

// this function is identical to the above except for the arguments it takes
void send_dns_messsge2(DNSMessage *msg, uint32_t saddr, uint32_t daddr, uint16_t sport,
                       uint16_t dport, bool is_tcp, bool swap_ip) {
    unsigned char *msgbytes;
    size_t msgbyte_len;
    dnsmessage_to_bytes(msg, &msgbytes, &msgbyte_len);

    int out_fd;
    if (!create_raw_socket(&out_fd)) {
        printf("Failed to make raw socket to send DNS Message \n");
        fflush(stdout);
        ERROR();
    }

    if (swap_ip) {
        if (is_tcp) {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, daddr,
                            saddr,
                            dport,
                            sport, is_tcp);
        } else {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, daddr,
                            saddr,
                            dport,
                            sport, is_tcp);
        }
    } else {
        if (is_tcp) {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, saddr,
                            daddr,
                            sport,
                            dport, is_tcp);
        } else {
            raw_socket_send(out_fd, msgbytes, msgbyte_len, saddr,
                            daddr,
                            sport,
                            dport, is_tcp);
        }
    }
    generic_close(&out_fd);
    free(msgbytes);
}

bool handle_internal_packet(struct nfq_q_handle *qh, uint32_t id,
                            struct iphdr *iphdr, uint64_t *question_hash_port,
                            unsigned char *outbuff, size_t *outbuff_len) {
    assert(is_internal_packet(iphdr));
    uint32_t verdict = NF_ACCEPT;
    if (!nfq_set_verdict(qh, id, verdict, 0, NULL)) {
        printf("Failed to accept internal packet\n");
        fflush(stdout);
        exit(-1);
    }

    // We need to get the file descriptor from a previous cb, so get it from
    // a hashtable based on the dest (original socket's source port)
    // if there is something there, receive it, otherwise just return
    conn_info *ci;
    int fd;
    if (!hashmap_get
            (connection_info.map, question_hash_port, sizeof(uint64_t),
             (uintptr_t * ) & ci)) {
        return false;
    }

    fd = ci->fd;
    struct pollfd ufd;
    memset(&ufd, 0, sizeof(struct pollfd));
    ufd.fd = fd;
    ufd.events = POLLIN;
    int rv = poll(&ufd, 1, 0);
    if (rv == -1) {
        perror("Failed to poll");
        fflush(stdout);
        exit(-1);
    } else if (rv == 0) {
        // This must be an "outgoing" internal message
        // so we just need to accept
        return false;
    } else {
        if (ufd.revents & POLLIN) {
            *outbuff_len = recv(fd, outbuff, *outbuff_len, 0);
            return true;
        } else {
            printf("poll returned on an event we don't care about\n");
            exit(-1);
        }
    }
}

void internal_close(int fd, uint64_t question_hash_port) {
    hashmap_remove(connection_info.map, &question_hash_port,
                   sizeof(uint64_t));
    generic_close(&fd);
}

void refresh_hashmap(hashmap **map);

void *sendTCPQueryThread(void *ptr) {
    int delay_ms = 1;
    if (DEBUG)
        delay_ms = 5;

    printf("\nSleep for %d ms...\n", delay_ms);        // slight delay to let the resolver process syn-ack first
    usleep(delay_ms * 1000);

    ToSendTCPData *mystruct = (ToSendTCPData *) ptr;

    int fd;
    if (!create_raw_socket(&fd)) {
        printf("Failed to make raw socket to send DNS Message \n");
        fflush(stdout);
        ERROR();
    }

    int value = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value))) {
        perror("Error setting IP_HDRINCL");
        exit(-1);
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(mystruct->tcph->dest);
    sin.sin_addr.s_addr = mystruct->iph->daddr;

    if (sendto(fd, mystruct->payload, ntohs(mystruct->iph->tot_len), 0,
               (struct sockaddr *) &sin,
               sizeof(sin)) < 0) {
        perror("raw socket failed to send");
        return false;
    }

    generic_close(&fd);

    return NULL;
}

/* Source: https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a */
/* set tcp checksum: given IP header and tcp segment */
unsigned short compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
    register unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl << 2);
    struct tcphdr *tcphdrp = (struct tcphdr *) (ipPayload);
    //add the pseudo header
    //the source ip
    sum += (pIph->saddr >> 16) & 0xFFFF;
    sum += (pIph->saddr) & 0xFFFF;
    //the dest ip
    sum += (pIph->daddr >> 16) & 0xFFFF;
    sum += (pIph->daddr) & 0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);

    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += *ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if (tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload) & htons(0xFF00));
    }
    //Fold 32-bit sum to 16 bits: add carrier to result
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short) sum;
    return tcphdrp->check;
}

uint32_t process_dns_message(struct nfq_q_handle *qh, uint32_t id,
                             unsigned char *payload, size_t payloadLen,
                             struct iphdr *iphdr, void *transport_header, bool is_tcp, bool BYPASS) {
    unsigned char *pkt_content;
    DNSMessage *msg;

    uint32_t saddr = iphdr->saddr;
    uint32_t daddr = iphdr->daddr;
    uint16_t sport;
    uint16_t dport;
    uint16_t sport_;
    uint16_t dport_;

    if (is_tcp) {
        sport = ((struct tcphdr *) transport_header)->source;
        sport_ = sport;
        sport = ntohs(sport);
        dport = ((struct tcphdr *) transport_header)->dest;
        dport_ = dport;
        dport = ntohs(dport);
    } else {
        sport = ((struct udphdr *) transport_header)->source;
        sport_ = sport;
        sport = ntohs(sport);
        dport = ((struct udphdr *) transport_header)->dest;
        dport_ = dport;
        dport = ntohs(dport);
    }

    if (is_tcp) {
        printf("\n\n* Got IP Packet via TCP *\n");
    } else
        printf("\n\n* Got IP Packet via UDP *\n");

    print_ip_port(saddr, daddr, sport, dport);

    size_t msgSize = payloadLen;
    if (is_tcp) {
        pkt_content = payload + sizeof(struct tcphdr) + sizeof(struct iphdr);
        msgSize -= sizeof(struct tcphdr) + sizeof(struct iphdr);
    } else {
        pkt_content = payload + sizeof(struct udphdr) + sizeof(struct iphdr);
        msgSize -= sizeof(struct udphdr) + sizeof(struct iphdr);
    }

    if (is_tcp) {
        if ((daddr == 50336940 || saddr == 50336940) && is_resolver)            // 50336940 = root ip. Ignore
            return NF_ACCEPT;
//        printf("[Warning]This doesn't look like a dnsmessage\n");
        fflush(stdout);
        if (DEBUG) {
            printf("Packet bytes: ");
            for (int i = 0; i < payloadLen; i++)
                printf("%02x ", payload[i]);
            printf("\n");
        }
        printf("tcp_syn : %hu\n", ((struct tcphdr *) transport_header)->syn);
        printf("tcp_ack : %hu\n", ((struct tcphdr *) transport_header)->ack);
        printf("tcp_psh : %hu\n", ((struct tcphdr *) transport_header)->psh);
        printf("tcp_fin : %hu\n", ((struct tcphdr *) transport_header)->fin);
        printf("tcp_rst : %hu\n", ((struct tcphdr *) transport_header)->rst);

        if (is_resolver && (((struct tcphdr *) transport_header)->syn) == 1 &&
            (((struct tcphdr *) transport_header)->ack) == 0) {
            printf("TCP-SYN detected! \n");

            RequesterMsgStore *store;
            if (hashmap_get(requester_state, "0", sizeof("0"), (uintptr_t * ) & store)) {
                printf("Original Query found in cache!\n");
                DNSMessage *qry;
                clone_dnsmessage(store->qry, &qry);
//                dnsmessage_to_string(qry);

                unsigned char *msgbytes;
                size_t msgbyte_len;
                dnsmessage_to_bytes(qry, &msgbytes, &msgbyte_len);
                memcpy(old_txid, msgbytes, 2);
                printf("\nSaving old_txid %02x %02x\n", old_txid[0], old_txid[1]);

                ResourceRecord *rr;
                clone_rr(qry->additional_section[0], &rr);
                rr->type = 48;
                rr->clas = 1;
                rr->ttl = 604800;
                rr->rdsize = payloadLen;
                free(rr->rdata);
                rr->rdata = malloc(sizeof(unsigned char) * rr->rdsize);

                memcpy(rr->rdata, payload, payloadLen);

                ResourceRecord *rr_opt; // modified opt with HMAC cookie
                if (have_cookie) {
                    clone_rr(qry->additional_section[0], &rr_opt);
                    rr_opt->rdsize = (rr_opt->rdsize) + 2 + 2 + 8; //2B OpCode + 2B OpLength + 8B HMAC cookie
                    free(rr_opt->rdata);
                    rr_opt->rdata = malloc(sizeof(unsigned char) * rr_opt->rdsize);
                    memcpy(rr_opt->rdata, qry->additional_section[0]->rdata, qry->additional_section[0]->rdsize);

                    const unsigned char tmp[] = {0xFD, 0xE9, 0x00, 0x08}; // 2B OpCode + 2B OpLength
                    memcpy((rr_opt->rdata) + (qry->additional_section[0]->rdsize), tmp, 4);
                    memcpy((rr_opt->rdata) + (qry->additional_section[0]->rdsize) + 4, turbo_dns_cookie,
                           8); // 8B HMAC cookie
                }

                ResourceRecord **additional_section = malloc(sizeof(ResourceRecord * ) * 2);
                clone_rr(rr, additional_section);

                if (have_cookie) {
                    clone_rr(rr_opt, additional_section + 1);
                } else {
                    clone_rr(qry->additional_section[0], additional_section + 1);
                }

                Question **question_section = malloc(sizeof(Question * ));
                clone_question(qry->question_section[0], question_section);

                DNSMessage *tmp;
                create_dnsmessage(&tmp, qry->identification, qry->flags, 1, 0, 0, 2,
                                  question_section, NULL, NULL, additional_section);

                printf("Turbo DNS SYN Query\n");
//                dnsmessage_to_string(tmp);
                send_dns_messsge(tmp, store->iphdr, store->transport_header, 0, 0);
                if (!have_cookie) {
                    printf("Emptying cache...\n");
                    hashmap_remove(requester_state, "0", sizeof("0"));
                }
                printf("* Drop TCP-SYN *\n");
                return NF_DROP;
            }
        } else if (!is_resolver && (((struct tcphdr *) transport_header)->syn) == 1 &&
                   (((struct tcphdr *) transport_header)->ack) == 1) {
            printf("TCP-SYN-ACK detected! \n");

            ResponderMsgStore *store;
            if (hashmap_get(responder_state, "0", sizeof("0"), (uintptr_t * ) & store)) {
                printf("Original response found in cache! \n");
                DNSMessage *resp;
                clone_dnsmessage(store->resp, &resp);
//                dnsmessage_to_string(resp);

                ResourceRecord *rr;
                clone_rr(resp->additional_section[0], &rr);
                rr->type = 48;
                rr->clas = 1;
                rr->ttl = 604800;
                rr->rdsize = payloadLen;
                free(rr->rdata);
                rr->rdata = malloc(sizeof(unsigned char) * rr->rdsize);

                memcpy(rr->rdata, payload, payloadLen);

                ResourceRecord *rr_opt; // modified opt with HMAC cookie
                bool client_authenticated = false;
                clone_rr(resp->additional_section[0], &rr_opt);
                rr_opt->rdsize = (rr_opt->rdsize) + 2 + 2 + 8; //2B OpCode + 2B OpLength + 8B HMAC cookie
                free(rr_opt->rdata);
                rr_opt->rdata = malloc(sizeof(unsigned char) * rr_opt->rdsize);
                memcpy(rr_opt->rdata, resp->additional_section[0]->rdata, resp->additional_section[0]->rdsize);

                unsigned char *data_to_hmac = malloc(12); // 8B client cookie + 4B client IP address
                unsigned char *client_cookie = malloc(8);
                memcpy(client_cookie, (resp->additional_section[0]->rdata) + 4, 8);

                unsigned char bytes[4];
                bytes[0] = daddr & 0xFF;
                bytes[1] = (daddr >> 8) & 0xFF;
                bytes[2] = (daddr >> 16) & 0xFF;
                bytes[3] = (daddr >> 24) & 0xFF;

                unsigned char client_ip_addr[] = {bytes[0], bytes[1], bytes[2], bytes[3]};
                memcpy(data_to_hmac, client_cookie, 8);
                memcpy(data_to_hmac + 8, client_ip_addr, 4);

                unsigned char *result = gen_hmac("daemon_key00", strlen("daemon_key00"), data_to_hmac, 12);
                if (store->cookie_provided) {
                    printf("\nClient had provided a Turbo DNS cookie...");
                    printf("\nCookie provided: ");
                    for (int i = 0; i < 8; i++) {
                        printf("%02x ", store->cookie[i]);
                    }
                    printf("\nCookie calculated: ");
                    bool verify_status = true;
                    for (int i = 0; i < 8; i++) {
                        printf("%02x ", result[i]);
                        if (result[i] != store->cookie[i])
                            verify_status = false;
                    }
                    client_authenticated = verify_status;
                    printf("\nClient Authenticated: %s", verify_status ? "true" : "false");
                }

                const unsigned char buf[] = {0xFD, 0xE9, 0x00, 0x08}; // 2B OpCode + 2B OpLength
                memcpy((rr_opt->rdata) + (resp->additional_section[0]->rdsize), buf, 4);
                memcpy((rr_opt->rdata) + (resp->additional_section[0]->rdsize) + 4, result, 8); // 8B HMAC cookie

                ResourceRecord **additional_section = malloc(sizeof(ResourceRecord * ) * 2);
                clone_rr(rr, additional_section);

                clone_rr(rr_opt, additional_section + 1);


                Question **question_section = malloc(sizeof(Question * ));
                clone_question(resp->question_section[0], question_section);

                DNSMessage *tmp;
                create_dnsmessage(&tmp, resp->identification, resp->flags, 1, 0, 0, 2,
                                  question_section, NULL, NULL, additional_section);

                printf("\nSend Turbo DNS SYN-ACK Response\n");
                if (DEBUG)
                    dnsmessage_to_string(tmp);
                send_dns_messsge(tmp, store->iphdr, store->transport_header, 0, 0);


                if (client_authenticated) {
                    have_cookie = true;
                    printf("\n *** dummy ack *** \n");
                    char dummy_ip_hdr[] = {0x45, 0x00, 0x00, 0x34, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00,
                                           0x00, 0xac, 0x14, 0x00, 0x02, 0xac, 0x14, 0x00, 0x04};


                    char dummy_tcp_hdr[] = {0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x80, 0x10, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
                                            0x01, 0x08, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

                    unsigned char packet_iphdr[20];
                    memcpy(packet_iphdr, store->qry->additional_section[0]->rdata, 20);

//                    dummy_ip_hdr[4] = packet_iphdr[4];          // IP identification.
//                    dummy_ip_hdr[5] = packet_iphdr[5] + 1;     //  Ignoring overflow corner-cases

//                    for (int i = 0; i < 20; i++) {
//                        printf("%02x ", dummy_ip_hdr[i]);
//                    }

                    unsigned char packet_tcphdr[40];
                    memcpy(packet_tcphdr, store->qry->additional_section[0]->rdata + 20, 40);

                    memcpy(dummy_tcp_hdr, packet_tcphdr, 2); // copy client src port
                    memcpy(dummy_tcp_hdr + 4, packet_tcphdr + 4, 4); // copy client seq sum
                    dummy_tcp_hdr[7] += 1;  // seq + 1.
                    if (dummy_tcp_hdr[7] == 0x00)
                        dummy_tcp_hdr[6] += 1;  // overflow

                    memcpy(dummy_tcp_hdr + 24, packet_tcphdr + 28, 4); // copy client TSval
//                    dummy_tcp_hdr[27] += 5; // RTT = 5ms

                    memcpy(packet_tcphdr, payload + 20, 40);
                    memcpy(dummy_tcp_hdr + 8, packet_tcphdr + 4, 4); // copy server seq num into client ack
                    dummy_tcp_hdr[11] += 1; // ack + 1.
                    if (dummy_tcp_hdr[11] == 0x00)
                        dummy_tcp_hdr[10] += 1;  // overflow
                    memcpy(dummy_tcp_hdr + 28, packet_tcphdr + 28, 4); // copy TSecr

//                    printf("\n");
//                    for (int i = 0; i < 32; i++) {
//                        printf("%02x ", dummy_tcp_hdr[i]);
//                    }

                    char *ack_packet = malloc(20 + 32);
                    memcpy(ack_packet, dummy_ip_hdr, 20);
                    memcpy(ack_packet + 20, dummy_tcp_hdr, 32);

//                    printf("\n ACK Packet before \n");
//                    for (int i = 0; i < 52; i++) {
//                        printf("%02x ", ack_packet[i]);
//                    }

                    struct iphdr *iph = (struct iphdr *) dummy_ip_hdr;

                    unsigned short tcp_checksum = compute_tcp_checksum(iph, dummy_tcp_hdr);
//                    printf("\nchecksum: %02x\n", tcp_checksum);
                    unsigned char *tcp_checksum_bytearr = malloc(2);
                    tcp_checksum_bytearr[1] = (tcp_checksum >> 8) & 0xFF;
                    tcp_checksum_bytearr[0] = tcp_checksum & 0xFF;

//                    for (int i = 0; i < 2; i++)
//                        printf("\n*** %02x ***\n", tcp_checksum_bytearr[i]);

                    memcpy(dummy_tcp_hdr + 16, tcp_checksum_bytearr, 2);

                    memcpy(ack_packet, dummy_ip_hdr, 20);
                    memcpy(ack_packet + 20, dummy_tcp_hdr, 32);

                    if (DEBUG) {
                        printf("\n ACK IP Packet \n");
                        for (int i = 0; i < 52; i++) {
                            printf("%02x ", ack_packet[i]);
                        }
                    }
                    struct tcphdr *tcph = (struct tcphdr *) dummy_tcp_hdr;

                    int fd;
                    if (!create_raw_socket(&fd)) {
                        printf("Failed to make raw socket to send DNS Message \n");
                        fflush(stdout);
                        ERROR();
                    }

                    int value = 1;
                    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value))) {
                        perror("Error setting IP_HDRINCL");
                        exit(-1);
                    }

                    struct sockaddr_in sin;
                    sin.sin_family = AF_INET;
                    sin.sin_port = htons(tcph->dest);
                    sin.sin_addr.s_addr = iph->daddr;

//                    if (sendto(fd, ack_packet, ntohs(iph->tot_len), 0,
//                               (struct sockaddr *) &sin,
//                               sizeof(sin)) < 0) {
//                        perror("raw socket failed to send");
//                        return false;
//                    }

                    generic_close(&fd);


                    printf("\n *** dummy ack *** \n");

                    printf("\n *** dummy dns query *** \n");

                    unsigned char *msgbytes;
                    size_t msgbyte_len;
                    dnsmessage_to_bytes(store->resp, &msgbytes, &msgbyte_len);
                    msgbytes[2] = msgbytes[3] = 0x00; // set flags to 0x0000 (query)
//                    printf("\nresp length %d\n", msgbyte_len);

                    dummy_ip_hdr[3] = msgbyte_len + 2 + 32 + 20; // IP Total length
//                    dummy_ip_hdr[5] += 1;     // IP identification. Ignoring overflow corner-cases

//                    for (int i = 0; i < 20; i++) {
//                        printf("%02x ", dummy_ip_hdr[i]);
//                    }

                    dummy_tcp_hdr[13] = 0x18; // Flags: PSH, ACK
                    printf("\n");
//                    for (int i = 0; i < 32; i++) {
//                        printf("%02x ", dummy_tcp_hdr[i]);
//                    }

                    char *app_data = malloc(msgbyte_len + 2);
                    app_data[0] = 0x00;
                    app_data[1] = msgbyte_len;
                    memcpy(app_data + 2, msgbytes, msgbyte_len);
//                    printf("\n Data in TCP segment) \n");
//                    for (int i = 0; i < msgbyte_len + 2; i++) {
//                        printf("%02x ", app_data[i]);
//                    }

                    char *qry_packet = malloc(msgbyte_len + 2 + 32 + 20);
                    memcpy(qry_packet, dummy_ip_hdr, 20);
                    memcpy(qry_packet + 20, dummy_tcp_hdr, 32);
                    memcpy(qry_packet + 52, app_data, msgbyte_len + 2);

                    iph = (struct iphdr *) dummy_ip_hdr;

                    tcp_checksum = compute_tcp_checksum(iph, qry_packet + 20);
//                    printf("\nchecksum: %02x\n", tcp_checksum);
                    tcp_checksum_bytearr[1] = (tcp_checksum >> 8) & 0xFF;
                    tcp_checksum_bytearr[0] = tcp_checksum & 0xFF;

//                    for (int i = 0; i < 2; i++)
//                        printf("\n*** %02x ***\n", tcp_checksum_bytearr[i]);

                    memcpy(dummy_tcp_hdr + 16, tcp_checksum_bytearr, 2);
                    memcpy(qry_packet + 20, dummy_tcp_hdr, 32);
                    tcph = (struct tcphdr *) dummy_tcp_hdr;

                    if (DEBUG) {
                        printf("\n DNS Query TCP/IP packet \n");
                        for (int i = 0; i < msgbyte_len + 2 + 32 + 20; i++) {
                            printf("%02x ", qry_packet[i]);
                        }
                    }

                    printf("\n *** dummy dns query *** \n");

                    ToSendTCPData *tosendPTR;
                    tosendPTR = (ToSendTCPData *) malloc(sizeof(ToSendTCPData));
                    tosendPTR->iph = malloc(sizeof(iph));
                    tosendPTR->tcph = malloc(sizeof(tcph));
                    memcpy(tosendPTR->iph, iph, sizeof(iph));
                    memcpy(tosendPTR->tcph, tcph, sizeof(tcph));
                    tosendPTR->payload = malloc(msgbyte_len + 2 + 32 + 20);
                    memcpy(tosendPTR->payload, qry_packet, msgbyte_len + 2 + 32 + 20);

                    pthread_t thread_id;
                    pthread_create(&thread_id, NULL, sendTCPQueryThread, (void *) tosendPTR);
                }

                printf("Emptying cache...\n");
                hashmap_remove(responder_state, "0", sizeof("0"));
                printf("Drop TCP-SYN-ACK\n");
                return NF_DROP;
            }
        } else if (is_resolver && (((struct tcphdr *) transport_header)->syn) == 0 &&
                   (((struct tcphdr *) transport_header)->ack) == 1 &&
                   (((struct tcphdr *) transport_header)->psh) == 0) {
            if (sport == 53 && payloadLen > 54) {
                printf("TCP-ACK with data detected! \n");
                printf("payloadlen %d\n", payloadLen);
//                printf("\n1st response from nameserver...");
                char tmp_txid[2];
                memcpy(tmp_txid, payload + 20 + 32 + 2, 2);
                printf("\nold_txid %02x %02x", old_txid[0], old_txid[1]);
                printf("\nnew_txid %02x %02x", new_txid[0], new_txid[1]);
                printf("\ntxid in TCP segment %02x %02x", tmp_txid[0], tmp_txid[1]);
                if (old_txid[0] == tmp_txid[0] && old_txid[1] == tmp_txid[1]) {
                    printf("\nNeed to replace TXID: yes");

                    unsigned char new_payload[payloadLen];
                    memcpy(new_payload, payload, payloadLen);
                    memcpy(new_payload + 20 + 32 + 2, new_txid, 2);

                    unsigned short tcp_checksum = compute_tcp_checksum(iphdr, new_payload + 20);
//                    printf("\nchecksum: %02x\n", tcp_checksum);
                    unsigned char *tcp_checksum_bytearr = malloc(2);
                    tcp_checksum_bytearr[1] = (tcp_checksum >> 8) & 0xFF;
                    tcp_checksum_bytearr[0] = tcp_checksum & 0xFF;
                    memcpy(new_payload + 20 + 16, tcp_checksum_bytearr, 2);

//                    printf("\n New payload: ");
//                    for (int i = 0; i < payloadLen; i++) {
//                        printf("%02x ", new_payload[i]);
//                    }

                    int fd;
                    if (!create_raw_socket(&fd)) {
                        printf("Failed to make raw socket to send DNS Message \n");
                        fflush(stdout);
                        ERROR();
                    }

                    int value = 1;
                    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value))) {
                        perror("Error setting IP_HDRINCL");
                        exit(-1);
                    }

                    unsigned char tcp_hdr[32];
                    memcpy(tcp_hdr, new_payload + 20, 32);
                    struct tcphdr *tcph = (struct tcphdr *) tcp_hdr;

                    struct sockaddr_in sin;
                    sin.sin_family = AF_INET;
                    sin.sin_port = htons(tcph->dest);
                    sin.sin_addr.s_addr = iphdr->daddr;

                    if (sendto(fd, new_payload, ntohs(iphdr->tot_len), 0,
                               (struct sockaddr *) &sin,
                               sizeof(sin)) < 0) {
                        perror("raw socket failed to send");
                        return false;
                    }

                    generic_close(&fd);
                    printf("\n *** Drop TCP Old TxID Segment ***");
                    return NF_DROP;

                } else {
                    printf("\nNeed to replace TXID: no");
                }
            }
            RequesterMsgStore *store;
            if (hashmap_get(requester_state, "0", sizeof("0"), (uintptr_t * ) & store)) {
                printf("\nDropping TCP-ACK...");
                return NF_DROP;
            }
        } else if (is_resolver && (((struct tcphdr *) transport_header)->syn) == 0 &&
                   (((struct tcphdr *) transport_header)->ack) == 1 &&
                   (((struct tcphdr *) transport_header)->psh) == 1) {

            if (dport == 53) {
                printf("\nTCP-ACK-PSH detected!");
                printf("\nResolver is sending query...");
                memcpy(new_txid, payload + 20 + 32 + 2, 2);
                printf("\nold_txid %02x %02x", old_txid[0], old_txid[1]);
                printf("\nnew_txid %02x %02x", new_txid[0], new_txid[1]);

                RequesterMsgStore *store;
                if (hashmap_get(requester_state, "0", sizeof("0"), (uintptr_t * ) & store)) {
                    printf("\nEmptying cache...");
                    hashmap_remove(requester_state, "0", sizeof("0"));
                    printf("\nDropping TCP-ACK-PSH...");
                    return NF_STOLEN;
                }
            }
        } else if (!is_resolver && (((struct tcphdr *) transport_header)->syn) == 0 &&
                   (((struct tcphdr *) transport_header)->ack) == 1 && have_cookie) {

            if (sport == 53 && payloadLen > 54) {
                struct tcphdr *tcph = (struct tcphdr *) transport_header;
//                printf("\ntcp seq: %u", ntohl(tcph->seq));
//                printf("\nlast data seq: %u", last_data_seq);

                if (last_data_seq < ntohl(tcph->seq)) {
                    last_data_seq = ntohl(tcph->seq);
                } else if (last_data_seq >= ntohl(tcph->seq)) {
                    printf("\nRe-transmit attempt. * Drop *");
                    return NF_DROP;
                }
            }

        }
        return NF_ACCEPT;
    }

    int rc = bytes_to_dnsmessage(pkt_content, msgSize, &msg);

    if (rc != 0) {
        printf("[Error]Failed to convert bytes to dns_message\n");
        ERROR();
    }

    if (dport != 53 && sport != 53) {
        printf("[Warning]Non-standard dns port. Likely not dns message so ignoring.\n");
        return NF_ACCEPT;
    }

    /* DNS MESSAGE IS A QUERY */
    if (is_query(msg)) {
        // If we are sending the packet, and the packet
        // is a query, then there is nothing for us to
        // do yet...

        if (saddr == our_addr && dport == 53) {
            // drop AAAA requests
            if (((msg->question_section[0])->qtype) == 28) {
                return NF_DROP;
            }

            printf("Resolver : DNS query to send\n");
            if (DEBUG) {
                dnsmessage_to_string(msg);
            }

            if (turbo_dns && ((msg->question_section[0])->qtype) == 1 && (msg->arcount) <= 1) {
                uintptr_t out;

                if (!hashmap_get(requester_state, "0", sizeof("0"), &out)) {
                    printf("Storing query in cache...\n");
                    RequesterMsgStore *store = malloc(sizeof(RequesterMsgStore));
                    clone_dnsmessage(msg, &(store->qry));
                    store->iphdr = malloc(sizeof(struct iphdr));
                    memcpy(store->iphdr, iphdr, sizeof(struct iphdr));
                    store->transport_header = malloc(sizeof(struct udphdr));
                    memcpy(store->transport_header, transport_header, sizeof(struct udphdr));
                    hashmap_set(requester_state, "0", sizeof("0"), (uintptr_t) store);
                }

                DNSMessage *tmp;
                clone_dnsmessage(msg, &tmp);
                tmp->flags = tmp->flags | (1 << 9);     // Set TC
                tmp->flags = tmp->flags | (1 << 10);    // Set AA
                tmp->flags = tmp->flags | (1 << 15);    // Set QR
                printf("Daemon : Send TC Response to bind\n");
//                if (DEBUG) {
//                    dnsmessage_to_string(tmp);
//                }

                send_dns_messsge(tmp, iphdr, transport_header, is_tcp, 1);
                return NF_DROP;
            }
            printf("* Send DNS Query *\n");
            return NF_ACCEPT;

        } else if (daddr == our_addr && dport == 53) {
            printf("Name Server : Receive DNS Query \n");
            if (DEBUG)
                dnsmessage_to_string(msg);

            if (msg->arcount == 2) {
                printf("Turbo DNS SYN Query \n");

                uintptr_t out;

                if (!hashmap_get(responder_state, "0", sizeof("0"), &out)) {
                    ResponderMsgStore *store = malloc(sizeof(ResponderMsgStore));
                    printf("Adding query to cache...\n");
                    clone_dnsmessage(msg, &(store->qry));
                    hashmap_set(responder_state, "0", sizeof("0"), (uintptr_t) store);
                    have_cookie = false;
                    last_data_seq = 0;
                }

                printf("Accept query...\n");
                return NF_ACCEPT;
            }

            return NF_ACCEPT;

        }
    }

        /* DNS MESSAGE IS A RESPONSE */
    else {
        if (daddr == our_addr && sport == 53) {
            printf("Resolver : Receive DNS Response \n");
            if (DEBUG)
                dnsmessage_to_string(msg);

            if (is_truncated(msg) && (msg->arcount) > 1) {
                printf("Turbo DNS TCP-SYN-ACK response detected...\n");

                for (int i = 0; i < msg->arcount; i++) {
                    ResourceRecord *rr1 = msg->additional_section[i];
                    if ((rr1->type) == 41) {
                        printf("\nOPT found...");
                        if (rr1->rdata[28] == 0xFD && rr1->rdata[29] == 0xE9) {
                            printf("\nTurbo DNS cookie found: ");
                            memcpy(turbo_dns_cookie, (rr1->rdata) + 32, 8);
                            for (int i = 0; i < 8; i++) {
                                printf("%02x ", turbo_dns_cookie[i]);
                            }
                            printf("\nSaving Cookie...\n");
                            have_cookie = true;
                        }
                    }
                }


                printf("Daemon: Extract and send TCP SYN-ACK to bind...\n");

                unsigned char packet_iphdr[20];
                unsigned char packet_tcphdr[40];
                memcpy(packet_iphdr, msg->additional_section[0]->rdata, 20);
                memcpy(packet_tcphdr, (msg->additional_section[0]->rdata) + 20, 40);
                struct iphdr *iph = (struct iphdr *) packet_iphdr;
                struct tcphdr *tcph = (struct tcphdr *) packet_tcphdr;

                int fd;
                if (!create_raw_socket(&fd)) {
                    printf("Failed to make raw socket to send DNS Message \n");
                    fflush(stdout);
                    ERROR();
                }

                int value = 1;
                if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value))) {
                    perror("Error setting IP_HDRINCL");
                    exit(-1);
                }

                struct sockaddr_in sin;
                sin.sin_family = AF_INET;
                sin.sin_port = htons(tcph->dest);
                sin.sin_addr.s_addr = iph->daddr;

                if (sendto(fd, msg->additional_section[0]->rdata, ntohs(iph->tot_len), 0,
                           (struct sockaddr *) &sin,
                           sizeof(sin)) < 0) {
                    perror("raw socket failed to send");
                    return false;
                }

                generic_close(&fd);
                printf("* Drop DNS Response * \n");
                return NF_DROP;
            }

            return NF_ACCEPT;

        } else if (daddr == our_addr && dport == 53) {
            printf("We should never have to process a response directed at port 53\n");
            fflush(stdout);
            ERROR();
        } else if (saddr == our_addr && sport == 53) {
            printf("* DNS Response * \n");
            if (DEBUG)
                dnsmessage_to_string(msg);

            if (is_truncated(msg) && msg->arcount <= 1) {
                printf("TC Response detected...\n");

                ResponderMsgStore *store;
                if (hashmap_get(responder_state, "0", sizeof("0"), (uintptr_t * ) & store)) {
                    printf("Turbo DNS SYN query found in cache! \n");
                    if (DEBUG)
                        dnsmessage_to_string(store->qry);

                    for (int i = 0; i < store->qry->arcount; i++) {
                        ResourceRecord *rr1 = store->qry->additional_section[i];
                        if ((rr1->type) == 41) {
                            printf("\nOPT found...");
                            if (rr1->rdsize > 28 && rr1->rdata[28] == 0xFD && rr1->rdata[29] == 0xE9) {
                                printf("\nTurbo DNS cookie found: ");
                                memcpy(store->cookie, (rr1->rdata) + 32, 8);
                                for (int i = 0; i < 8; i++) {
                                    printf("%02x ", store->cookie[i]);
                                }
                                printf("\n");
                                store->cookie_provided = true;
                            } else
                                store->cookie_provided = false;
                        }
                    }


                    printf("\nDaemon : Extract and send TCP SYN to bind...\n");

                    unsigned char packet_iphdr[20];
                    unsigned char packet_tcphdr[40];
                    memcpy(packet_iphdr, store->qry->additional_section[0]->rdata, 20);
                    memcpy(packet_tcphdr, (store->qry->additional_section[0]->rdata) + 20, 40);
                    struct iphdr *iph = (struct iphdr *) packet_iphdr;
                    struct tcphdr *tcph = (struct tcphdr *) packet_tcphdr;

                    int fd;
                    if (!create_raw_socket(&fd)) {
                        printf("Failed to make raw socket to send DNS Message \n");
                        fflush(stdout);
                        ERROR();
                    }

                    int value = 1;
                    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value))) {
                        perror("Error setting IP_HDRINCL");
                        exit(-1);
                    }

                    struct sockaddr_in sin;
                    sin.sin_family = AF_INET;
                    sin.sin_port = htons(tcph->dest);
                    sin.sin_addr.s_addr = iph->daddr;

                    if (sendto(fd, store->qry->additional_section[0]->rdata, ntohs(iph->tot_len), 0,
                               (struct sockaddr *) &sin,
                               sizeof(sin)) < 0) {
                        perror("raw socket failed to send");
                        return false;
                    }

                    generic_close(&fd);
                    printf("Adding response to cache...\n");
                    clone_dnsmessage(msg, &(store->resp));
                    store->iphdr = malloc(sizeof(struct iphdr));
                    memcpy(store->iphdr, iphdr, sizeof(struct iphdr));
                    store->transport_header = malloc(sizeof(struct udphdr));
                    memcpy(store->transport_header, transport_header, sizeof(struct udphdr));
                    hashmap_set(responder_state, "0", sizeof("0"), (uintptr_t) store);
                    printf("* Drop DNS Response * \n");
                    return NF_DROP;
                }
            }

            return NF_ACCEPT;
        } else {
            printf("Fell through...\n");
            ERROR();
        }
    }
    return NF_ACCEPT;
}

uint32_t process_tcp(struct nfq_q_handle *qh, uint32_t id, struct iphdr *ipv4hdr,
                     unsigned char *payload, size_t payloadLen) {
    struct tcphdr *tcphdr =
            (struct tcphdr *) ((char *) payload + sizeof(*ipv4hdr));
//    uint16_t src_port = ntohs(tcphdr->source);
//    uint16_t dst_port = ntohs(tcphdr->dest);

    return process_dns_message(qh, id, payload, payloadLen, ipv4hdr, tcphdr,
                               true, BYPASS);
}

uint32_t process_udp(struct nfq_q_handle *qh, uint32_t id, struct iphdr *ipv4hdr,
                     unsigned char *payload, size_t payloadLen) {
    struct udphdr *udphdr =
            (struct udphdr *) ((char *) payload + sizeof(*ipv4hdr));
//    uint16_t src_port = ntohs(udphdr->source);
//    uint16_t dst_port = ntohs(udphdr->dest);

    return process_dns_message(qh, id, payload, payloadLen, ipv4hdr, udphdr,
                               false, BYPASS);
}

uint32_t process_packet(struct nfq_q_handle *qh, struct nfq_data *data,
                        uint32_t **verdict) {
    // For the sake of testing getting this to work in docker containers
    // this is just going to print packet header info if it's a packet
    // addressed to this machine

    size_t payloadLen = 0;
    unsigned char *payload = NULL;
    struct iphdr *ipv4hdr;
//    struct icmphdr *icmphdr;
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    payloadLen = nfq_get_payload(data, &payload);
    ipv4hdr = (struct iphdr *) payload;
    ph = nfq_get_msg_packet_hdr(data);
    id = ntohl(ph->packet_id);

    uint32_t dst_ip = ipv4hdr->daddr;
    uint32_t src_ip = ipv4hdr->saddr;
    uint32_t res;
    if (dst_ip == our_addr || src_ip == our_addr) {
        if (ipv4hdr->protocol == IPPROTO_TCP) {
            res = process_tcp(qh, id, ipv4hdr, payload, payloadLen);
        } else if (ipv4hdr->protocol == IPPROTO_UDP) {
            res = process_udp(qh, id, ipv4hdr, payload, payloadLen);
        } else if (ipv4hdr->protocol == IPPROTO_ICMP) {
//            icmphdr = (struct icmphdr *) ((char *) payload + sizeof(*ipv4hdr));
        } else {
            res = NF_ACCEPT;
        }
    } else if (ipv4hdr->protocol == IPPROTO_UDP) {
//        struct udphdr *udphdr =
//                (struct udphdr *) ((char *) payload + sizeof(*ipv4hdr));
//        uint16_t src_port = ntohs(udphdr->source);
//        uint16_t dst_port = ntohs(udphdr->dest);
        res = NF_DROP;
    } else {
        if (ipv4hdr->protocol == IPPROTO_ICMP) {
//            icmphdr = (struct icmphdr *) ((char *) payload + sizeof(*ipv4hdr));
            res = NF_DROP;
        } else {
            res = NF_ACCEPT;
        }
    }
    **verdict = res;
    if (res == 0xFFFF) {
        return 0;
    }

    return id;

}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa,
              void *data) {
    uint32_t verdict;
    uint32_t *verdict_p = &verdict;
    uint32_t id = process_packet(qh, nfa, &verdict_p);
    if (*verdict_p == 0xFFFF) {
        return 0;
    }

    verdict = *verdict_p;
    if (verdict == NF_DROP) {
        //printf("dropping packet\n");
        //fflush(stdout);
    }

    if (verdict == NF_ACCEPT) {
        //printf("accepting packet\n");
        //fflush(stdout);
    }

    if (nfq_set_verdict(qh, id, verdict, 0, NULL) < 0) {
        printf("Verdict error\n");
        fflush(stdout);
        exit(-1);
    }

    return 0;
}

int get_addr(char *ipaddr) {
    inet_pton(AF_INET, ipaddr, &our_addr);
    return 0;
}

void free_key(void *key, size_t ksize, uintptr_t value, void *usr) {
    free(key);
}

void refresh_shared_map(shared_map **map) {
    if (map == NULL)
        return;
    shared_map *m = *map;
    if (m != NULL) {
        sem_wait(&(m->lock));
        hashmap_iterate(m->map, free_key, NULL);
        hashmap_free(m->map);
        m->map = hashmap_create();
        sem_post(&(m->lock));
    } else {
        init_shared_map(m);
    }

    *map = m;
}

void refresh_hashmap(hashmap **map) {
    if (map == NULL)
        return;
    hashmap *m = *map;
    if (m != NULL) {
        hashmap_iterate(m, free_key, NULL);
        hashmap_free(m);
    }

    m = hashmap_create();
    *map = m;
}

void refresh_state(void) {
    shared_map *rcp;
    shared_map *cip;
    rcp = &responder_cache;
    cip = &connection_info;
    refresh_shared_map(&rcp);
    refresh_shared_map(&cip);
    refresh_hashmap(&requester_state);
    refresh_hashmap(&responder_state);
}

int main(int argc, char **argv) {
    turbo_dns_cookie = malloc(cookie_size);
    char *ipaddr;
    if (argc < 2 || argc > 9) {
        printf("\nWrong number of arguments: %d\n", argc);
        return -1;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--is_resolver") == 0) {
            printf("Is a resolver\n");
            is_resolver = true;
        } else if (strcmp(argv[i], "--bypass") == 0) {
//            printf("bypassing daemon\n");
            BYPASS = true;
        } else if (strcmp(argv[i], "--maxudp") == 0) {
            i++;
            MAXUDP = atoi(argv[i]);
            printf("Using maxudp: %u\n", MAXUDP);
        } else if (strcmp(argv[i], "--algorithm") == 0) {
            i++;
            printf("Using algorithm: %s\n", argv[i]);
        } else {
            ipaddr = argv[i];
        }
    }

    printf("Starting daemon...\n");
    size_t buff_size = 0xffff;
    char buf[buff_size];
    int fd;
    /*get this machine's ip address from ioctl */
    if (get_addr(ipaddr) != 0)
        return -1;
    /*Create and initialize handle for netfilter_queue */
    struct nfq_handle *h = nfq_open();
    init_shared_map(&responder_cache);
    init_shared_map(&connection_info);
    requester_state = hashmap_create();
    responder_state = hashmap_create();

    if (!h) {
        printf("Failed getting h\n");
        return -1;
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        printf("Failed to bind\n");
        return -1;
    }

    struct nfq_q_handle *qh;
    qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh) {
        printf("Failed to make queue\n");
        return -1;
    }

    if ((nfq_set_mode(qh, NFQNL_COPY_PACKET, buff_size)) == -1) {
        printf("Failed to tune queue\n");
        return -1;
    }

    fd = nfq_fd(h);
    printf("Listening...\n");
    fflush(stdout);
    for (;;) {
        int rv;
        struct pollfd ufd;
        memset(&ufd, 0, sizeof(struct pollfd));
        ufd.fd = fd;
        ufd.events = POLLIN;
        rv = poll(&ufd, 1, 0);    // If we time out, then reset hashtable?
        if (rv < 0) {
            printf("Failed to poll nfq\n");
            return -1;
        } else if (rv == 0) {
            // Timed out
        } else {
            rv = recv(fd, buf, sizeof(buf), 0);
            if (rv < 0) {
                printf("failed to receive a thing\n");
                return -1;
            }
            nfq_handle_packet(h, buf, rv);
        }
    }
}
