/**
 * eBPF C program to be dynamically injected in the kernel.
 * The aim of this program is to extract some info concerning many packets passing through the interface in order to prevent a possible attack.
 * By now the following protocols are checked:
 *  - TCP
 *  - UDP
 */

/*Protocol types according to the standard*/
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Number of max TCP session tracked */
#define N_SESSION 10
#define SESSION_DROP_AFTER_TIME 30000000000

/*Features to be exported*/
struct features {
    //Real features
    uint64_t n_packets_server;                      // Number of packets from server
    uint64_t n_packets_client;                      // Number of packets from client
    uint64_t n_bits_server;                         // Total bits from server
    uint64_t n_bits_client;                         // Total bits from client
    uint64_t start_timestamp;                       // Connection begin timestamp
    uint64_t alive_timestamp;                       // Last message received timestamp
    uint8_t  method;                                // The method used to determine the server
    __be32 server_ip;                               // The server address
} __attribute__((packed));

/*Session identifier*/
struct session_key {
    __be32 saddr;                                   //IP source address
    __be32 daddr;                                   //IP dest address
    __be16 sport;                                   //Source port
    __be16 dport;                                   //Dest port
    __u8   proto;                                   //Protocol ID
} __attribute__((packed));

/*Ethernet Header => https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h (slightly different)*/
struct eth_hdr {
    __be64 dst: 48;
    __be64 src: 48;
    __be16 proto;
} __attribute__((packed));

/*Ip Header => https://github.com/torvalds/linux/blob/master/include/uapi/linux/ip.h */
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,
        version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
        ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
    /*The options start here. */
} __attribute__((packed));

/*TCP Header => https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h */
struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16   res1:4,
        doff:4,
        fin:1,
        syn:1,
        rst:1,
        psh:1,
        ack:1,
        urg:1,
        ece:1,
        cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16   doff:4,
        res1:4,
        cwr:1,
        ece:1,
        urg:1,
        ack:1,
        psh:1,
        rst:1,
        syn:1,
        fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
} __attribute__((packed));

/*UDP Header https://github.com/torvalds/linux/blob/master/include/uapi/linux/udp.h */
struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
} __attribute__((packed));

/*Tracked session LRU map*/
BPF_TABLE("extern", struct session_key, struct features, SESSIONS_TRACKED_CRYPTO, N_SESSION);

/*Method to determine which member of the communication is the server*/
static __always_inline __be32 heuristic_server_tcp(struct iphdr *ip, struct tcphdr *tcp, uint64_t curr_time, uint8_t *method) {
  /*If receive Syn, then srcIp is the server*/
  if(tcp->syn) {
    *method = 1;
    return ip->saddr;
  }

  /*If destination port < 1024, then dstIp is the server*/
  if(tcp->dest < 1024) {
    *method = 2;
    return ip->daddr;
  }

  if(tcp->source < 1024) {
    *method = 2;
    return ip->saddr;
  }

  *method = 3;
  /*Otherwise, randomly pick*/
  return curr_time % 2 ? ip->saddr : ip->daddr;
}

static __always_inline __be32 heuristic_server_udp(struct iphdr *ip, struct udphdr *udp, uint64_t curr_time, uint8_t *method) {
  /*If destination port < 1024, then dstIp is the server*/
  if(udp->dest < 1024) {
    *method = 2;
    return ip->daddr;
  }

  if(udp->source < 1024) {
    *method = 2;
    return ip->saddr;
  }


  *method = 3;
  /*Otherwise, randomly pick*/
  return curr_time % 2 ? ip->saddr : ip->daddr;
}

/*Method to add a new session in the map*/
static __always_inline void insert_new_session(__be32 server, uint64_t curr_time, uint16_t pkt_len, bool is_server, struct session_key *key, uint8_t method) {
  if(is_server) {
    struct features new_val = {.n_packets_server=1, .n_bits_server=pkt_len, .start_timestamp=curr_time, .alive_timestamp=curr_time, .server_ip=server, .method=method};  
    SESSIONS_TRACKED_CRYPTO.insert(key, &new_val);
  } else {
    struct features new_val = {.n_packets_client=1, .n_bits_client=pkt_len, .start_timestamp=curr_time, .alive_timestamp=curr_time, .server_ip=server, .method=method};
    SESSIONS_TRACKED_CRYPTO.insert(key, &new_val);
  }
}

static __always_inline void update_expired_session(__be32 server, uint64_t curr_time, uint16_t pkt_len, bool is_server, struct session_key *key, uint8_t method) {
  if(is_server) {
    struct features new_val = {.n_packets_server=1, .n_bits_server=pkt_len, .start_timestamp=curr_time, .alive_timestamp=curr_time, .server_ip=server, .method=method};  
    SESSIONS_TRACKED_CRYPTO.update(key, &new_val);
  } else {
    struct features new_val = {.n_packets_client=1, .n_bits_client=pkt_len, .start_timestamp=curr_time, .alive_timestamp=curr_time, .server_ip=server, .method=method};
    SESSIONS_TRACKED_CRYPTO.update(key, &new_val);
  }
}

static __always_inline void update_session(struct features *value, uint16_t pkt_len, uint64_t curr_time, bool is_server) {
  if(is_server) {
    value->n_packets_server += 1;
    value->n_bits_server += pkt_len;
  } else {
    value->n_packets_client += 1;
    value->n_bits_client += pkt_len;
  }
  value->alive_timestamp = curr_time;
}

static __always_inline int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  void *data = (void *) (long) ctx->data;
  void *data_end = (void *) (long) ctx->data_end;

  /*Parsing L2*/
  struct eth_hdr *ethernet = data;
  if (data + sizeof(*ethernet) > data_end)
    return RX_OK;

  if (ethernet->proto != bpf_htons(ETH_P_IP))
    return RX_OK;

  /*Parsing L3*/
  struct iphdr *ip = data + sizeof(struct eth_hdr);
  if (data + sizeof(struct eth_hdr) + sizeof(*ip) > data_end)
    return RX_OK;
  if ((int) ip->version != 4)
    return RX_OK;

  /*Calculating ip header length
   * value to multiply by 4 (SHL 2)
   *e.g. ip->ihl = 5 ; TCP Header starts at = 5 x 4 byte = 20 byte */
  uint8_t ip_header_len = ip->ihl << 2;

  switch (ip->protocol) {
    case IPPROTO_TCP: {
      /*Parsing L4 TCP*/
      struct tcphdr *tcp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) tcp + sizeof(*tcp) > data_end)
        return RX_OK;

      struct session_key key = {.saddr=ip->daddr, .daddr= ip->saddr, .sport=tcp->dest, .dport=tcp->source, .proto=ip->protocol};
      /*Checking if packed is already timestamped, otherwise get it from kernel bpf function*/
      uint64_t curr_time = ctx->tstamp == 0? bpf_ktime_get_ns() : ctx->tstamp;
      uint16_t pkt_len = bpf_ntohs(ip->tot_len);

      /*Check if new session*/
      struct features *value = SESSIONS_TRACKED_CRYPTO.lookup(&key);
      if (!value) {
        uint8_t method;
        __be32 server = heuristic_server_tcp(ip, tcp, curr_time, &method);
        insert_new_session(server, curr_time, pkt_len, server==ip->saddr, &key, method);
        break;
      }

      /*Check if the entry was too old => overwrite it*/
      if(curr_time - value->alive_timestamp > SESSION_DROP_AFTER_TIME) {
        uint8_t method;
        __be32 server = heuristic_server_tcp(ip, tcp, curr_time, &method);
        update_expired_session(server, curr_time, pkt_len, server==ip->saddr, &key, method);
        break;
      } 

      /*Update current session*/
      update_session(value, pkt_len, curr_time, value->server_ip==ip->saddr);
      break;
    }
    case IPPROTO_UDP: {
      /*Parsing L4 UDP*/
      struct udphdr *udp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) udp + sizeof(*udp) > data_end) {
        return RX_OK;
      }

      struct session_key key = {.saddr=ip->daddr, .daddr= ip->saddr, .sport=udp->dest, .dport=udp->source, .proto=ip->protocol};
      /*Checking if packed is already timestamped, otherwise get it from kernel bpf function*/
      uint64_t curr_time = ctx->tstamp == 0? bpf_ktime_get_ns() : ctx->tstamp;
      uint16_t pkt_len = bpf_ntohs(ip->tot_len);

      /*Check if new session*/
      struct features *value = SESSIONS_TRACKED_CRYPTO.lookup(&key);
      if (!value) {
        uint8_t method;
        __be32 server = heuristic_server_udp(ip, udp, curr_time, &method);
        insert_new_session(server, curr_time, pkt_len, server==ip->saddr, &key, method);
        break;
      }

      /*Check if the entry was too old => overwrite it*/
      if(curr_time - value->alive_timestamp > SESSION_DROP_AFTER_TIME) {
        uint8_t method;
        __be32 server = heuristic_server_udp(ip, udp, curr_time, &method);
        update_expired_session(server, curr_time, pkt_len, server==ip->saddr, &key, method);
        break;
      } 

      /*Update current session*/
      update_session(value, pkt_len, curr_time, value->server_ip==ip->saddr);
      break;
    }
    /*Ignored protocol*/
    default : {
      return RX_OK;
    }
  }

  /* Here operations after the capture */
  return RX_OK;
}