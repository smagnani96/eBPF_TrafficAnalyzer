/**
 * eBPF C program to be dynamically injected in the kernel.
 * The aim of this program is to extract some info concerning many packets passing through the interface in order to prevent a possible attack.
 * By now the following protocols are checked:
 *  - TCP
 *  - UDP
 *
 * VERSION: 1.0
 */

/*Protocol types according to the standard*/
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Number of max TCP session tracked */
#define N_SESSION 10000
#define SESSION_DROP_AFTER_TIME 30000000000

/*Features to be exported*/
struct features {
    //Real features
    uint64_t n_packets;                             // Number of Ingress packets
    uint64_t n_packets_reverse;                     // Number of Egress packets
    uint64_t n_bits;                                // Total Ingress bits
    uint64_t n_bits_reverse;                        // Total Egress bits
    uint64_t start_timestamp;                       // Connection begin timestamp
    uint64_t alive_timestamp;                       // Last message received timestamp
    uint32_t  method;                               // The method used to determine the server (4 byte to avoid misreading)
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

/*Tracked session map*/
BPF_TABLE("percpu_hash", struct session_key, struct features, SESSIONS_TRACKED_CRYPTO, N_SESSION);

/*Method to determine which member of the communication is the server*/
static __always_inline __be32 heuristic_server_tcp(struct iphdr *ip, struct tcphdr *tcp, uint32_t *method) {
  /*If Syn, then srcIp is the server*/
  if(tcp->syn) {/*If source port < 1024, then srcIp is the server*/
    *method = 1;
    return tcp->ack? ip->saddr : ip->daddr;
  }

  uint16_t dst_port = bpf_htons(tcp->dest);
  /*If destination port < 1024, then dstIp is the server*/
  if(dst_port < 1024) {
    *method = 2;
    return ip->daddr;
  }

  uint16_t src_port = bpf_htons(tcp->source);
  /*If source port < 1024, then srcIp is the server*/
  if(src_port < 1024) {
    *method = 2;
    return ip->saddr;
  }

  *method = 3;
  /*Otherwise, the lowest port is the server*/
  return dst_port < src_port ? ip->daddr : ip->saddr;
}

static __always_inline __be32 heuristic_server_udp(struct iphdr *ip, struct udphdr *udp, uint32_t *method) {
  /*If destination port < 1024, then dstIp is the server*/
  uint16_t dst_port = bpf_htons(udp->dest);
  if(dst_port < 1024) {
    *method = 2;
    return ip->daddr;
  }

  uint16_t src_port = bpf_htons(udp->source);
  /*If source port < 1024, then srcIp is the server*/
  if(src_port < 1024) {
    *method = 2;
    return ip->saddr;
  }

  *method = 3;
  /*Otherwise, the lowest port is the server*/
  return dst_port < src_port ? ip->daddr : ip->saddr;
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

      struct session_key key = {.saddr=ip->saddr, .daddr= ip->daddr, .sport=tcp->source, .dport=tcp->dest, .proto=ip->protocol};
      /*Checking if packed is already timestamped, otherwise get it from kernel bpf function*/
      uint64_t curr_time = pcn_get_time_epoch();
      uint16_t pkt_len = bpf_ntohs(ip->tot_len);

      /*Check if match normal key*/
      struct features *value = SESSIONS_TRACKED_CRYPTO.lookup(&key);
      if (value) {
        pcn_log(ctx, LOG_DEBUG, "TCP matched normal key");
        /*Check if the entry was too old => overwrite it*/
        if(curr_time - value->alive_timestamp > SESSION_DROP_AFTER_TIME) {
          pcn_log(ctx, LOG_DEBUG, "TCP Session overwritten with normal key");
          uint32_t method;
          __be32 server = heuristic_server_tcp(ip, tcp, &method);
          struct features new_val = {.n_packets=1, .n_bits=pkt_len, .start_timestamp=curr_time, .alive_timestamp=curr_time, .server_ip=server, .method=method};  
          SESSIONS_TRACKED_CRYPTO.update(&key, &new_val);
          break;
        } 
        /*Update current session*/
        value->n_packets += 1;
        value->n_bits += pkt_len;
        value->alive_timestamp = curr_time;
        break;
      }

      /*Check if match reverse key*/
      struct session_key reverse_key = {.saddr=ip->daddr, .daddr= ip->saddr, .sport=tcp->dest, .dport=tcp->source, .proto=ip->protocol};
      value = SESSIONS_TRACKED_CRYPTO.lookup(&reverse_key);
 
      if(value) {
        pcn_log(ctx, LOG_DEBUG, "TCP matched reverse_key");
        /*Check if the entry was too old => overwrite it*/
        if(curr_time - value->alive_timestamp > SESSION_DROP_AFTER_TIME) {
          pcn_log(ctx, LOG_DEBUG, "TCP Session overwritten with reverse_key");
          uint32_t method;
          __be32 server = heuristic_server_tcp(ip, tcp, &method);
          struct features new_val = {.n_packets_reverse=1, .n_bits_reverse=pkt_len, .start_timestamp=curr_time, .alive_timestamp=curr_time, .server_ip=server, .method=method};  
          SESSIONS_TRACKED_CRYPTO.update(&reverse_key, &new_val);
          break;
        } 
        /*Update current session*/
        value->n_packets_reverse += 1;
        value->n_bits_reverse += pkt_len;
        value->alive_timestamp = curr_time;
        break;
      }

      /*Insert new one with normal key*/
      pcn_log(ctx, LOG_DEBUG, "TCP New session");
      uint32_t method;
      __be32 server = heuristic_server_tcp(ip, tcp, &method);
      struct features new_val = {.n_packets=1, .n_bits=pkt_len, .start_timestamp=curr_time, .alive_timestamp=curr_time, .server_ip=server, .method=method};  
      SESSIONS_TRACKED_CRYPTO.insert(&key, &new_val);
      break;
    }
    case IPPROTO_UDP: {
      /*Parsing L4 UDP*/
      struct udphdr *udp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) udp + sizeof(*udp) > data_end) {
        return RX_OK;
      }

      struct session_key key = {.saddr=ip->saddr, .daddr= ip->daddr, .sport=udp->source, .dport=udp->dest, .proto=ip->protocol};
      /*Checking if packed is already timestamped, otherwise get it from kernel bpf function*/
      uint64_t curr_time = pcn_get_time_epoch();
      uint16_t pkt_len = bpf_ntohs(ip->tot_len);

      /*Check if match normal key*/
      struct features *value = SESSIONS_TRACKED_CRYPTO.lookup(&key);
      if (value) {
        /*Check if the entry was too old => overwrite it*/
        if(curr_time - value->alive_timestamp > SESSION_DROP_AFTER_TIME) {
          pcn_log(ctx, LOG_DEBUG, "UDP Session overwritten with normal key");
          uint32_t method;
          __be32 server = heuristic_server_udp(ip, udp, &method);
          struct features new_val = {.n_packets=1, .n_bits=pkt_len, .start_timestamp=curr_time, .alive_timestamp=curr_time, .server_ip=server, .method=method};  
          SESSIONS_TRACKED_CRYPTO.update(&key, &new_val);
          break;
        }
        /*Update current session*/
        value->n_packets += 1;
        value->n_bits += pkt_len;
        value->alive_timestamp = curr_time;
        pcn_log(ctx, LOG_DEBUG, "UDP Session updated with normal key");
        break;
      }

      /*Check if match reverse key*/
      struct session_key reverse_key = {.saddr=ip->daddr, .daddr= ip->saddr, .sport=udp->dest, .dport=udp->source, .proto=ip->protocol};
      value = SESSIONS_TRACKED_CRYPTO.lookup(&reverse_key);
      if (value) {
        /*Check if the entry was too old => overwrite it*/
        if(curr_time - value->alive_timestamp > SESSION_DROP_AFTER_TIME) {
          pcn_log(ctx, LOG_DEBUG, "UDP Session overwritten with reverse_key");
          uint32_t method;
          __be32 server = heuristic_server_udp(ip, udp, &method);
          struct features new_val = {.n_packets_reverse=1, .n_bits_reverse=pkt_len, .start_timestamp=curr_time, .alive_timestamp=curr_time, .server_ip=server, .method=method};  
          SESSIONS_TRACKED_CRYPTO.update(&reverse_key, &new_val);
          break;
        }
        /*Update current session*/
        value->n_packets_reverse += 1;
        value->n_bits_reverse += pkt_len;
        value->alive_timestamp = curr_time;
        pcn_log(ctx, LOG_DEBUG, "UDP Session updated with normal key");
        break;
      } 

      /*Insert new one with normal key*/
      pcn_log(ctx, LOG_DEBUG, "UDP New session");
      uint32_t method;
      __be32 server = heuristic_server_udp(ip, udp, &method);
      struct features new_val = {.n_packets=1, .n_bits=pkt_len, .start_timestamp=curr_time, .alive_timestamp=curr_time, .server_ip=server, .method=method};  
      SESSIONS_TRACKED_CRYPTO.insert(&key, &new_val);
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
