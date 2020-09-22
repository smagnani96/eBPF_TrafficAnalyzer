/**
 * eBPF C program to be dynamically injected in the kernel.
 * The aim of this program is to extract some info concerning many packets passing through the interface in order to prevent a possible attack.
 * By now the following protocols are checked:
 *  - TCP
 *  - UDP
 *  - ICMP
 *
 * VERSION: 1.0
 */

/*Protocol types according to the standard*/
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

/*Own control variables*/
#define N_SESSION                   100             // Number of max TCP session tracked
#define N_PACKET_PER_SESSION        100             // Number of packet from the same TCP session
#define N_PACKET_TOTAL \
    N_SESSION * N_PACKET_PER_SESSION                // Number of max packet captured (Size of PACKET_BUFFER)

/*Session identifier*/
struct session_key {
    __be32 saddr;                                   //IP source address
    __be32 daddr;                                   //IP dest address
    __be16 sport;                                   //Source port (if ICMP = 0)
    __be16 dport;                                   //Dest port (if ICMP = 0)
    __u8   proto;                                   //Protocol ID
} __attribute__((packed));

/*Session value*/
struct session_value {
  __be32 server_ip;                                 //The server IP
  uint64_t n_packets;                               //The number of packet captured so far
} __attribute__((packed));

/*Features to be exported*/
struct features {
    struct session_key id;                          //Session identifier
    __be32 server_ip;                               //The server IP
    uint64_t timestamp;                             //Packet timestamp
    uint16_t length;                                //IP length value
    uint16_t ipFlagsFrag;                           //IP flags
    uint16_t tcpLen;                                //TCP payload length
    uint32_t tcpAck;                                //TCP ack n°
    uint8_t tcpFlags;                               //TCP flags
    uint16_t tcpWin;                                //TCP window value
    uint8_t udpSize;                                //UDP payload length
    uint8_t icmpType;                               //ICMP operation type
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

/*ICMP Header https://github.com/torvalds/linux/blob/master/include/uapi/linux/icmp.h*/
struct icmphdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct {
            __be16 __unused;
            __be16 mtu;
        } frag;
        __u8 reserved[4];
    } un;
} __attribute__((packed));

/*Structure shared between Control Plane - Data Plane*/
BPF_QUEUESTACK_SHARED("queue",PACKET_BUFFER_DDOS, struct features, N_PACKET_TOTAL, 0);

/*Tracked session map*/
BPF_TABLE_SHARED("hash", struct session_key, struct session_value, SESSIONS_TRACKED_DDOS, N_SESSION);

/*Method to determine which member of the communication is the server*/
static __always_inline __be32 heuristic_server_tcp(struct iphdr *ip, struct tcphdr *tcp) {
  /*If Syn, then srcIp is the server*/
  if(tcp->syn) {/*If source port < 1024, then srcIp is the server*/
    return tcp->ack? ip->saddr : ip->daddr;
  }
  uint16_t dst_port = bpf_htons(tcp->dest);
  /*If destination port < 1024, then dstIp is the server*/
  if(dst_port < 1024) {
    return ip->daddr;
  }
  uint16_t src_port = bpf_htons(tcp->source);
  /*If source port < 1024, then srcIp is the server*/
  if(src_port < 1024) {
    return ip->saddr;
  }
  /*Otherwise, the lowest port is the server*/
  return dst_port < src_port ? ip->daddr : ip->saddr;
}

static __always_inline __be32 heuristic_server_udp(struct iphdr *ip, struct udphdr *udp) {
  /*If destination port < 1024, then dstIp is the server*/
  uint16_t dst_port = bpf_htons(udp->dest);
  if(dst_port < 1024) {
    return ip->daddr;
  }
  uint16_t src_port = bpf_htons(udp->source);
  /*If source port < 1024, then srcIp is the server*/
  if(src_port < 1024) {
    return ip->saddr;
  }
  /*Otherwise, the lowest port is the server*/
  return dst_port < src_port ? ip->daddr : ip->saddr;
}

/*Default function called at each packet on interface*/
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

  /*Checking for considered protocols*/
  if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_ICMP) {
    return RX_OK;
  }

  /*Calculating ip header length
   * value to multiply by 4 (SHL 2)
   *e.g. ip->ihl = 5 ; TCP Header starts at = 5 x 4 byte = 20 byte */
  uint8_t ip_header_len = ip->ihl << 2;
  
  /*Checking if packed is already timestamped, otherwise get it from kernel bpf function*/
  uint64_t curr_time = pcn_get_time_epoch();
  struct session_value zero = {0};

  switch (ip->protocol) {
    case IPPROTO_TCP: {
      /*Parsing L4 TCP*/
      struct tcphdr *tcp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) tcp + sizeof(*tcp) > data_end) {
        return RX_OK;
      }
      /*Check if it is already tracked or try to track it*/
      struct session_key key = {.saddr=ip->saddr, .daddr=ip->daddr, .sport=tcp->source, .dport=tcp->dest, .proto=ip->protocol};
      struct session_value *value = SESSIONS_TRACKED_DDOS.lookup_or_try_init(&key, &zero);
      if(!value) {
        break;
      }

      /*Check if max packet reached*/
      if(value->n_packets == N_PACKET_PER_SESSION){
        break;
      } else if(value->n_packets == 0){
        value->server_ip = heuristic_server_tcp(ip, tcp);
      }
      value->n_packets +=1;

      /*Now I'm sure to take the packet*/
      uint16_t len = bpf_ntohs(ip->tot_len);
      struct features new_features = {.id=key, .server_ip=value->server_ip, .length=len, .timestamp=curr_time, .ipFlagsFrag=bpf_ntohs(ip->frag_off),
        .tcpAck=tcp->ack_seq, .tcpWin=bpf_ntohs(tcp->window), .tcpLen=(uint16_t)(len - ip_header_len - sizeof(*tcp)), 
        .tcpFlags=(tcp->cwr << 7) | (tcp->ece << 6) | (tcp->urg << 5) | (tcp->ack << 4)
                | (tcp->psh << 3)| (tcp->rst << 2) | (tcp->syn << 1) | tcp->fin};
      
      /*Try to push those features into PACKET_BUFFER*/
      PACKET_BUFFER_DDOS.push(&new_features, 0);
      break;
    }
    case IPPROTO_ICMP: {
      /*Parsing L4 ICMP*/
      struct icmphdr *icmp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) icmp + sizeof(*icmp) > data_end) {
        return RX_OK;
      }

      /*Check if it is already tracked or try to track it*/
      struct session_key key = {.saddr=ip->saddr, .daddr=ip->daddr, .sport=0, .dport=0, .proto=ip->protocol};
      struct session_value *value = SESSIONS_TRACKED_DDOS.lookup_or_try_init(&key, &zero);
      if(!value) {
        break;
      }

      /*Check if max packet reached*/
      if(value->n_packets == N_PACKET_PER_SESSION){
        break;
      } else if(value->n_packets == 0){
        value->server_ip = ip->daddr;
      }
      value->n_packets +=1;

      /*Now I'm sure to take the packet*/
      struct features new_features = {.id=key, .server_ip=value->server_ip, .length=bpf_ntohs(ip->tot_len), .icmpType=icmp->type,
        .timestamp=curr_time, .ipFlagsFrag=bpf_ntohs(ip->frag_off)};
      
      /*Try to push those features into PACKET_BUFFER*/
      PACKET_BUFFER_DDOS.push(&new_features, 0);
      break;
    }
    case IPPROTO_UDP: {
      /*Parsing L4 UDP*/
      struct udphdr *udp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) udp + sizeof(*udp) > data_end) {
        return RX_OK;
      }

      struct session_key key = {.saddr=ip->saddr, .daddr=ip->daddr, .sport=udp->source, .dport=udp->dest, .proto=ip->protocol};
      /*Check if it is already tracked or try to track it*/
      struct session_value *value = SESSIONS_TRACKED_DDOS.lookup_or_try_init(&key, &zero);
      if(!value) {
        break;
      }

      /*Check if max packet reached*/
      if(value->n_packets == N_PACKET_PER_SESSION){
        break;
      } else if(value->n_packets == 0){
        value->server_ip = heuristic_server_udp(ip, udp);
      }
      value->n_packets +=1;

      /*Now I'm sure to take the packet*/
      struct features new_features = {.id=key, .server_ip=value->server_ip, .length=bpf_ntohs(ip->tot_len), .udpSize=bpf_ntohs(udp->len) - sizeof(*udp),
        .timestamp=curr_time, .ipFlagsFrag=bpf_ntohs(ip->frag_off)};
      
      /*Try to push those features into PACKET_BUFFER*/
      PACKET_BUFFER_DDOS.push(&new_features, 0);
      break;
    }
    /*Should never reach this code since already checked*/
    default : {
      return RX_OK;
    }
  }

  /* pcn_log(ctx, LOG_TRACE, "Successfully captured packet") */
  return RX_OK;
}