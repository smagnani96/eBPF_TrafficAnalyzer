/**
 * eBPF C program to be dynamically injected in the kernel.
 * The aim of this program is to extract some info concerning many packets passing through the interface in order to prevent a possible attack.
 * By now the following protocols are checked:
 *  - TCP
 *  - UDP
 *  - ICMP
 */

/*Protocol types according to the standard*/
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

/*Own control variables*/
#define N_SESSION                   10              // Number of max TCP session tracked
#define N_PACKET_PER_SESSION        10              // Number of packet from the same TCP session
#define N_PACKET_TOTAL \
    N_SESSION * N_PACKET_PER_SESSION                // Number of max packet captured (Size of PACKET_BUFFER)
#define SESSION_ACCEPT_RESTART_TIME 5000000000      // Seconds to wait before accepting new sessions
#define SESSION_PACKET_RESTART_TIME 1000000000      // Seconds to wait before restarting to track packets from an already tracked session
#define BUFFER_PACKET_RESTART_TIME  1000000000      // Seconds to wait before resetting the buffer (5 seconds)

/*Features to be exported*/
struct features {
    //Needed to identify the session
    uint32_t srcIp;                                 // IP source 
    uint32_t dstIp;                                 // IP dest 
    uint16_t srcPort;                               // Source port in little endian (if ICMP = 0)
    uint16_t dstPort;                               // Dest port in little endian (if ICMP = 0)
    uint8_t protocol;                               // Protocol ID
    //Real features
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
  uint64_t last_ins_tstamp;                         // Timestamp of last packet inserted for that session
  uint32_t n_packets;                               // Total number of packet stored for that session since reset
} __attribute__((packed));

/*Structure containing info about capture*/
struct capture_info {
    unsigned int next_index;                        // The nex position in the PACKET_BUFFER to insert the packet
    unsigned int n_session_tracking;                // Number of actual tracked sessions
    uint64_t last_session_ins_tstamp;               // Timestamp of the last session inserted
    uint64_t last_packet_ins_tstamp;                // Timestamp of the last packet inserted
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

/*Structures shared between Control Plane - Data Plane*/
BPF_ARRAY(CAPTURE_INFO, struct capture_info, 1);
BPF_ARRAY(PACKET_BUFFER, struct features, N_PACKET_TOTAL);
/*Tracked session LRU map*/
BPF_TABLE("lru_hash", struct session_key, struct session_value, SESSIONS_TRACKED, N_SESSION);

/*Utility function to check if a session is already tracked and can take the current packet into account. If it is not tracked, try to do it.*/
static __always_inline int check_or_try_add_session(struct session_key *key, struct capture_info *cinfo, uint64_t curr_time) {
  struct session_value *value = SESSIONS_TRACKED.lookup(key);
  if (!value) {
    /*Check if I can accept new sessions*/
    if(cinfo->n_session_tracking == N_SESSION) {
      /*Check if the last session accepted was long time ago*/
      if(curr_time - cinfo->last_session_ins_tstamp < SESSION_ACCEPT_RESTART_TIME) {
        return 1;
      }
      /*Start accepting new session, OVERRIDING older ones*/
      cinfo->n_session_tracking = 0; 
    }
    /*New session accepted*/
    struct session_value newVal = {.last_ins_tstamp=curr_time, .n_packets=1};
    SESSIONS_TRACKED.insert(key, &newVal);
    cinfo->n_session_tracking += 1;
    cinfo->last_session_ins_tstamp = curr_time;
  } else {
    /*Checking if reached number of packets per session stored*/
    if(value->n_packets == N_PACKET_PER_SESSION) {
        /*Checking if passed enough time since the last packed stored*/
        if(curr_time - value->last_ins_tstamp < SESSION_PACKET_RESTART_TIME) {
            return 1;
        }
        /*Restart considering packets for that session*/
        value->n_packets = 0;
    }
    /*Already present session*/
    value->last_ins_tstamp = curr_time;
    value->n_packets +=1;  
  }
  return 0;
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

  /*Checking for considered protocols*/
  if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_ICMP) {
    return RX_OK;
  }

  /*Retrieving capture information*/
  unsigned int key = 0;
  struct capture_info *cinfo = CAPTURE_INFO.lookup(&key);
  if (!cinfo){
      return RX_OK;
  }

  /*Checking if packed is already timestamped, otherwise get it from kernel bpf function*/
  uint64_t curr_time = ctx->tstamp == 0? bpf_ktime_get_ns() : ctx->tstamp;

  /*Checking if array of captured packets is full*/
  if(cinfo->next_index == N_PACKET_TOTAL) {
    /*Checking if last insertion happened 10s ago*/
    if(curr_time - cinfo->last_packet_ins_tstamp < BUFFER_PACKET_RESTART_TIME) {
      return RX_OK;
    }
    /*Reset head to zero to start extracting packet feature again*/
    cinfo->next_index = 0;
  }

  /*Retrieving current features slot*/
  struct features *pkt_info =  PACKET_BUFFER.lookup(&cinfo->next_index);
  if (!pkt_info){
      return RX_OK;
  }

  /*Calculating ip header length
   * value to multiply by 4 (SHL 2)
   *e.g. ip->ihl = 5 ; TCP Header starts at = 5 x 4 byte = 20 byte */
  uint8_t ip_header_len = ip->ihl << 2;

  switch (ip->protocol) {
    case IPPROTO_TCP: {
      /*Parsing L4 TCP*/
      struct tcphdr *tcp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) tcp + sizeof(*tcp) > data_end) {
        return RX_OK;
      }
      /*Check if it is already tracked or try to track it*/
      struct session_key key = {.saddr=ip->saddr, .daddr=ip->daddr, .sport=tcp->source, .dport=tcp->dest, .proto=ip->protocol};
      if(check_or_try_add_session(&key, cinfo, curr_time) != 0) {
        return RX_OK;
      }

      /*Now I'm sure to take the packet*/
      uint16_t len = bpf_ntohs(ip->tot_len);
      struct features newFeatures = {.srcPort=bpf_htons(tcp->source), .dstPort=bpf_htons(tcp->dest), .length=len, 
        .tcpAck=tcp->ack_seq, .tcpWin=bpf_ntohs(tcp->window), .tcpLen=(uint16_t)(len - ip_header_len - sizeof(*tcp)), 
        .tcpFlags=(tcp->cwr << 7) | (tcp->ece << 6) | (tcp->urg << 5) | (tcp->ack << 4)
                | (tcp->psh << 3)| (tcp->rst << 2) | (tcp->syn << 1) | tcp->fin};
      
      *pkt_info = newFeatures;
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
      if(check_or_try_add_session(&key, cinfo, curr_time) != 0) {
        return RX_OK;
      }

      /*Now I'm sure to take the packet*/
      uint16_t len = bpf_ntohs(ip->tot_len);
      struct features newFeatures = {.length=len, .icmpType=icmp->type};
      
      *pkt_info = newFeatures;
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
      if(check_or_try_add_session(&key, cinfo, curr_time) != 0) {
        return RX_OK;
      }

      /*Now I'm sure to take the packet*/
      uint16_t len = bpf_ntohs(ip->tot_len);
      struct features newFeatures = {.srcPort=bpf_htons(udp->source), .dstPort=bpf_htons(udp->dest), .length=len, .udpSize=bpf_ntohs(udp->len) - sizeof(*udp)};
      
      *pkt_info = newFeatures;
      break;
    }
    /*Should never reach this code since already checked*/
    default : {
      return RX_OK;
    }
  }

  /*Setting packet features*/
  pkt_info->srcIp = bpf_ntohl(ip->saddr);
  pkt_info->dstIp = bpf_ntohl(ip->daddr);
  pkt_info->protocol = ip->protocol;
  pkt_info->timestamp = curr_time;
  pkt_info->ipFlagsFrag = bpf_ntohs(ip->frag_off);
   
  /*pcn_log(ctx, LOG_TRACE, "Inserted Packet at index: %u ", cinfo->next_index);*/

  /*The capture was fine, update last timestamp and index*/
  cinfo->last_packet_ins_tstamp = curr_time;
  cinfo->next_index += 1;
  return RX_OK;
}