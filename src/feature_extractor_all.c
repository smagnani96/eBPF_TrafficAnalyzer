/**
 * eBPF C program to be dynamically injected in the kernel.
 * The aim of this program is to extract some info concerning many packets passing through the interface in order to prevent a possible attack.
 * By now the following protocols are checked:
 *  - TCP
 *  - UDP
 *  - ICMP
 */
/*Protocol types according to standard*/
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

/*Own control variables*/
#define N_PACKET             10000          // Buffer size (total packet stored)
#define N_SESSION            10240          // Number of max TCP session tracked
#define N_PACKET_PER_SESSION 100            // Number of packet from the same TCP session
#define PACKET_RESTART_TIME  5000000000     //  Number of seconds to wait before resetting the buffer (5 seconds)
#define SESSION_RESTART_TIME 1000000000     // Seconds to wait before tracking packets from an already tracked session

/*TCP-SESSION identifier*/
struct tcp_session_key {
    __be32  saddr;               //IP source address
    __be32  daddr;               //IP dest address
    __be16  sport;               //TCP source port
    __be16  dport;               //TCP dest port
} __attribute__((packed));

struct tcp_session_value {
    uint64_t last_ins_tstamp;    // Timestampt of last inserted packet for that session
    uint32_t n_packets;          // Number of packed tracked for that session
} __attribute__((packed));

/*Structure containing info about capture and valid indexes*/
struct capture_info {
    unsigned int feature_map_index;     // Buffer index
    unsigned int n_session_tracking;    // Number of actual tracked sessions
    uint64_t last_ins_tstamp;           // Timestampt of the last tracked packet
} __attribute__((packed));

/*Features to be exported*/
struct features {
    uint64_t timestamp;     //Packet timestamp
    uint32_t saddr;         //IP source address
    uint32_t daddr;         //IP destination address
    uint16_t sport;         //TCP/UDP source port
    uint16_t dport;         //TCP/UDP destination port
    uint16_t length;        //IP length value
    uint16_t ipv4_flags;    //IP flags
    uint16_t tcp_len;       //TCP payload length
    uint32_t tcp_ack;       //TCP ack n°
    uint8_t  tcp_flags;     //TCP flags
    uint16_t tcp_win;       //TCP window value
    uint8_t udp_len;        //UDP payload length
    uint8_t  icmp_type;     //ICMP operation type
} __attribute__((packed));

/*Ethernet Header*/
struct eth_hdr {
    __be64 dst   : 48;
    __be64 src   : 48;
    __be16 proto;
} __attribute__((packed));

/*Ip Header*/
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
    __u8    tos;
    __be16  tot_len;
    __be16  id;
    __be16  frag_off;
    __u8    ttl;
    __u8    protocol;
    __sum16 check;
    __be32  saddr;
    __be32  daddr;
    /*The options start here. */
} __attribute__((packed));

/*TCP Header*/
struct tcphdr {
    __be16  source;
    __be16  dest;
    __be32  seq;
    __be32  ack_seq;
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
    __be16  window;
    __sum16 check;
    __be16  urg_ptr;
} __attribute__((packed));

/*UDP Header*/
struct udphdr {
    __be16  source;
    __be16  dest;
    __be16  len;
    __sum16 check;
} __attribute__((packed));

/*ICMP Header*/
struct icmphdr {
  __u8      type;
  __u8      code;
  __sum16   checksum;
  union {
    struct {
        __be16  id;
        __be16  sequence;
    } echo;
    __be32  gateway;
    struct {
        __be16  __unused;
        __be16  mtu;
    } frag;
    __u8    reserved[4];
  } un;
} __attribute__((packed));

/*Structure used as initializer*/
static const struct features EmptyFeatures;

/*Structures shared between Control Plane - Data Plane*/
BPF_ARRAY(CAPTURE_INFO, struct capture_info, 1);
BPF_ARRAY(PACKET_FEATURE_MAP, struct features, N_PACKET);
/*Tracked session LRU map*/
BPF_TABLE("lru_hash", struct tcp_session_key, struct tcp_session_value, TCP_SESSIONS_TRACKED, N_SESSION);

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
    if(ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_ICMP){
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
    if(cinfo->feature_map_index == N_PACKET) {
        /*Checking if last insertion happened 10s ago*/
        if(curr_time - cinfo->last_ins_tstamp < PACKET_RESTART_TIME) {
            return RX_OK;
        }
        /*Reset head to zero to start extracting packet feature again*/
        cinfo->feature_map_index = 0;
    }

    /*Retrieving current features slot*/
    struct features *pkt_info =  PACKET_FEATURE_MAP.lookup(&cinfo->feature_map_index);
    if (!pkt_info){
        return RX_OK;
    }

    /*Calculating ip header length
     * value to multiply *4
     *e.g. ip->ihl = 5 ; TCP Header starts at = 5 x 4 byte = 20 byte */
    uint8_t ip_header_len = ip->ihl << 2;   //SHL 2 -> *4 multiply

    switch(ip->protocol) {
    	case IPPROTO_TCP: {
            /*Parsing L4 TCP*/
    		struct tcphdr *tcp = data + sizeof(struct eth_hdr) + ip_header_len;
		 	if((void *)tcp + sizeof(*tcp) > data_end) {
 				return RX_OK;
            }
            /*Check if it is already tracked*/
            struct tcp_session_key session = {.saddr=ip->saddr, .daddr=ip->daddr, .sport=tcp->source, .dport=tcp->dest};
            struct tcp_session_value *value = TCP_SESSIONS_TRACKED.lookup(&session);
            if(!value) {
                /*Increase tracked sessions and store current one in map*/
                struct tcp_session_value val = {.last_ins_tstamp=curr_time, .n_packets=1};
                TCP_SESSIONS_TRACKED.insert(&session, &val);
                cinfo->n_session_tracking+=1;
            } else {
                /*Checking if reached number of packets per session stored*/
                if(value->n_packets == N_PACKET_PER_SESSION) {
                    /*Checking if passed enough time*/
                    if(curr_time - value->last_ins_tstamp < SESSION_RESTART_TIME) {
                        return RX_OK;
                    }
                    /*This session is still active, already reached number of tracked packets but long time ago => reset the counter */
                    value->n_packets = 0;
                }
                value->last_ins_tstamp = curr_time;
                value->n_packets+=1;
            }
    
            /*Now that I'm sure to take this packet reset the structure (could contain old data)*/
            *pkt_info = EmptyFeatures;
            pkt_info->length = bpf_ntohs(ip->tot_len);
            pkt_info->sport = bpf_htons(tcp->source);
            pkt_info->dport = bpf_htons(tcp->dest);
            pkt_info->tcp_ack = tcp->ack_seq;
 			pkt_info->tcp_win = bpf_ntohs(tcp->window);
 			pkt_info->tcp_len = (uint16_t)(pkt_info->length - ip_header_len - sizeof(*tcp));
 			pkt_info->tcp_flags = (tcp->cwr << 7) | (tcp->ece << 6) | (tcp->urg << 5) | (tcp->ack << 4)
 			 					| (tcp->psh << 3)| (tcp->rst << 2) | (tcp->syn << 1) | tcp->fin;
 			break;
    	}
    	case IPPROTO_ICMP: {
            /*Parsing L4 ICMP*/
            struct icmphdr *icmp = data + sizeof(struct eth_hdr) + ip_header_len;
            if((void *)icmp + sizeof(*icmp) > data_end) {
                return RX_OK;
            }
            /*Now that I'm sure to take this packet reset the structure (could contain old data)*/
            *pkt_info = EmptyFeatures;
            pkt_info->length = bpf_ntohs(ip->tot_len);
            pkt_info->icmp_type = icmp->type;
    		break;
        }
    	case IPPROTO_UDP: {
            /*Parsing L4 UDP*/
            struct udphdr *udp = data + sizeof(struct eth_hdr) + ip_header_len;
            if((void *)udp + sizeof(*udp) > data_end) {
                return RX_OK;
            }
            /*Now that I'm sure to take this packet reset the structure (could contain old data)*/
            *pkt_info = EmptyFeatures;
            pkt_info->length = bpf_ntohs(ip->tot_len);
            pkt_info->sport = bpf_htons(udp->source);
            pkt_info->dport = bpf_htons(udp->dest);
            pkt_info->udp_len = bpf_ntohs(udp->len) - sizeof(*udp);
    		break;
        }
        /*Should never reach this code since already checked*/
        default : {
            return RX_OK;
        }
    }

    /*Setting packet features*/
    pkt_info->timestamp = curr_time;
    pkt_info->saddr = bpf_ntohl(ip->saddr);
    pkt_info->daddr = bpf_ntohl(ip->daddr);
    pkt_info->ipv4_flags = bpf_ntohs(ip->frag_off);
   
    //pcn_log(ctx, LOG_TRACE, "Inserted Packet at index: %u ", cinfo->feature_map_index);

    /*The capture was fine, update last timestamp and index*/
    cinfo->last_ins_tstamp = curr_time;
    cinfo->feature_map_index+=1;

	return RX_OK;
}