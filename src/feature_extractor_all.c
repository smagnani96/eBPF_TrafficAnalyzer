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
#define N_PACKET 10000
#define N_SESSION 10240
#define RESTART_TIME 10000000000

/*TCP-SESSION identifier*/
struct tcp_session {
    __be32  saddr;
    __be32  daddr;
    __be16  sport;
    __be16  dport;
} __attribute__((packed));

/*Structure containing info about capture and valid indexes*/
struct capture_info {
    unsigned int feature_map_index;
    unsigned int n_session_tracking;
    uint64_t last_ins_tstamp;
} __attribute__((packed));

/*Features to be exported*/
struct features {
    uint32_t saddr;         //IP source address
    uint32_t daddr;         //IP destination address
    uint64_t timestamp;     //Packet timestamp
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
/*Tracked session map*/
BPF_TABLE("lru_hash", struct tcp_session, u8, TCP_SESSIONS_TRACKED, N_SESSION);

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
        if(curr_time - cinfo->last_ins_tstamp < RESTART_TIME) {
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
            struct tcp_session session = {.saddr=ip->saddr, .daddr=ip->daddr, .sport=tcp->source, .dport=tcp->dest};
            u8 *is_tracked = TCP_SESSIONS_TRACKED.lookup(&session);
            if(!is_tracked) {
                /*Increase tracked sessions and store current one in map*/
                u8 val = 1;
                TCP_SESSIONS_TRACKED.insert(&session, &val);
                cinfo->n_session_tracking+=1;
            }/* else {
                //Don't know actually what to do with that counter
                *is_tracked+=1;
            }*/
    
            /*Now that I'm sure to take this packet reset the structure (could contain old data)*/
            *pkt_info = EmptyFeatures;
            pkt_info->length = bpf_ntohs(ip->tot_len);
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
   
    /*The capture was fine, update last timestamp and index*/
    cinfo->last_ins_tstamp = curr_time;
    cinfo->feature_map_index+=1;

	return RX_OK;
}