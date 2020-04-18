/**
 * eBPF C program to be dynamically injected in the kernel.
 * The aim of this program is to extract some info concerning many packets passing through the interface in order to prevent a possible attack.
 * By now the following protocols are checked:
 *  - TCP
 *  - UDP
 *  - ICMP
 * It still lacks of decision making about which TCP session should be tracked (WIP).
 */
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1

#define N_PACKET 100

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
};

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
};

/*UDP Header*/
struct udphdr {
    __be16  source;
    __be16  dest;
    __be16  len;
    __sum16 check;
};

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
};

/*Features to be exported*/
struct features {
	uint32_t saddr;
	uint32_t daddr;
    uint64_t timestamp;
    uint16_t length;
    uint16_t ipv4_flags;
    uint16_t tcp_len;
    uint32_t tcp_ack;
    uint8_t  tcp_flags;
    uint16_t tcp_win;
    uint8_t udp_len;
    uint8_t  icmp_type;
} __attribute__((packed));

/*Structures shared between Control Plane - Data Plane*/
BPF_ARRAY(INDEX_COUNTER, unsigned int, 1);
BPF_ARRAY(PACKET_INFO, struct features, N_PACKET);

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

 	/*Retrieving data structures*/
 	unsigned int key = 0;
 	unsigned int *index_counter = INDEX_COUNTER.lookup(&key);
 	if (!index_counter || *index_counter >= N_PACKET){
    	return RX_OK;
 	}
 	struct features *pkt_info =  PACKET_INFO.lookup(index_counter);
 	if (!pkt_info){
    	return RX_OK;
 	}

 	/*Setting timestamp*/
 	if (ctx->tstamp == 0) {
		pkt_info->timestamp = bpf_ktime_get_ns();
	} else {
		pkt_info->timestamp = ctx->tstamp;
	}

	/*Setting Ip info*/
	pkt_info->saddr = bpf_ntohl(ip->saddr);
	pkt_info->daddr = bpf_ntohl(ip->daddr);
	pkt_info->length = bpf_ntohs(ip->tot_len);
	pkt_info->ipv4_flags = bpf_ntohs(ip->frag_off);

    switch(ip->protocol) {
    	case IPPROTO_TCP: {
            /*Parsing L4 TCP*/
    		struct tcphdr *tcp = data + sizeof(struct eth_hdr) + sizeof(struct iphdr);
		 	if(data + sizeof(struct eth_hdr) + sizeof(struct iphdr) + sizeof(*tcp) > data_end) {
 				return RX_OK;
            }
 			pkt_info->tcp_ack = tcp->ack_seq;
 			pkt_info->tcp_win = bpf_ntohs(tcp->window);
 			pkt_info->tcp_len = (uint16_t)(pkt_info->length - sizeof(struct iphdr) - sizeof(*tcp));
 			pkt_info->tcp_flags = (tcp->cwr << 7) | (tcp->ece << 6) | (tcp->urg << 5) | (tcp->ack << 4)
 			 					| (tcp->psh << 3)| (tcp->rst << 2) | (tcp->syn << 1) | tcp->fin;
            pcn_log(ctx, LOG_INFO, "Inserted TCP packet at index: %d ", *index_counter);
 			break;
    	}
    	case IPPROTO_ICMP: {
            /*Parsing L4 ICMP*/
            struct icmphdr *icmp = data + sizeof(struct eth_hdr) + sizeof(struct iphdr);
            if(data + sizeof(struct eth_hdr) + sizeof(struct iphdr) + sizeof(*icmp) > data_end) {
                return RX_OK;
            }
            pkt_info->icmp_type = icmp->type;
            pcn_log(ctx, LOG_INFO, "Inserted ICMP packet at index: %d ", *index_counter);
    		break;
        }
    	case IPPROTO_UDP: {
            /*Parsing L4 UDP*/
            struct udphdr *udp = data + sizeof(struct eth_hdr) + sizeof(struct iphdr);
            if(data + sizeof(struct eth_hdr) + sizeof(struct iphdr) + sizeof(*udp) > data_end) {
                return RX_OK;
            }
            pkt_info->udp_len = bpf_ntohs(udp->len);
            pcn_log(ctx, LOG_INFO, "Inserted UDP packet at index: %d ", *index_counter);
    		break;
        }
    }
    *index_counter+=1;
	return RX_OK;
}