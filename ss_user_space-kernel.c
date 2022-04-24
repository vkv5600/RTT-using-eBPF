#include <stddef.h>
#include <stdbool.h>
#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <iproute2/bpf_elf.h>
#include <time.h>
#include <math.h>
#include "common.h"

#define RET 0
#define IP_PKT 0
#define ICMP_PKT 1
#define TCP_PKT 2
#define UDP_PKT 3

struct datarec {
    __u64 rx_packets;
};

struct bpf_elf_map SEC("maps") counter_map = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key   = sizeof(__u64),
    .size_value = sizeof(struct datarec),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem   = 1024,
};

struct bpf_elf_map SEC("maps") counter_map1 = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key   = sizeof(__u64),
    .size_value = sizeof(struct datarec),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem   = 1024,
};
struct bpf_elf_map SEC("maps") timestamp = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key   = sizeof(__u64),
    .size_value = sizeof(struct datarec),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem   = 1,
};
struct bpf_elf_map SEC("maps") RTT = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key   = sizeof(__u64),
    .size_value = sizeof(struct datarec),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem   = 1024,
};
            
SEC("flow1")//outgoing packet
int parse_pkt(struct __sk_buff *skb)
{   
    __u64 ts;
    ts=bpf_ktime_get_ns();
    __u64 index=0;
    
    bpf_map_update_elem(&timestamp,&index,&ts,0);
    
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    int ret,flag;
    struct datarec *rec;
    __u64 key = 0;
    	
    if(data < data_end)
    {
        struct ethhdr *eth = data;
        if (data + sizeof(*eth) > data_end)
            return TC_ACT_SHOT;

        if (bpf_htons(eth->h_proto) != 0x0800) {
            bpf_printk("Received non IP packet with eth thype = %x", bpf_htons(eth->h_proto));
            return TC_ACT_UNSPEC;
        }
        struct iphdr *iph = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*iph) > data_end)
            return TC_ACT_SHOT;

        /* send only TCP packets*/
        if (iph->protocol == 0x6) 
        {  
            struct tcphdr *tcph = data + sizeof(*eth) + sizeof(*iph);
            
            int payload = sizeof(data);
            
            if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end)
                return TC_ACT_SHOT;
            bpf_printk("\nFirst packet") ;   
           
    	    bpf_printk("Time : %lu",ts);
            bpf_printk("ip_src=%x, ip_dst=%x,", bpf_htonl(iph->saddr), bpf_htonl(iph->daddr));    
            
            bpf_printk("src_port=%d, dest_dport=%d, ack_seq=%d", bpf_htons(tcph->source), bpf_htons(tcph->dest), bpf_htons(tcph->ack_seq)); 
            bpf_printk("payload=%d,seq=%d",payload,bpf_htons(tcph->seq)); 
                 
            __u32 flowid=bpf_htonl(iph->saddr)+bpf_htonl(iph->daddr)+bpf_htons(tcph->source)+bpf_htons(tcph->dest)+bpf_htons(tcph->seq);            
            bpf_printk("Flow ID: %x",flowid);
            key = flowid;
            flag=bpf_map_update_elem(&counter_map,&flowid,&ts,1);
            if(flag < 0)
            	bpf_printk("Collision");
            bpf_printk("Flag value: %d",flag);
        }
        else if (iph->protocol == 0x11)
        {
           struct udphdr *udph = data + sizeof(*eth) + sizeof(*iph);
           if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph) > data_end)
               return TC_ACT_SHOT;
           bpf_printk("l4_sport=%d, l4_dport=%d", bpf_htons(udph->source), bpf_htons(udph->dest));
           key = UDP_PKT;
        }
        return RET;
    }
    return RET;

}
SEC("flow2")//incoming reply packet
int parse_rcv_pkt(struct __sk_buff *skb)
{   
    __u64 ts;
    ts=bpf_ktime_get_ns();
    
    __u64 index=0;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    int ret,flag;
    struct datarec *rec;
    __u64 key = 0;
    	
    if(data < data_end)
    {
        struct ethhdr *eth = data;
        if (data + sizeof(*eth) > data_end)
            return TC_ACT_SHOT;

        if (bpf_htons(eth->h_proto) != 0x0800) {
            bpf_printk("Received non IP packet with eth thype = %x", bpf_htons(eth->h_proto));
            return TC_ACT_UNSPEC;
        }

        struct iphdr *iph = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*iph) > data_end)
            return TC_ACT_SHOT;

        /* send only TCP packets*/
        if (iph->protocol == 0x6) 
        {   bpf_printk("\nSecond packet") ; 
    	    bpf_printk("Time : %lu",ts);
            struct tcphdr *tcph = data + sizeof(*eth) + sizeof(*iph);
            if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end)
                return TC_ACT_SHOT;
            
            int payload = sizeof(data);   
            bpf_printk("ip_src=%x, ip_dst=%x,", bpf_htonl(iph->saddr), bpf_htonl(iph->daddr));    
            bpf_printk("src_port=%d, dest_dport=%d, ack_seq=%d", bpf_htons(tcph->source), bpf_htons(tcph->dest), bpf_htons(tcph->ack_seq)); 
            bpf_printk("payload=%d,seq=%d",payload,bpf_htons(tcph->seq)); 
            __u32 flowid=bpf_htonl(iph->saddr)+bpf_htonl(iph->daddr)+bpf_htons(tcph->source)+bpf_htons(tcph->dest)+bpf_htons(tcph->ack_seq);
            bpf_printk("Flow ID: %x",flowid);
            key = flowid;
            flag=bpf_map_update_elem(&counter_map1,&flowid,&ts,1);
            if(flag < 0)
            	bpf_printk("Collision");
            bpf_printk("Flag value: %d",flag);
        }
        else if (iph->protocol == 0x11)
        {
           struct udphdr *udph = data + sizeof(*eth) + sizeof(*iph);
           if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph) > data_end)
               return TC_ACT_SHOT;
           bpf_printk("l4_sport=%d, l4_dport=%d", bpf_htons(udph->source), bpf_htons(udph->dest));
           key = UDP_PKT;
           rec = bpf_map_lookup_elem(&counter_map, &key);
           if(rec == NULL)
           {
               return TC_ACT_SHOT;
           }

           rec->rx_packets = rec->rx_packets + 1;
        }
        return RET;
    }
    return RET;

}
char _license[] SEC("license") = "GPL";