#include <stddef.h>
#include <stdbool.h>
#include <linux/pkt_cls.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <iproute2/bpf_elf.h>
#include<stdio.h>

#include "common.h"

#define RET 0
#define IP_PKT 0
#define ICMP_PKT 1
#define TCP_PKT 2
#define UDP_PKT 3
struct datarec {
    __u32 rx_packets;
};


//int map_fd;
//long long key, value;

//map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(key),sizeof(value), 256);



struct bpf_elf_map SEC("maps") counter_map1 = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key   = sizeof(__u64),
    .size_value = sizeof(struct datarec),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem   = 16,//ip,udp,tcp,icmp
};

struct bpf_elf_map SEC("maps") counter_map2= {
    .type = BPF_MAP_TYPE_HASH,
    .size_key   = sizeof(__u64),
    .size_value = sizeof(struct datarec),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem   = 8,//ip,udp,tcp,icmp
};

struct bpf_elf_map SEC("maps") counter_map3= {
    .type = BPF_MAP_TYPE_HASH,
    .size_key   = sizeof(__u64),
    .size_value = sizeof(struct datarec),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem   = 8,//ip,udp,tcp,icmp
};

struct bpf_elf_map SEC("maps") counter_map4= {
    .type = BPF_MAP_TYPE_HASH,
    .size_key   = sizeof(__u64),
    .size_value = sizeof(struct datarec),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem   = 8,//ip,udp,tcp,icmp
};
        
SEC("flow1")
int parse_pkt(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    int ret;
    struct datarec *rec;
    __u64 key = 0;
    
    
    __u64 ts;
    ts=bpf_ktime_get_ns();

    bpf_printk("Time3 : %x",ts);
    if(data < data_end)
    {
        struct ethhdr *eth = data;
        if (data + sizeof(*eth) > data_end)
            return TC_ACT_SHOT;

        if (bpf_htons(eth->h_proto) != 0x0800){
            bpf_printk("Received non IP packet with eth thype = %x", bpf_htons(eth->h_proto));
            return TC_ACT_UNSPEC;
        }


        struct iphdr *iph = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*iph) > data_end)
            return TC_ACT_SHOT;

        bpf_printk("Received IP pkt with ip_src=%x, ip_dst=%x, proto=%d", bpf_htonl(iph->saddr), bpf_htonl(iph->daddr), iph->protocol);
        u_int32_t a = bpf_htonl(iph->daddr);
        bpf_printk("%x",a); // 
        //key = IP_PKT;
        //rec = bpf_map_lookup_elem(&counter_map1, &key);
       // if(rec == NULL)
       // {
           // return TC_ACT_SHOT;
        //}
       // __u32 flowid=bpf_htonl(iph->saddr)+bpf_htonl(iph->daddr);
        //bpf_printk("Flow ID: %x",flowid);
        
        //rec->rx_packets = rec->rx_packets + 1;

        /* send only TCP packets*/
        if (iph->protocol == 0x6) 
        {
            struct tcphdr *tcph = data + sizeof(*eth) + sizeof(*iph);
            if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end)
                return TC_ACT_SHOT;
            bpf_printk("Received TCP pkt with l4_sport=%d, l4_dport=%d , sequence_number = %d ", bpf_htons(tcph->source), bpf_htons(tcph->dest),bpf_htons(tcph->ack_seq));
            key = TCP_PKT;
            rec = bpf_map_lookup_elem(&counter_map1, &key);
            __u64 flowid=bpf_htonl(iph->saddr)+bpf_htonl(iph->daddr)+bpf_htons(tcph->source)+bpf_htons(tcph->dest)+bpf_htons(tcph->seq);
            bpf_printk("Flow ID: %x",flowid);
            int flag = bpf_map_update_elem(&counter_map1,&flowid,&ts,1);
        
            bpf_printk("%d",flag); 
            if(flag<0){
     		int flag2 = bpf_map_update_elem(&counter_map2,&flowid,&ts,1);
     		if(flag2<0){
     			int flag3 = bpf_map_update_elem(&counter_map3,&flowid,&ts,1);
     		}
     	    }	
            
          
            
            //if(rec == NULL)
            //{
               // return TC_ACT_SHOT;
            //}
           // rec->rx_packets = rec->rx_packets + 1;

        }
        else if (iph->protocol == 0x11)
        {
           struct udphdr *udph = data + sizeof(*eth) + sizeof(*iph);
           if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph) > data_end)
           return TC_ACT_SHOT;
           bpf_printk("Received UDP pkt with l4_sport=%d, l4_dport=%d", bpf_htons(udph->source), bpf_htons(udph->dest));
           key = UDP_PKT;
           rec = bpf_map_lookup_elem(&counter_map1, &key);
               // bpf_trace_printk(rec,sizeof(rec));
           if(rec == NULL)
           {
               return TC_ACT_SHOT;
           }

           rec->rx_packets = rec->rx_packets + 1;
        }
        else if (iph->protocol == 0x01)
        {
            bpf_printk("Received ICMP packet");
            key = ICMP_PKT;
            rec = bpf_map_lookup_elem(&counter_map1, &key);
            //bpf_trace_printk(rec,sizeof(rec));
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



SEC("flow2")
int parse_rcv_pkt(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    int ret;
    struct datarec *rec;
    __u64 key = 0;
    
    int count=0;
    __u64 ts;
    ts=bpf_ktime_get_ns();

    bpf_printk("Time3 : %x",ts);
    
    __u64 rtt;
    if(data < data_end)
    {
        struct ethhdr *eth = data;
        if (data + sizeof(*eth) > data_end)
            return TC_ACT_SHOT;

        if (bpf_htons(eth->h_proto) != 0x0800){
            bpf_printk("Received non IP packet with eth thype = %x", bpf_htons(eth->h_proto));
            return TC_ACT_UNSPEC;
        }


        struct iphdr *iph = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*iph) > data_end)
            return TC_ACT_SHOT;

        bpf_printk("Received IP pkt with ip_src=%x, ip_dst=%x, proto=%d", bpf_htonl(iph->saddr), bpf_htonl(iph->daddr), iph->protocol);
        u_int32_t a = bpf_htonl(iph->daddr);
        bpf_printk("%x",a); // 
        //key = IP_PKT;
        //rec = bpf_map_lookup_elem(&counter_map1, &key);
       // if(rec == NULL)
       // {
           // return TC_ACT_SHOT;
        //}
       // __u32 flowid=bpf_htonl(iph->saddr)+bpf_htonl(iph->daddr);
        //bpf_printk("Flow ID: %x",flowid);
        
        //rec->rx_packets = rec->rx_packets + 1;

        /* send only TCP packets*/
        if (iph->protocol == 0x6) 
        {
            struct tcphdr *tcph = data + sizeof(*eth) + sizeof(*iph);
            if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end)
                return TC_ACT_SHOT;
            bpf_printk("Received TCP pkt with l4_sport=%d, l4_dport=%d , sequence_number = %d ", bpf_htons(tcph->source), bpf_htons(tcph->dest),bpf_htons(tcph->ack_seq));
            //key = TCP_PKT;
            
            __u64 flowid=bpf_htonl(iph->saddr)+bpf_htonl(iph->daddr)+bpf_htons(tcph->source)+bpf_htons(tcph->dest)+bpf_htons(tcph->ack_seq);
            bpf_printk("Flow ID: %x",flowid);
            rec = bpf_map_lookup_elem(&counter_map1, &flowid);
            if(rec == NULL){
            		 rec = bpf_map_lookup_elem(&counter_map2, &flowid);
            		
            		 if(rec == NULL){
            		 	rec = bpf_map_lookup_elem(&counter_map3, &flowid);
            		 	if(rec == NULL){
            		 		bpf_printk("unable to found the packet with given flowid in any of the 3 tables");
            		 			
            		 			return RET;
            		 	}
            		 	
            		 }	
            		 
            }
            bpf_printk("outgoing packet timestamp: %lu",rec->rx_packets);
             
            rtt = ts-rec->rx_packets;
            bpf_printk("rount trip time: %lu",rtt);
            bpf_map_update_elem(&counter_map4,&flowid,&rtt,1);
             
             
             
             
             
            
            //int flag = bpf_map_update_elem(&counter_map1,&flowid,&ts,1);
            //bpf_printk("%d",flag); 
            //if(flag<0){
     	//	int flag2 = bpf_map_update_elem(&counter_map2,&flowid,&ts,1);
     	//	if(flag2<0){
     	//		int flag3 = bpf_map_update_elem(&counter_map3,&flowid,&ts,1);
     	//	}
     	  //  }	
            
          
            
            //if(rec == NULL)
            //{
               // return TC_ACT_SHOT;
            //}
           // rec->rx_packets = rec->rx_packets + 1;

        }
        else if (iph->protocol == 0x11)
        {
           struct udphdr *udph = data + sizeof(*eth) + sizeof(*iph);
           if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph) > data_end)
           return TC_ACT_SHOT;
           bpf_printk("Received UDP pkt with l4_sport=%d, l4_dport=%d", bpf_htons(udph->source), bpf_htons(udph->dest));
           key = UDP_PKT;
           rec = bpf_map_lookup_elem(&counter_map1, &key);
               // bpf_trace_printk(rec,sizeof(rec));
           if(rec == NULL)
           {
               return TC_ACT_SHOT;
           }

           rec->rx_packets = rec->rx_packets + 1;
        }
        else if (iph->protocol == 0x01)
        {
            bpf_printk("Received ICMP packet");
            key = ICMP_PKT;
            rec = bpf_map_lookup_elem(&counter_map1, &key);
            //bpf_trace_printk(rec,sizeof(rec));
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
