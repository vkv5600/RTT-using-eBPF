#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <errno.h>
#include <assert.h>
#include <sys/sysinfo.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <libgen.h>
#include <linux/if_link.h>
#include <poll.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <time.h>
#include <math.h>


#define MAXLEN 64
#define PATH_MAX        4096

char tc_pin_base_dir[MAXLEN] =  "/sys/fs/bpf/tc/globals";
char tc_map_name1[] = "counter_map";
char tc_map_name2[] = "timestamp";

struct datarec {
    __u64 rx_packets;
};
int open_bpf_map_file(const char *pin_dir,
                      const char *mapname,
                      struct bpf_map_info *info)
{
        char filename[PATH_MAX];
        int err, len, fd;
        __u32 info_len = sizeof(*info);

        len = snprintf(filename, PATH_MAX, "%s/%s", pin_dir, mapname);
        if (len < 0) {
                fprintf(stderr, "ERR: constructing full mapname path\n");
                return -1;
        }

        fd = bpf_obj_get(filename);
        if (fd < 0) {
                fprintf(stderr,
                        "WARN: Failed to open bpf map file:%s err(%d):%s\n",
                        filename, errno, strerror(errno));
                return fd;
        }
        return fd;
}


void main ()
{
    struct datarec rec1,rec2;
    __u64 i,j,rTT,r,start,arrival,temp,threshold;
    __u32 aux, index=0;
    int map_fd1,map_fd2,map_fd3,map_fd4,flag;
    struct timespec ts,tym;
    clock_gettime(CLOCK_REALTIME, &tym);    
    
    map_fd1 = open_bpf_map_file(tc_pin_base_dir, tc_map_name1, NULL);
    map_fd2 = open_bpf_map_file(tc_pin_base_dir, tc_map_name2, NULL);

    if (map_fd1 < 0 || map_fd2 < 0) {
        printf("finding the map for packet counter failed\n");
        return;
    }
    bpf_map_get_next_key(map_fd2,&index,&j);
    bpf_map_lookup_elem(map_fd2, &j, &rec2);
   
    flag=0;

    while(1)
    {	    sleep(0.1);
    	    if(bpf_map_get_next_key(map_fd1,&i,&j) != 0)//getting next key for incoming reply packet
    	    {	//Ran out of map. Resetting
    	    	j=-1;
    	    }
    	    clock_gettime(CLOCK_REALTIME, &ts);	
            
            arrival=start+rec1.rx_packets;//arrival of the packet w.r.t clock realtime
            temp=ts.tv_nsec+ts.tv_sec*pow(10,9);
            threshold=abs(temp-arrival);
            if(threshold>5000000000)//if threshold reached, delete that outgoing packet.
            {
            	printf("Threshold reached..................................\n");
            	bpf_map_delete_elem(map_fd1,&i);
            	i=j;
            	continue;
            }
	    flag=1;
            i=j;	
    }
    printf("\nExiting");
}