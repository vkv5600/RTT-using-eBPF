# Passive Measurement of Round Trip Time using eBPF

## Codes: 

### Single staged RTT calculation at user space

	User plane code : ss_user_space-user.c
	Kernel plane code : ss_user_space-kernel.c
	
### Single staged RTT calculation at kernel space 

	User plane code : ss_kernel_space-user.c
	Kernel plane code : ss_kernel_space-kernel.c
	
### Multi staged RTT calculation at kernel space 

	Kernel plane code : ms_kernel_space_kernel.c
	

Running the kernel space code:

	sudo tc qdisc add dev <interface> clsact

	clang -O2 -g -S -emit-llvm -DDEBUG -c <kernel_code> -o - | llc -march=bpf -filetype=obj -o out.o
	sudo tc filter add dev <interface> ingress prio 1 handle 3 bpf obj out.o section flow1 verbose
	sudo tc filter add dev <interface> ingress prio 1 handle 3 bpf obj out.o section flow2 verbose
	sudo cat /sys/kernel/tracing/trace_pipe
	
To reset the interface:

	sudo tc filter del dev <interface> ingress prio 1
	sudo tc filter del dev <interface> ingress prio 1

Viewing the map:

	sudo bpftool map dump id <>

Runing the User plane code:

	cc <user_plane code> ../xdp-tutorial/libbpf/src/libbpf.a -lelf -lz
	sudo ./a.out
