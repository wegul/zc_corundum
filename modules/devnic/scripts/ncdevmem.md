# ncdevmem commands:

0. install driver & check version
1. turn off tcp options
	` ./disable_tcp_options `
2. open server: 
   -d ifindex; -l listen; -s server ip; -f ifname
	`sudo ./ncdevmem -d 4 -l -s 10.0.0.4 -f enp175s0np0 -p 5201`
    With perf:
        ` sudo /home/weigao/devmem-linux/tools/perf/perf record -C 1 -o /home/weigao/profiler/results/perf.data taskset -c 1 ./ncdevmem -d 7 -l -s 10.0.1.4 -f enp175s0np1 -p 5201 `
3. in atlas5, open pktforge. do client sending:
	`./client -s 10.0.0.4 -p 5201`


    sudo /home/weigao/devmem-linux/tools/perf/perf record -C 1 -o /home/weigao/profiler/results/perf.data taskset -c 1 ./ncdevmem -d 23 -l -s 10.0.1.4 -f enp175s0np1 -p 5201

    sudo /home/weigao/devmem-linux/tools/perf/perf record -C 1 -o /home/weigao/profiler/results/perf.data taskset -c 1 ./server