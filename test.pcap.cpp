// (c) 2018 Yuoa.
// test.pcap.cpp

#include "common.hpp"
#include "pcap.hpp"

using std::cout;
using std::endl;

bpf_u_int32 basicTest(char* dev) {

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *net, *mask;
    int ret;
    struct in_addr addr;

    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

    if (ret == -1) {

        printf("%s\n", errbuf);
        terminate(ERR_BASIC_LOOKUPNET);

    } else {

        addr.s_addr = netp;
        net = inet_ntoa(addr);
        printf("  > NET: %s\n", net);
        addr.s_addr = maskp;
        mask = inet_ntoa(addr);
        printf("  > MASK: %s\n", mask);

    }

    return netp;

}
