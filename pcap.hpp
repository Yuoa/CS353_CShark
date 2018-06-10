// (c) 2018 Yuoa.
// pcap.hpp

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <climits>
#include <set>
#include <limits>
#include <cstring>
#include <cstdio>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cmath>
#include <iomanip>
#include <bitset>
#include <cctype>
#include <algorithm>
#include <functional>
#include <ctime>
#include <map>
#include <vector>
#include "gtp.hpp"

typedef struct gtphdr *gtphead;
typedef struct bpf_program bpfp;
typedef const struct pcap_pkthdr *pkthead;
typedef struct ip *iphead;
typedef struct tcphdr *tcphead;
typedef struct udphdr *udphead;
typedef struct ether_header *ethhead;
typedef struct winsize wsize;

size_t initPacketHandler();
size_t gpl(); // Total Packet Length
size_t gpc(); // Total Packet Count
time_t gpft(); // First Packet Timestamp (sec)
time_t gplt(); // Last Packet Timestamp (sec)
size_t gpprl(short); // Packet Length of Protocols By Type
size_t gpprc(short); // Packet Count of Protocols By Type
size_t gppol(short); // Packet Length of Ports By Type
size_t gppoc(short); // Packet Count of Ports By Type
size_t gphol(std::string); // Packet Length By Hosts
size_t gphoc(std::string); // Packet Count By Hosts
std::set<std::string> ghost(); // Get Host List
std::vector<gtphead> ggtp();

bool dispDataConfig(bool);

void pac2both(u_char*, pkthead, const u_char*);
void pac2disp(u_char*, pkthead, const u_char*);
void pac2total(u_char*, pkthead, const u_char*);
void pac2gtpa(u_char*, pkthead, const u_char*);

bpf_u_int32 basicTest(char*);
void pCapture(char*, bpf_u_int32);
void pAnalyze();
void pDecapGTPHeader();

inline bool exists (const std::string& name) { return ( access( name.c_str(), F_OK ) != -1 ); }

std::string protocol2string(u_char);
//std::string tcpport2string(u_char);
