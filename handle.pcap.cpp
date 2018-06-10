// (c) 2018 Yuoa.
// handle.pcap.cpp

#include "common.hpp"
#include "pcap.hpp"

using std::cout;
using std::endl;
using std::strlen;
using std::bitset;
using std::vector;
using std::floor;
using std::log2;
using std::printf;
using std::hex;
using std::dec;
using std::setfill;
using std::string;
using std::map;
using std::set;
using std::setw;

/* These shortly-named functions are result of time lack! */

static set<string> hosts;
static vector<gtphead> gtps;

time_t pft(bool m, time_t n) { static time_t pft; if (m && (n == 0 || pft == 0)) {pft = n;}; return pft; }
time_t gpft() { return pft(false, 0); }

time_t plt(bool m, time_t n) { static time_t plt; if (m) {plt = n;}; return plt; }
time_t gplt() { return plt(false, 0); }

size_t pl(bool m, size_t n) { static size_t pl; if (m) {pl = n;}; return pl; }
size_t upl(size_t l) { return pl(true, pl(false, 0) + l); }
size_t gpl() { return pl(false, 0); }

size_t pc(bool m, size_t n) { static size_t pc; if (m) {pc = n;}; return pc; }
size_t upc() { return pc(true, pc(false, 0) + 1); }
size_t gpc() { return pc(false, 0); }

size_t pprl(bool m, short i, size_t n) { static size_t pl[3]; if (m) {pl[i] = n;}; return pl[i]; }
size_t upprl(short i, size_t l) { return pprl(true, i, pprl(false, i, 0) + l); }
size_t gpprl(short i) { return pprl(false, i, 0); }

size_t pprc(bool m, short i, size_t n) { static size_t pc[3]; if (m) {pc[i] = n;}; return pc[i]; }
size_t upprc(short i) { return pprc(true, i, pprc(false, i, 0) + 1); }
size_t gpprc(short i) { return pprc(false, i, 0); }

size_t ppol(bool m, short i, size_t n) { static size_t pl[4]; if (m) {pl[i] = n;}; return pl[i]; }
size_t uppol(short i, size_t l) { return ppol(true, i, ppol(false, i, 0) + l); }
size_t gppol(short i) { return ppol(false, i, 0); }

size_t ppoc(bool m, short i, size_t n) { static size_t pc[4]; if (m) {pc[i] = n;}; return pc[i]; }
size_t uppoc(short i) { return ppoc(true, i, ppoc(false, i, 0) + 1); }
size_t gppoc(short i) { return ppoc(false, i, 0); }

size_t phol(bool m, string i, size_t n) { static map<string, size_t> pl; if (i.compare("clear") == 0) { pl.clear(); } else if (m) {pl[i] = n;}; return pl[i]; }
size_t uphol(string i, size_t l) { return phol(true, i, phol(false, i, 0) + l); }
size_t gphol(string i) { return phol(false, i, 0); }

size_t phoc(bool m, string i, size_t n) { static map<string, size_t> pc; if (i.compare("clear") == 0) { pc.clear(); } else if (m) {pc[i] = n;}; return pc[i]; }
size_t uphoc(string i) { return phoc(true, i, phoc(false, i, 0) + 1); }
size_t gphoc(string i) { return phoc(false, i, 0); }

set<string> ghost() { return hosts; }
vector<gtphead> ggtp() { return gtps; }

size_t initPacketHandler() {
    gtps.clear();
    hosts.clear();
    phol(true, "clear", 0);
    phoc(true, "clear", 0);
    pprl(true, 0, 0);
    pprl(true, 1, 0);
    pprl(true, 2, 0);
    pprc(true, 0, 0);
    pprc(true, 1, 0);
    pprc(true, 2, 0);
    ppol(true, 0, 0);
    ppol(true, 1, 0);
    ppol(true, 2, 0);
    ppol(true, 3, 0);
    ppoc(true, 0, 0);
    ppoc(true, 1, 0);
    ppoc(true, 2, 0);
    ppoc(true, 3, 0);
    plt(true, 0);
    pl(true, 0);
    pft(true, 0);
    return pc(true, 0);
}

bool dispData(bool m, bool d) { static bool disp; if (m) {disp = d;}; return disp; }
bool dispDataConfig(bool d) { return dispData(true, d); }

void pac2both(u_char* temp, pkthead header, const u_char* packet) {

    pac2disp(temp, header, packet);
    pcap_dump(temp, header, packet);

}

void pac2disp(u_char* temp, pkthead pacHeader, const u_char* packet) {

    ethhead ethHeader = (ethhead) packet;
    packet += sizeof(struct ether_header);

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {

        iphead ipHeader = (iphead) packet;

        cout << bold << "  [No. " << upc() << "]" << def << " IPv" << ipHeader->ip_v << " packet" << endl;

        if (ipHeader->ip_p == 6) {

            tcphead tcpHeader = (tcphead) (packet + ipHeader->ip_hl * 4);
            cout << "    From: " << inet_ntoa(ipHeader->ip_src) << blue << ":" << ntohs(tcpHeader->source) << def << "\t To: " << inet_ntoa(ipHeader->ip_dst) << blue << ":" << ntohs(tcpHeader->dest) << def << "\t Sequence: " << tcpHeader->seq << endl;
            cout << "    Urgent Pointer: " << tcpHeader->urg_ptr  << "\t ACK Sequence: " << tcpHeader->ack_seq << "\t TCP Check: " << bitset<16>(tcpHeader->check) << endl;

        } else if (ipHeader->ip_p == 17) {

            udphead udpHeader = (udphead) (packet + ipHeader->ip_hl * 4);
            cout << "    From: " << inet_ntoa(ipHeader->ip_src) << blue << ":" << ntohs(udpHeader->source) << def << "\t To: " << inet_ntoa(ipHeader->ip_dst) << blue << ":" << ntohs(udpHeader->dest) << def << endl;
            cout << "    UDP Check: " << bitset<16>(udpHeader->check) << "\t UDP Length: " << udpHeader->len << endl;

        } else
            cout << "    From: " << inet_ntoa(ipHeader->ip_src) << "\t To: " << inet_ntoa(ipHeader->ip_dst) << endl;

        cout << "    Header Length: " << ipHeader->ip_hl << " words\t Identification: " << ntohs(ipHeader->ip_id) << "\t TTL: " << ntohs(ipHeader->ip_ttl) << endl;
        cout << "    Protocol: " << protocol2string(ipHeader->ip_p) << "\t Checksum: "<< ipHeader->ip_sum << "\t Offset: " << bitset<16>(ipHeader->ip_off) << endl;

        if (dispData(false, false)) {

            int length = pacHeader->len, count = 0, width = -1;
            wsize size;
            ioctl(STDOUT_FILENO, TIOCGWINSZ, &size);
            cout << "    Data:";

            while (((++(width) + 1) * 16) < size.ws_row);
            while (length--) {

                if ((count % 16) == 0)
                    cout << " ";

                if ((count++ % (width * 16) == 0))
                    cout << endl << "      ";

                printf("%02x", *(packet++));

            }

            cout << endl << endl;

        } else
            cout << endl;

    } else
        cout << bold << "  [No. " << upc() << "] " << def << gray << "None IP packet." << def << endl << endl;

}

void pac2total(u_char* temp, pkthead pacHeader, const u_char* packet) {

    if (ntohs(((ethhead) packet)->ether_type) != ETHERTYPE_IP)
        return;

    iphead ipHeader = (iphead) (packet + sizeof(struct ether_header));

    uphoc(string(inet_ntoa(ipHeader->ip_dst)));
    uphol(string(inet_ntoa(ipHeader->ip_dst)), pacHeader->len * 4);
    hosts.insert(string(inet_ntoa(ipHeader->ip_dst)));

    if (ipHeader->ip_p == 6) { // TCP

        upprc(0);
        upprl(0, pacHeader->len * 4);

        tcphead tcpHeader = (tcphead) (packet + ipHeader->ip_hl * 4 + sizeof(struct ether_header));

        if (ntohs(tcpHeader->dest) == 20 || ntohs(tcpHeader->source) == 20 || ntohs(tcpHeader->dest) == 21 || ntohs(tcpHeader->source) == 21 || ntohs(tcpHeader->dest) == 990 || ntohs(tcpHeader->source) == 990) {
            uppoc(0);
            uppol(0, pacHeader->len * 4);
        } else if (ntohs(tcpHeader->dest) == 22 || ntohs(tcpHeader->source) == 22) {
            uppoc(1);
            uppol(1, pacHeader->len * 4);
        } else if (ntohs(tcpHeader->dest) == 53 || ntohs(tcpHeader->source) == 53) {
            uppoc(2);
            uppol(2, pacHeader->len * 4);
        } else if (ntohs(tcpHeader->dest) == 80 || ntohs(tcpHeader->source) == 80 || ntohs(tcpHeader->dest) == 443 || ntohs(tcpHeader->source) == 443) {
            uppoc(3);
            uppol(3, pacHeader->len * 4);
        }

    } else if (ipHeader->ip_p == 17) { // UDP

        upprc(1);
        upprl(1, pacHeader->len * 4);

        udphead udpHeader = (udphead) (packet + ipHeader->ip_hl * 4 + sizeof(struct ether_header));

        if (ntohs(udpHeader->dest) == 69 || ntohs(udpHeader->source) == 69) {
            uppoc(0);
            uppol(0, pacHeader->len * 4);
        } else if (ntohs(udpHeader->dest) == 53 || ntohs(udpHeader->source) == 53) {
            uppoc(2);
            uppol(2, pacHeader->len * 4);
        } else if (ntohs(udpHeader->dest) == 80 || ntohs(udpHeader->source) == 80) {
            uppoc(3);
            uppol(3, pacHeader->len * 4);
        }

    } else if (ipHeader->ip_p == 1 || ipHeader->ip_p == 58) { // ICMP

        upprc(2);
        upprl(2, pacHeader->len * 4);

    }

    pft(true, pacHeader->ts.tv_sec);
    plt(true, pacHeader->ts.tv_sec);
    upc();
    upl(pacHeader->len * 4);

}

void pac2gtpa(u_char* temp, pkthead pacHeader, const u_char* packet) {

    upc();
    if (ntohs(((ethhead) packet)->ether_type) != ETHERTYPE_IP)
        return;

    gtphead gtpHeader = (gtphead) (packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));

    __u16 tlen, gtpLen = gtpHeader->length_1;
    gtpLen = gtpLen << 8;
    tlen = gtpHeader->length_2;
    gtpLen += tlen;
    __u32 tteid, gtpTEID = gtpHeader->tei_1;
    gtpTEID = gtpTEID << 24;
    tteid = gtpHeader->tei_2;
    gtpTEID += tteid << 16;
    tteid = gtpHeader->tei_3;
    gtpTEID += tteid << 8;
    gtpTEID += gtpHeader->tei_4;
    cout << "  [Packet No. " << gpc() << ": GTP]" << endl;
    cout << "    > GTP Version: " << (int) gtpHeader->version << "\t Message Type: 0x" << hex << (int) gtpHeader->msg_type << dec << endl;
    cout << "    > GTP Length: " << ntohs(gtpLen) << "\t TEID: 0x" << hex << gtpTEID << dec << endl;
    if (gtpHeader->s == 1) {

        __u16 gtpSeq = (gtpHeader->seq_2 << 8) + gtpHeader->seq_1;
        cout << "    > GTP Sequence: " << ntohs(gtpSeq) << endl;

    }
    if (gtpHeader->pn == 1) {

        cout << "    > N-PDU Number: " << ntohs(gtpHeader->npdu) << endl;

    }
    if (gtpHeader->e == 1) {

        cout << "    > Next Extension Header Type: " << ntohs(gtpHeader->neht) << endl;

    }

    cout << endl;

}
