// (c) 2018 Yuoa.
// analyze.pcap.cpp

#include "common.hpp"
#include "pcap.hpp"

using std::cerr;
using std::endl;
using std::string;
using std::cout;
using std::numeric_limits;
using std::streamsize;
using std::cin;

void pAnalyze() {

    cout << bold << "[Open Offline Packet]" << def << endl;

    cin.clear();
    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    bool first = true;
    string pfileName;
    do {

        if (!first)
            cerr << red << "  > That file does not exist." << def << endl << endl;
        cout << "  Enter PCAP file name to open: ";
        cin >> pfileName;

        first = false;

    } while (!exists(pfileName));

    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t *pcapf = pcap_open_offline(pfileName.c_str(), errbuff), *pcapt = pcapf;

    if (pcapf == NULL){
        cerr << errbuff << endl;
        terminate(ERR_PCAPFILE_READ);
    } else {

        cout << green << "  > PCAP file open succeed." << def << endl << endl;

        initPacketHandler();
        pcap_loop(pcapf, 0, pac2total, NULL);

        cout << bold << "[Offline Packet Analysis - Overall]" << def << endl;
        cout << "  > Packets: " << green << gpc() << def << endl;
        cout << "  > Total bytes: " << green << gpl() << def << " bytes" << endl;
        cout << "  > Time between first packet and last packet: " << green << gplt() - gpft() << def << " sec(s)" << endl;
        cout << "  > Average packet size: " << green << float(gpl()) / float(gpc()) << def << " bytes" << endl;
        cout << "  > Average Packet Inter-arrival Time: " << green << float(gplt() - gpft()) / float(gpc()) << def << " sec(s)" << endl << endl;

        cout << bold << "[Offline Packet Analysis - TCP/UDP/ICMP]" << def << endl;
        cout << "  > TCP Packets: " << green << gpprc(0) << def << "\t TCP bytes: " << green << gpprl(0) << def << " bytes" << endl;
        cout << "  > UDP Packets: " << green << gpprc(1) << def << "\t UDP bytes: " << green << gpprl(1) << def << " bytes" << endl;
        cout << "  > ICMP Packets: " << green << gpprc(2) << def << "\t ICMP bytes: " << green << gpprl(2) << def << " bytes" << endl << endl;

        cout << bold << "[Offline Packet Analysis - FTP/SSH/DNS/HTTP]" << def << endl;
        cout << "  > FTP Packets: " << green << gppoc(0) << def << "\t FTP bytes: " << green << gppol(0) << def << " bytes" << endl;
        cout << "  > SSH Packets: " << green << gppoc(1) << def << "\t SSH bytes: " << green << gppol(1) << def << " bytes" << endl;
        cout << "  > DNS Packets: " << green << gppoc(2) << def << "\t DNS bytes: " << green << gppol(2) << def << " bytes" << endl;
        cout << "  > HTTP(S) Packets: " << green << gppoc(3) << def << "\t HTTP(S) bytes: " << green << gppol(3) << def << " bytes" << endl << endl;

        cout << bold << "[Offline Packet Analysis - By Destination]" << def << endl;
        for(auto& host:ghost())
            cout << "  > " << host << ": " << green << gphoc(host) << def << " packet(s), " << green << gphol(host) << def << " bytes" << endl;
        cout << endl;

    }

    cout << "Packet analysis part finished." << endl << endl;

}
