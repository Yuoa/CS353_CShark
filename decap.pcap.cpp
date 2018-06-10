// (c) 2018 Yuoa.
// decap.pcap.cpp

#include "common.hpp"
#include "pcap.hpp"

using std::cerr;
using std::endl;
using std::string;
using std::cout;
using std::numeric_limits;
using std::streamsize;
using std::cin;

void pDecapGTPHeader() {

    cout << bold << "[Open Offline Packet Containing GTP Packet]" << def << endl;

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

        cout << bold << "[Offline Packet Analysis - GTP Decapsulation]" << def << endl;
        initPacketHandler();
        pcap_loop(pcapf, 0, pac2gtpa, NULL);

    }

    cout << "GTP Packet Header decapsulating part finished." << endl << endl;

}
