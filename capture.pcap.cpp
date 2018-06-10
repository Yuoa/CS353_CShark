// (c) 2018 Yuoa.
// capture.pcap.cpp

#include "common.hpp"
#include "pcap.hpp"

using std::cerr;
using std::endl;
using std::cout;
using std::strcmp;
using std::strcpy;
using std::cin;
using std::numeric_limits;
using std::streamsize;
using std::size_t;
using std::rename;
using std::remove;
using std::string;
using std::transform;
using std::ptr_fun;
using std::tolower;

void pCapture(char* dev, bpf_u_int32 netp) {

    char errbufl[PCAP_ERRBUF_SIZE];
    pcap_t* pcapl = pcap_open_live(dev, INT_MAX, false, 0, errbufl);

    if (pcapl == NULL) {
        cerr << "Tip: To capture packets, run with superuser permission." << endl;
        cerr << errbufl << endl;
        terminate(ERR_PCAPINIT_FAILED);
    } else {

        bpfp filter;
        string filstr;
        size_t temp = 0;

        cout << bold << "[Packet Capture Configuration]" << def << endl;

        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        // Make PCAP Filter
        do {

            if (temp == -1)
                cerr << red << "  > Compiling filter failed. Input filter string correctly:" << endl << "    " << filstr << def << endl << endl;

            cout << "  Enter filter string (default|(empty)|~): ";
            getline(cin, filstr);

            if (filstr.compare("default") == 0)
                filstr = "tcp or icmp or udp";

        } while ((temp = pcap_compile(pcapl, &filter, (char*) filstr.c_str(), 0, netp)) == -1);

        // Set PCAP Filter
        if (filstr.length()) {

            cout << green << "  > Compiling filter succeeded:" << endl << "    " << filstr << def << endl;
            if (pcap_setfilter(pcapl, &filter) == -1)
                terminate(ERR_PCAPFILTER_APPLY);
            else
                cout << green << "  > Applying filter succeeded." << def << endl << endl;

        } else
            cout << green << "  > No filter configured." << def << endl << endl;

        // Set How Many Packets to Capture
        temp = 0;
        while (true) {

            cout << "  Enter how many packets to capture [0(infty)|1-" << numeric_limits<size_t>::max() << "]: ";
            cin >> temp;

            if (temp >= 0 && temp <= numeric_limits<size_t>::max())
    			break;
    		else {

                cerr << red << "  > Entered's not in range." << def << endl << endl;

                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');

            }

        }
        if (temp == 0)
            cout << green << "  > Infinite packets are going to be captured." << def << endl << "  > Infinite options cannot save dump file." << endl << "  > You must turn off the program with Ctrl-C." << endl << red << "  > I have no time to implement user-stoppable program!" << def << endl << endl;
        else
            cout << green << "  > " << temp << " packets are going to be captured." << def << endl << endl;

        // Set If want display Data
        string dispDataAnswer;
        while (true) {

            cout << "  Do you want to display packet data? (y/n): ";
            cin >> dispDataAnswer;
            transform(dispDataAnswer.begin(), dispDataAnswer.end(), dispDataAnswer.begin(), ptr_fun<int, int>(tolower));

            if (dispDataAnswer.compare("y") == 0 || dispDataAnswer.compare("yes") == 0 || dispDataAnswer.compare("yeah") == 0 || dispDataAnswer.compare("yeap") == 0 || dispDataAnswer.compare("ok") == 0) {
                dispDataConfig(true);
                cout << green << "  > Data will displayed." << def << endl << endl;
                break;
            } else if (dispDataAnswer.compare("n") == 0 || dispDataAnswer.compare("no") == 0 || dispDataAnswer.compare("nope") == 0 || dispDataAnswer.compare("x") == 0 || dispDataAnswer.compare("not") == 0) {
                dispDataConfig(false);
                cout << green << "  > Data will NOT displayed." << def << endl << endl;
                break;
            } else
                cerr << red << "  > Please answer correctly." << def << endl << endl;

        }

        // Open pcap file if not infinite mode
        pcap_dumper_t *dumper;
        if (temp != 0) {

            dumper = pcap_dump_open(pcapl, "./.temp.pcap");

            if (dumper == NULL)
                terminate(ERR_PCAPFILE_INIT);

        }

        // Capture (temp=capc) packets
        size_t capc = temp, imax = INT_MAX;
        cout << bold << "[Capturing Packets]" << def << endl;
        initPacketHandler();
        while (capc > 0 || temp == 0) {

            if (temp != 0)
                cout << "  Trying to capture " << (capc > (imax - 1) ? (imax - 1) : capc) << "/" << temp << " packets..." << endl;
            cout << endl;

            pcap_loop(pcapl, (int) (capc > (imax - 1) ? (imax - 1) : capc), temp == 0 ? pac2disp : pac2both, (u_char*) dumper);
            capc -= (capc > (imax - 1) ? (imax - 1) : capc);

        }

        // Gathering status and show it
        struct pcap_stat stat;
        cout << bold << "[Capture Result]" << def << endl;
        if (pcap_stats(pcapl, &stat) != 0) {

            cerr << red << "  > Error in getting statistics: " << bold << pcap_geterr(pcapl) << def << endl;
            if (temp > 0)
                cerr << red << "  > You can see capture dump file at \".temp.pcap\"." << endl;

        } else {

            cout << "  > " << green << stat.ps_recv << def << " packets received by filter" << endl;
            cout << "  > " << green << stat.ps_drop << def << " packets dropped by kernel" << endl;
            cout << "  > " << green << stat.ps_ifdrop << def << " packets dropped by NIC" << endl;
            cout << "  > " << green << temp << def << " packets captured after filter" << endl;

        }
        cout << endl;

        // Close file and capturing
        if (temp != 0) pcap_dump_close(dumper);
        pcap_close(pcapl);

        // Save dump file as other name if not infinite
        if (temp != 0) {

            char pcapName[255];
            cout << bold << "[Save PCAP File]" << def << endl;

            SavePCAP:

            cout << "  Enter new pcap file name(e.g. 'test.pcap'; '-' to skip): ";
            cin >> pcapName;

            if (strcmp("-", pcapName) == 0) {

                int rmResult = remove("./.temp.pcap");
                if (rmResult) {

                    cerr << red << "  > Error during remove temporary dump file." << def << endl;
                    cerr << red << "  > You can manually delete temporary dump file '.temp.pcap'." << def << endl;

                }

                cout << "  > Successfully skipped." << endl;

            } else {

                int rnResult = rename("./.temp.pcap", pcapName);
                if (rnResult) {

                    cerr << red << "  > Error during rename temporary dump file." << def << endl;
                    cerr << red << "  > Enter another file name." << def << endl;

                    goto SavePCAP;

                }

                cout << green << "  > Successfully saved." << def << endl;

            }

            cout << endl;

        }

        cout << "Packet capturing part finished." << endl << endl;

    }

}
