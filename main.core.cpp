// (c) 2018 Yuoa.
// main.core.cpp

#include "common.hpp"
#include "core.hpp"
#include "dev.hpp"
#include "pcap.hpp"

using std::cout;
using std::endl;

int main(/*int arc, char** ars*/) {

	cout << bold << "Welcome to " << cyan << "CShark 353" << def << bold << "!" << def << endl << endl;

	char* devName = getNetworkDevice();

	if (devName == NULL)
		terminate(ERR_GETDEV_FATAL);
	else {

		// Let user know what xemself selected
		cout << "Selected device: " << devName << endl << endl;

		// Basic netmask inforwmation gathering test
		cout << bold << "[Basic PCAP Loopup Test]" << def << endl;
		bpf_u_int32 netp = basicTest(devName);
		cout << endl << green << "Basic Test Completed Successfully." << def << endl << endl;

		while (true) {
			// Make user select what function does he want
			cout << bold << "[Selecting A Function]" << def << endl;
			char *options[] = {"Capture packets", "Analyze packets", "Decapsulate GTP Header", "Exit program"};
			short partNo = makeSelection("the way what you want", options, 4);
			cout << "Selected part: " << options[partNo] << endl << endl;

			// Go each part with device name
			if (partNo == 3) break;
			switch (partNo) {

				case 0: // "Capture packets"
					pCapture(devName, netp);
					break;

				case 1: // "Analyze packets"
					pAnalyze();
					break;

				case 2: // "Decapsulate packets"
					pDecapGTPHeader();
					break;

				default: // ERROR!
					terminate(ERR_MENU_UNKNOWN);
					break;

			}

		}

	}

	cout << bold << "Bye!" << endl << endl;

	return 0;

}
