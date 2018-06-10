// (c) 2018 Yuoa.
// get.dev.cpp

#include "common.hpp"
#include "dev.hpp"

using std::cout;
using std::cerr;
using std::endl;
using std::vector;

/*[Q] Why I used getifaddrs rather than pcap_findalldevs?
  [A] I don't know why, but in my server, pcap_findalldevs doesn't operated
      correctly. So I directly used getifaddrs.*/
char* getNetworkDevices() {

    ifas *devsOriginalForm;
    int getAddrResult;

    getAddrResult = getifaddrs(&devsOriginalForm);

    if (getAddrResult) {

        cerr << "Failed to find default device: " << getAddrResult << endl;
		terminate(ERR_FAIL_FINDDEVICES);

    } else {

        // Convert ifas** to vector
        vector<ifas*> devs;
        while (devsOriginalForm != NULL) {
            devs.push_back(devsOriginalForm);
            devsOriginalForm = devsOriginalForm->ifa_next;
        }

        if (devs.size() == 0) {
            cerr << "There is no network device." << endl;
            terminate(ERR_NO_NETDEVICES);
        } else {
            cout << devs.size() << " interfaces found." << endl;
        	return selectNetworkDevice(devs);
        }

    }

    return NULL;

}
