// (c) 2018 Yuoa.
// select.dev.cpp

#include "common.hpp"
#include "core.hpp"
#include "dev.hpp"

using std::cout;
using std::cerr;
using std::cin;
using std::endl;
using std::string;
using std::set;
using std::distance;
using std::vector;
using std::numeric_limits;
using std::streamsize;

char* selectNetworkDevice(vector<ifas*> devs) {

    // Filter: get only device names
    // Info: pcap_lookupnet function requires only device name
    set<string> devNameSet;
    for (auto devi = devs.begin(); devi != devs.end(); devi++)
        devNameSet.insert(c2string((*devi)->ifa_name));

    if (devNameSet.size() == 1)
        cout << "1 device found: " << *devNameSet.begin() << endl;
    else {

        short devNum = 0;
        short devCount = devNameSet.size();

        cout << devCount << " devices found." << endl << endl;
        cout << bold << "[Selecting A Network Device]" << def << endl;

        vector<string> devNames = s2vector<string>(devNameSet);
        return (char*) devNames.at(makeSelection("a target device", devNames)).c_str();

    }

    return (char*) (*(devNameSet.begin())).c_str();

}
