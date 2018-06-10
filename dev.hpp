// (c) 2018 Yuoa.
// dev.hpp

#include <limits>
#include <ifaddrs.h>
#include <sys/types.h>

typedef struct ifaddrs ifas;

char* getNetworkDevices();
char* selectNetworkDevice(std::vector<ifas*>);

inline char* getNetworkDevice() { return getNetworkDevices(); }
