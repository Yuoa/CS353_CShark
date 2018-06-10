// (c) 2018 Yuoa.
// common.hpp

#include <iostream>
#include <string>
#include <set>
#include <vector>
#include <iterator>

#ifndef DEF_ERRORS
	#define DEF_ERRORS
	#define ERR_FAIL_FINDDEVICES "ERR_FAIL_FINDDEVICES"
	#define ERR_NO_NETDEVICES "ERR_NO_NETDEVICES"
	#define ERR_GETDEV_FATAL "ERR_GETDEV_FATAL"
	#define ERR_BASIC_LOOKUPNET "ERR_BASIC_LOOKUPNET"
	#define ERR_PCAPINIT_FAILED "ERR_PCAPINIT_FAILED"
	#define ERR_PCAPFILE_INIT "ERR_PCAPFILE_INIT"
	#define ERR_PCAPFILE_READ "ERR_PCAPFILE_READ"
	#define ERR_PCAPFILTER_APPLY "ERR_PCAPFILTER_APPLY"
	#define ERR_MENU_UNKNOWN "ERR_MENU_UNKNOWN"
#endif

void _debug(char*);
inline void _debug() { _debug(""); }
char* _replace(char*, char*, const char*, const char*);

inline std::string c2string(char* chars) { std::string str(chars); return str; }

inline std::ostream& bold(std::ostream& o) { return o << "\e[1m"; }
inline std::ostream& red(std::ostream& o) { return o << "\e[31m"; }
inline std::ostream& green(std::ostream& o) { return o << "\e[32m"; }
inline std::ostream& cyan(std::ostream& o) { return o << "\e[36m"; }
inline std::ostream& blue(std::ostream& o) { return o << "\e[34m"; }
inline std::ostream& gray(std::ostream& o) { return o << "\e[37m"; }
inline std::ostream& def(std::ostream& o) { return o << "\e[0m"; }

template <typename T>
std::vector<T> s2vector(std::set<T> items) {
	std::vector<T> _items;
	for (auto itemi = items.begin(); itemi != items.end(); itemi++)
		_items.push_back(*itemi);
	return _items;
}

void terminate(char*);
void terminate(std::string);
