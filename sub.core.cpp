// (c) 2018 Yuoa.
// sub.core.cpp
// (old) aux.core.cpp

#include "common.hpp"
#include "core.hpp"

using std::size_t;
using std::cout;
using std::cin;
using std::cerr;
using std::endl;
using std::hex;
using std::string;
using std::strcpy;
using std::hash;
using std::numeric_limits;
using std::streamsize;
using std::vector;
using std::distance;

void _debug(char* s) { static size_t i = 0; std::cout << "[Debug][" << i++ << "] " << s << std::endl; }

char* _replace(char* target, char* cstr, const char* cfrom, const char* cto) {
	string str(cstr);
	const string from(cfrom);
	const string to(cto);
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
    strcpy(target, (char*) str.c_str());
	return target;
}

/*[I] DO NOT USE initializer_list in makeSelection function. Build & examization
      environment is uncertain.*/
short makeSelection(char* what, vector<string> options) {

	cout << "Please select " << what << "." << endl;

	for (auto opti = options.begin(); opti != options.end(); opti++) {
		cout << "  [" << distance(options.begin(), opti) + 1 << "] " << (*opti) << endl;
	}

	short selection = 0;
	while (true) {

		cout << endl << "Select [1-" << options.size() << "]: ";
		cin >> selection;

		if (selection > 0 && selection <= options.size())
			break;
		else {

			cerr << red << "Entered's not in range." << def << endl;
			cin.clear();
			cin.ignore(numeric_limits<streamsize>::max(), '\n');

		}

	}

	return selection - 1;

}
short makeSelection(char* what, char** options, short optionc) {

	cout << "Please select " << what << "." << endl;

	char* option;
	short idx = -1, selection = 0;
	while (idx < optionc - 1) {

		option = options[++idx];
		cout << "  [" << idx + 1 << "] " << option << endl;

	}

	while (true) {

		cout << endl << "Select [1-" << optionc << "]: ";
		cin >> selection;

		if (selection > 0 && selection <= optionc)
			break;
		else {

			cerr << red << "Entered's not in range." << def << endl;
			cin.clear();
			cin.ignore(numeric_limits<streamsize>::max(), '\n');

		}

	}

	return selection - 1;

}

void terminate(char* err) { string sERR(err); return terminate(sERR); }
void terminate(string err) {

	size_t errHash = hash<string>{}(err);
	cerr << bold << red << "[!] " << def << red << "Error occured, program terminated: " << bold << err << def << red << "(0x" << hex << errHash << ')' << def << endl;
	exit(errHash);

}
