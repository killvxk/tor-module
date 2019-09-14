#include "common.h"
#include "Tor.h"

using namespace tor;

int main()
{
	string answer = "";

	_CrtMemState _ms;
	_CrtMemCheckpoint(&_ms);

	while (true) {
		Tor tor;
		int code = tor.Initialize();
		if (code) {
			cout << endl << "Error in initialization process." << endl << endl;
			goto error;

			return 1;
		}

		//http://duskgytldkxiuqc6.onion/fedpapers/federndx.htm
		code = tor.ConnectToOnionServer("duskgytldkxiuqc6.onion");
		if (code) {
			cout << endl << "Error in connection process." << endl << endl;

			goto error;

			return 2;
		}

		code = tor.GetOnionData("/index.html", answer);
		if (code) {
			cout << endl << "Error in getting data process." << endl << endl;
			goto error;

			return 3;
		}

		cout << answer << endl;

		error:

		tor.~Tor();

		//system("pause");

		break;
	}

	_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
	_CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDOUT);

	_CrtMemDumpAllObjectsSince(&_ms);

	system("pause");
}