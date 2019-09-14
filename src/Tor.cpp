#include "Tor.h"

#ifdef _CRTDBG_MAP_ALLOC
#define new new( _NORMAL_BLOCK, __FILE__, __LINE__)
#endif

using namespace tor;

Tor::Tor() {
	connected_services.reserve(5);
}

tor::Tor::~Tor()
{
	for (int i = 0; i < connected_services.size(); i++) {
		//connected_services[i].circuit_rendezvous.~Circuit();
	}

	WSACleanup();
}

int tor::Tor::Initialize()
{
	WSADATA WsaData;
	WSAStartup(0x0101, &WsaData);

	srand(time(0));

	int code = consensus.Initialize();
	if (code) {
		return 1;
	}

	return 0;
}

int tor::Tor::ConnectToOnionServer(string onion_url)
{
	connected_services.emplace_back(consensus, onion_url);

	int code = connected_services.back().ConnectToService();
	if (code) {
		return 1;
	}

	return 0;
}

int tor::Tor::GetOnionData(string query, string& output)
{
	int code = connected_services.back().MakeRequest(query, output);
	if (code) {
		return 1;
	}

	return 0;
}
