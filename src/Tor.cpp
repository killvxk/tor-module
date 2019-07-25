#include "Tor.h"

using namespace tor;

Tor::Tor() {
	
}

tor::Tor::~Tor()
{
	for (int i = 0; i < connected_services.size(); i++) {
		//connected_services[i].~Service();
	}
}

void tor::Tor::Initialize()
{
	WSADATA WsaData;
	WSAStartup(0x0101, &WsaData);

	srand(time(0));

	consensus.Initialize();
}

int tor::Tor::ConnectToOnionServer(string onion_url)
{
	connected_services.push_back(Service(consensus, onion_url));

	connected_services.back().ConnectToService();

	return 0;
}

int tor::Tor::GetOnionData(string query, string& output)
{
	connected_services.back().MakeRequest(query, output);

	return 0;
}
