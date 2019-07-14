#include "Tor.h"

using namespace tor;

Tor::Tor() {
	
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
	Service onion_service(consensus, onion_url);
	onion_service.ConnectToService();

	return 0;
}
