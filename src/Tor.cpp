#include "Tor.h"

using namespace tor;

Tor::Tor() {
	
}

void tor::Tor::Initialize()
{
	WSADATA WsaData;
	WSAStartup(0x0101, &WsaData);

	consensus.Initialize();
}
