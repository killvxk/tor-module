#pragma once
#include "common.h"
#include "Service.h"

namespace tor {

	class Tor {
	public:
		Consensus consensus;

		Tor();
		void Initialize();
		int ConnectToOnionServer(string onion_url);
		string GetOnionData(string onion_url, string query);
	};

}// namespace tor