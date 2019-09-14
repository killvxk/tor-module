#pragma once
#include "common.h"
#include "Service.h"

namespace tor {

	class Tor {
	public:
		Consensus consensus;

		vector<Service> connected_services;
		Service *total_service = nullptr;

		Tor();
		~Tor();

		int Initialize();
		int ConnectToOnionServer(string onion_url);
		int GetOnionData(string query, string &output);
	};

}// namespace tor