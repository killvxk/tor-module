#pragma once

#include "common.h"
#include "Circuit.h"

namespace tor {

	class Service {
	public:
		Consensus& consensus;

		string onion_url;
		vector<string> descriptors;
		vector<Relay*> descriptor_relays;

		Circuit circuit_descriptor; // need to get descriptor with intro points
		Circuit circuit_rendezvous; // main channel
		Circuit circuit_introducing; // need to introduce our rendezvous circuit

		Service(Consensus &consensus, string onion_url);

		int ConnectToService();
		int GetResponsibleDirectories();
	};

}// namespace tor#pragma once
