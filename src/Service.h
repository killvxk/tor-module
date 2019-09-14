#pragma once

#include "common.h"
#include "Circuit.h"

namespace tor {

	class Service {
	public:
		Consensus& consensus;

		string onion_url;
		short onion_port = 80;
		vector<vector<byte>> descriptors;
		vector<Relay*> descriptor_relays;

		static const int max_circuit_reset_attempts = 3;
		
		CircuitRelay onion_relay;

		vector<IntroductionPoint> introduction_points;

		int circuit_inc = 1;
		Circuit circuit_descriptor; // need to get descriptor with intro points
		Circuit circuit_rendezvous; // main channel
		Circuit circuit_introducing; // need to introduce our rendezvous circuit

		Service(Consensus &consensus, string onion_url);
		~Service();

		int ConnectToService();
		int MakeRequest(string query, string &answer);
		int GetResponsibleDirectories();
		int ParseIntroductionPoints(string descriptor);
	};

}// namespace tor
