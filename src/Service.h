#pragma once

#include "common.h"
#include "Circuit.h"

namespace tor {

	class Service {
	public:
		Consensus& consensus;

		string onion_url;
		short onion_port = 80;
		vector<ByteSeq> descriptors;
		vector<Relay*> descriptor_relays;
		
		CircuitRelay onion_relay;

		vector<IntroductionPoint> introduction_points;

		Circuit circuit_descriptor; // need to get descriptor with intro points
		Circuit circuit_rendezvous; // main channel
		Circuit circuit_introducing; // need to introduce our rendezvous circuit

		Service(Consensus &consensus, string onion_url);

		int ConnectToService();
		int MakeRequest(string query, string &answer);
		int GetResponsibleDirectories();
		int ParseIntroductionPoints(string descriptor);
	};

}// namespace tor
