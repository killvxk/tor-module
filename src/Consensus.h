#pragma once

#include "common.h"
#include "Relay.h"
#include "CircuitRelay.h"

namespace tor {

	class Consensus {
	public:
		vector<Relay> consensus_relays;
		string consensus_data;

		vector<Relay> relays;
		int relays_num = 0;

		int Initialize();
		int GetConsensus(Relay consensus_relay);
		int ParseConsensus();

		int FillPublicKey(CircuitRelay& relay);
	};

}// namespace tor