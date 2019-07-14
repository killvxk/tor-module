#pragma once

//#define CIRCUIT_DEBUG_INFO

#include "common.h"
#include "Consensus.h"

namespace tor {

	class Circuit {
	public:
		enum CircuitType {
			DescriptorFetch = 0,
			Introducing,
			Rendezvous,
		};

		Consensus &consensus;
		unsigned long circuit_id = 0;
		string onion_url;

		vector<CircuitRelay> circuit_relays;

		vector<string> descriptors;
		vector<Relay*> descriptor_relays;

		Circuit(string onion_url, Consensus &consensus);

		int Initialize(string onion_url, Consensus& consensus, vector<string> descriptors, vector<Relay*> descriptor_relays);
		int SetCircuit(int hops_number, CircuitType circuit_type);
		// Establish circuit to end_relay
		int EstablishConnection(int hops_number, Relay& end_relay);
		int AddRelayToCircuit(Relay& relay);
		int CreateDirStream();

		int ConnectToRelay(CircuitRelay &relay);
		int ExtendToRelay(CircuitRelay& relay);

		int FullEncryptCell(byte* cell_bytes, int cell_size);
		int FullDecryptCell(byte* cell_bytes, int cell_size);

		Relay& GetRandomRelayWithFlags(RelayFlags flags);
	};

}// namespace tor