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
		unsigned short stream_id = 1;
		string onion_url;
		short onion_port;

		vector<CircuitRelay> circuit_relays;

		// for descriptor fetch circuit
		vector<ByteSeq> descriptors;
		vector<Relay*> descriptor_relays;
		string introduction_points_string;

		// for rendezvous and introducing circiuts
		byte* rendezvous_cookie = nullptr;

		// for introducing circuit
		IntroductionPoint *introduction_point = nullptr;
		Relay *introduction_point_relay = nullptr;
		CircuitRelay *rendzvous_relay = nullptr;
		CircuitRelay *onion_relay = nullptr;

		Circuit(string onion_url, Consensus &consensus, int circuit_id);
		~Circuit();

		int Initialize(string onion_url, Consensus& consensus, vector<ByteSeq> descriptors, vector<Relay*> descriptor_relays); // for descriptor fetch
		int Initialize(string onion_url, Consensus& consensus); // for rendezvous
		int Initialize(string onion_url, Consensus& consensus, IntroductionPoint *introduction_point, 
			CircuitRelay*rendzvous_relay, CircuitRelay*onion_relay, byte *rendezvous_cookie); // for introducing
		
		int SetCircuit(int hops_number, CircuitType circuit_type);
		int EstablishConnection(int hops_number);
		int EstablishConnection(int hops_number, Relay& end_relay); // Establish circuit to end_relay
		int AddRelayToCircuit(Relay& relay);
		int CreateRelayStream(short service_port);
		int MakeStreamRequest(string data, string &output);

		int DestroyCircuit();

		// version 2
		int CreateDirStream();
		int GetFullStreamData(byte* &data, int& data_size);
		int FetchDescriptor(ByteSeq descriptor_id, string host_ip, string &descriptor);

		int EstablishRendezvous(byte* cookie);

		int MakeIntroduce();

		int FinishRendezvous(CircuitRelay* onion_relay);

		// version 3
		int EstablishIntroduction();


		int ConnectToRelay(CircuitRelay &relay);
		int ExtendToRelay(CircuitRelay& relay);

		int FullEncryptCell(byte* cell_bytes, int cell_size);
		int FullDecryptCell(byte* cell_bytes, int cell_size);

		Relay& GetRandomRelayWithFlags(RelayFlags flags);
	};

}// namespace tor