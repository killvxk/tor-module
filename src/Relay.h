#pragma once

#include "common.h"

class Relay{
public:
	int relay_id = 0;

	// relay info
	string relay_name; // nickname
	string relay_identity_base64; // identity's hash base64 (27)
	byte *relay_identity = nullptr; // identity's hash (20)
	string relay_fingerprint; // identity fingerprint (uses to get public key and extend circuit(hz)) (40)
	string relay_digest; // hash of its most recent descriptor
	string relay_publication_time; // the publication time of its most recent descriptor, in the form YYYY - MM - DD HH : MM:SS, in UTC.
	IP relay_ip; // ip struct
	int relay_orport = 0, relay_dirport = 0; // relay's ports

	struct RelayFlags {
		bool Authority = false;
		bool BadExit = false;
		bool Exit = false;
		bool Fast = false;
		bool Guard = false;
		bool HSDir = false;
		bool NoEdConsensus = false;
		bool Stable = false;
		bool StaleDesc = false;
		bool Running = false;
		bool Valid = false;
		bool V2Dir = false;
	}relay_flags;

	// circuit info
	unsigned long circuit_id = 0;

	// crypto objects
	RSA::PublicKey onion_key; // public onion-key rsa (uses in CREATE, EXTEND cells)
	RSAES_OAEP_SHA_Encryptor onion_encryptor;

	Relay(string input_ip, string input_name, int input_orport, int input_dirport);
	Relay(string full_string);

	int ParseFlags(string flags_string);
};