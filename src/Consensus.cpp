#include "Consensus.h"

#ifdef _CRTDBG_MAP_ALLOC
#define new new( _NORMAL_BLOCK, __FILE__, __LINE__)
#endif

int tor::Consensus::Initialize()
{
	consensus_relays.push_back(Relay("194.109.206.212", "dizum", 443, 80));
	consensus_relays.push_back(Relay("66.111.2.131", "Serge", 9001, 9030));
	consensus_relays.push_back(Relay("128.31.0.34", "moria1", 9101, 9131));
	consensus_relays.push_back(Relay("86.59.21.38", "tor26", 443, 80));
	consensus_relays.push_back(Relay("204.13.164.118", "bastet", 443, 80));
	consensus_relays.push_back(Relay("171.25.193.9", "maatuska", 80, 443));
	consensus_relays.push_back(Relay("193.23.244.244", "dannenberg", 443, 80));
	consensus_relays.push_back(Relay("154.35.175.225", "Faravahar", 443, 80));
	consensus_relays.push_back(Relay("131.188.40.189", "gabelmoo", 443, 80));
	consensus_relays.push_back(Relay("199.58.81.140", "longclaw", 443, 80));

	for (int i = 0; i < consensus_relays.size(); i++) {
		if (!GetConsensus(consensus_relays[i])) {
			break;
		}
	}

	if (consensus_data.length() <= 0) {
		return 1;
	}

	ParseConsensus();

	cout << "Consensus parsed" << endl;

	return 0;
}

int tor::Consensus::GetConsensus(Relay consensus_relay)
{
	string query = "GET /tor/status-vote/current/consensus HTTP/1.0\r\nHost: " + consensus_relay.relay_ip.ip_string + "\r\n\r\n";

	int code_return = GetSocketData(consensus_relay.relay_ip.ip_string, consensus_relay.relay_dirport, consensus_data, query);
	if (code_return) {
		return 1;
	}

	//slice http header
	size_t found = consensus_data.find("network-status-version");
	if (found != string::npos)
		consensus_data.erase(0, found);
	else
		return 2;

	ofstream ofs("consensus", ios_base::trunc);
	ofs << consensus_data << endl;
	ofs.close();

	return 0;
}

int tor::Consensus::ParseConsensus()
{
	int line_end_ptr = 0;
	string line_string = "";

	while (true) {
		line_end_ptr = consensus_data.find('\n');
		if (line_end_ptr == string::npos)
			break;
		line_string = consensus_data.substr(0, line_end_ptr + 1);

		if (line_string[0] == 'r' && line_string[1] == ' ') {
			relays.push_back(Relay(line_string));
			relays.back().relay_id = relays_num++;
		}
		if (line_string[0] == 's' && line_string[1] == ' ') {
			relays.back().ParseFlags(line_string);
		}

		consensus_data.erase(0, line_end_ptr + 1);
	}

	return 0;
}

int tor::Consensus::FillPublicKey(CircuitRelay& relay)
{
	int key_relay_id = 0;
	string descriptor_string, query, onion_key_str;
	size_t key_itr;

	while (true) {
		while (true) {
			key_relay_id = rand() % relays.size();
			if (relays[key_relay_id].relay_flags.V2Dir) 
				break; // found some dir relay
		}

		query = "GET /tor/server/fp/" + relay.relay_fingerprint + " HTTP/1.0\r\nHost: " + relays[key_relay_id].relay_ip.ip_string + "\r\n\r\n";
		int code = GetSocketData(relays[key_relay_id].relay_ip.ip_string, relays[key_relay_id].relay_dirport, descriptor_string, query);
		if (code) {
			continue;
		}

		if (descriptor_string.find("200 OK") != string::npos) // if response has HTTP success code "200 OK" then break, otherwise continue
			break;
	}

	key_itr = descriptor_string.find("onion-key") + 41; // make itr after "onion-key" and "-----BEGIN RSA PUBLIC KEY-----"
														// onion key start
	onion_key_str = descriptor_string.substr(key_itr);
	onion_key_str.erase(onion_key_str.find("-----END RSA PUBLIC KEY-----")); // erase after onion-key's end
	// we don't need to delete all '\n' chars because of BERDecoder

	ByteQueue queue;
	Base64Decoder key_decoder;

	key_decoder.Attach(new Redirector(queue));
	key_decoder.Put(reinterpret_cast<const byte*>(onion_key_str.data()), onion_key_str.length());
	key_decoder.MessageEnd();

	relay.onion_key.BERDecodePublicKey(queue, false, queue.MaxRetrievable()); // fill onion-key to object
	relay.onion_encryptor = RSAES_OAEP_SHA_Encryptor(relay.onion_key); // create encryptor with onion-key
	relay.onion_key_string = onion_key_str;

	Base64Decode(onion_key_str, relay.onion_key_bytes, relay.onion_key_bytes_size);

	return 0;
}

