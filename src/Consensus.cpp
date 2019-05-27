#include "Consensus.h"


int Consensus::Initialize()
{
	consensus_relays.push_back(Relay("194.109.206.212", "dizum", 443, 80));

	GetConsensus(consensus_relays[0]);

	ParseConsensus();

	return 0;
}

int Consensus::GetConsensus(Relay consensus_relay)
{
	string query = "GET /tor/status-vote/current/consensus HTTP/1.0\r\nHost: " + consensus_relay.relay_ip.ip_string + "\r\n\r\n";

	GetSocketData(consensus_relay.relay_ip.ip_string, consensus_relay.relay_dirport, consensus_data, query);

	//slice http header
	size_t found = consensus_data.find("network-status-version");
	if (found != string::npos)
		consensus_data.erase(0, found);

	ofstream ofs("consensus", ios_base::trunc);
	ofs << consensus_data << endl;
	ofs.close();

	return 0;
}

int Consensus::ParseConsensus()
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

	
	
	ofstream ofs("relays.txt", ios_base::trunc);
	for (int i = 0; i < relays.size(); i++) {
		ofs << i << " " << relays[i].relay_name << " " << relays[i].relay_dirport << " " << relays[i].relay_identity_base64 << " " << relays[i].relay_ip.ip_string << " " << relays[i].relay_orport << " ";
		//for (int b = 0; b < relays[i].flagsStr.size(); b++) {
		//	ofs << relays[i].flagsStr[b] << " ";
		//}
		ofs << endl;
	}
	ofs.close();

	

	return 0;
}

int Consensus::FillPublicKey(Relay& relay)
{
	int key_relay_id = 0;
	string descriptor_string, query, onion_key_str;
	size_t key_itr_start, key_itr_end;

	while (true) {
		while (true) {
			key_relay_id = rand() % relays.size();
			if (relays[key_relay_id].relay_flags.V2Dir) 
				break; // found some dir relay
		}

		query = "GET /tor/server/fp/" + relay.relay_fingerprint + " HTTP/1.0\r\nHost: " + relays[key_relay_id].relay_ip.ip_string + "\r\n\r\n";
		GetSocketData(relays[key_relay_id].relay_ip.ip_string, relays[key_relay_id].relay_dirport, descriptor_string, query);

		if (descriptor_string.find("200 OK") != string::npos) // if response has HTTP success code "200 OK" then break, otherwise continue
			break;
	}

	key_itr_start = descriptor_string.find("onion-key") + 41; // make itr after "onion-key" and "-----BEGIN RSA PUBLIC KEY-----"
														// onion key start
	onion_key_str = descriptor_string.substr(key_itr_start);
	onion_key_str.erase(onion_key_str.find("-----END RSA PUBLIC KEY-----")); // erase after onion-key's end
	// we don't need to delete all '\n' chars because of BERDecoder

	ByteQueue queue;
	Base64Decoder key_decoder;

	key_decoder.Attach(new Redirector(queue));
	key_decoder.Put(reinterpret_cast<const byte*>(onion_key_str.data()), onion_key_str.length());
	key_decoder.MessageEnd();

	relay.onion_key.BERDecodePublicKey(queue, false, queue.MaxRetrievable()); // fill onion-key to object
	relay.onion_encryptor = RSAES_OAEP_SHA_Encryptor(relay.onion_key); // create encryptor with onion-key

	return 0;
}

int Consensus::FillPublicKey(int relay_id)
{
	return FillPublicKey(relays[relay_id]);
}

