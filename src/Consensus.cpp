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

	return 0;
}

int Consensus::ParseConsensus()
{
	int endOfLine = 0;
	string &bufferStr = consensus_data;
	string str = "";

	while (true) {
		endOfLine = bufferStr.find('\n');
		if (endOfLine == string::npos)
			break;
		str = bufferStr.substr(0, endOfLine + 1);

		if (str[0] == 'r' && str[1] == ' ') {
			relays.push_back(Relay(str));

			bufferStr.erase(0, endOfLine + 1);

			endOfLine = bufferStr.find('\n');
			str = bufferStr.substr(0, endOfLine);

			relays.back().ParseFlags(str);
			relays.back().id = relaysNum;

			relaysNum++;
		}

		bufferStr.erase(0, endOfLine + 1);
	}

	if (isDebug) {
		ofstream ofs("relays.txt", ios_base::trunc);
		for (int i = 0; i < relays.size(); i++) {
			ofs << i << " " << relays[i].name << " " << relays[i].dirPort << " " << relays[i].ident << " " << relays[i].ipv4 << " " << relays[i].orPort << " ";
			for (int b = 0; b < relays[i].flagsStr.size(); b++) {
				ofs << relays[i].flagsStr[b] << " ";
			}
			ofs << endl;
		}
		ofs.close();
	}

	return 0;
}
