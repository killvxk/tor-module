#include "Relay.h"

Relay::Relay(string input_ip, string input_name, int input_orport, int input_dirport)
{
	relay_ip.ip_string = input_ip;
	relay_name = input_name;
	relay_orport = input_orport;
	relay_dirport = input_dirport;
}

Relay::Relay(string full_string)
{
	string param_string;
	int param_num = 0;
	size_t space_itr = 0;

	full_string.erase(0, 2);
	space_itr = full_string.find(" ");
	full_string[full_string.length() - 1] = ' '; // make last symbol ' ' to parse last parameter
	
	while (space_itr != string::npos || full_string.length()) { // useless but safe
		if (space_itr != string::npos) {
			param_string = full_string.substr(0, space_itr); // copy param to buffer str and erase it from original
			full_string.erase(0, space_itr + 1);

			switch (param_num++) {
			case 0: {
				relay_name = param_string;
				break;
			}
			case 1: {
				relay_identity_base64 = param_string;

				relay_identity = new byte[20];
				Base64Decode(relay_identity_base64, relay_identity);

				relay_fingerprint = HashToString(relay_identity);
				break;
			}
			case 2: {
				relay_digest = param_string;
				break;
			}
			case 3: { // date part
				relay_publication_time = param_string;
				break;
			}
			case 4: { // time part
				relay_publication_time += ' '; 
				relay_publication_time += param_string;
				break;
			}
			case 5: {
				relay_ip.ip_string = param_string;
				ExpandIpStructure(relay_ip);
				break;
			}
			case 6: {
				relay_orport = stoi(param_string);
				break;
			}
			case 7: {
				relay_dirport = stoi(param_string);
				break;
			}
			default:
				break;
			}

			space_itr = full_string.find(" ");
		}
		else {
			break;
		}
	}
}

int Relay::ParseFlags(string flags_string)
{
	size_t found = 0;

	flags_string.erase(0, 2); // slice string

	found = flags_string.find("Authority");
	if (found != string::npos)
		relay_flags.Authority = true;

	found = flags_string.find("BadExit");
	if (found != string::npos)
		relay_flags.BadExit = true;

	found = flags_string.find("Exit");
	if (found != string::npos)
		relay_flags.Exit = true;

	found = flags_string.find("Fast");
	if (found != string::npos)
		relay_flags.Fast = true;

	found = flags_string.find("Guard");
	if (found != string::npos)
		relay_flags.Guard = true;

	found = flags_string.find("HSDir");
	if (found != string::npos)
		relay_flags.HSDir = true;

	found = flags_string.find("NoEdConsensus");
	if (found != string::npos)
		relay_flags.NoEdConsensus = true;

	found = flags_string.find("Stable");
	if (found != string::npos)
		relay_flags.Stable = true;

	found = flags_string.find("StaleDesc");
	if (found != string::npos)
		relay_flags.StaleDesc = true;

	found = flags_string.find("Running");
	if (found != string::npos)
		relay_flags.Running = true;

	found = flags_string.find("Valid");
	if (found != string::npos)
		relay_flags.Valid = true;

	found = flags_string.find("V2Dir");
	if (found != string::npos)
		relay_flags.V2Dir = true;

	return 0;
}

