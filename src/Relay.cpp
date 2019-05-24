#include "Relay.h"

Relay::Relay(string input_ip, string input_name, int input_orport, int input_dirport)
{
	relay_ip.ip_string = input_ip;
	relay_name = input_name;
	relay_orport = input_orport;
	relay_dirport = input_dirport;
}

