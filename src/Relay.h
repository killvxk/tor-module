#pragma once

#include "common.h"

class Relay{
public:
	int relay_id = 0;
	unsigned long circuit_id = 0;
	string relay_name;
	IP relay_ip;
	int relay_orport, relay_dirport;

	Relay(string input_ip, string input_name, int input_orport, int input_dirport);
};