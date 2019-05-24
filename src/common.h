#pragma once

//c++ headers
#include <string>
#include <vector>
#include <iostream>
#include <fstream>

//winapi headers
#include <windows.h> 
#include <winsock.h>

#pragma comment(lib, "WSock32.Lib")

using namespace std;

struct IP {
	int first_octet;
	int second_octet;
	int third_octet;
	int fouth_octet;

	string ip_string;
};

int GetSocketData(string socket_ip, u_short socket_port, string &data, string query = "");