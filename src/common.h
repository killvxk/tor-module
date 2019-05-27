#pragma once

//some tor constants
#define DH_LEN 128
#define HASH_LEN 20
#define KEY_LEN 16
#define DH_SEC_LEN 40
#define PK_ENC_LEN 128
#define PK_PAD_LEN 42

//c++ headers
#include <string>
#include <vector>
#include <iostream>
#include <fstream>

//winapi headers
#include <windows.h> 
#include <winsock.h>

#pragma comment(lib, "WSock32.Lib")

//CryptoPP headers
#include <base64.h>
#include <sha.h>
#include <sha3.h>
#include <rsa.h>

using namespace std;
using namespace CryptoPP;

struct IP {
	int octets[4];

	string ip_string;
};

enum flags {
	Authority = 0,
	BadExit,
	Exit,
	Fast,
	Guard,
	HSDir,
	NoEdConsensus,
	Stable,
	StaleDesc,
	Running,
	Valid,
	V2Dir,
};

int GetSocketData(string socket_ip, u_short socket_port, string &data, string query = "");
int Base64Decode(string data, byte* output_data);
string HashToString(byte *hash, int hash_length = HASH_LEN);
int ExpandIpStructure(IP& ip_struct);