#pragma once
#define _CRT_SECURE_NO_WARNINGS
#undef UNICODE

//some tor constants
#define DH_LEN 128
#define HASH_LEN 20
#define KEY_LEN 16
#define DH_SEC_LEN 40
#define PK_ENC_LEN 128
#define PK_PAD_LEN 42

//TAP defines
#define PK_DATA_LEN (PK_ENC_LEN - PK_PAD_LEN)
#define PK_DATA_LEN_WITH_KEY (PK_DATA_LEN - KEY_LEN)
#define TAP_C_HANDSHAKE_LEN (DH_LEN + KEY_LEN + PK_PAD_LEN).
#define TAP_S_HANDSHAKE_LEN (DH_LEN + HASH_LEN).

//useful macros
#define LOW(x) (x & 0xFF)
#define HIGH(x) ((x >> 8) & 0xFF)

//c++ headers
#include <string>
#include <vector>
#include <iostream>
#include <fstream>

//winapi headers
#include <windows.h> 
#include <winsock.h>

//ssl imports
#define SECURITY_WIN32
#define IO_BUFFER_SIZE  0x10000
#include <sspi.h>
#include <schannel.h>
#pragma comment(lib, "WSock32.Lib")
#pragma comment(lib, "Crypt32.Lib")

//CryptoPP headers
#include <base64.h>
#include <base32.h>
#include <hex.h>
#include <sha.h>
#include <sha3.h>
#include <rsa.h>
#include <dh.h>
#include <osrng.h>
#include <modes.h>

using namespace std;
using namespace CryptoPP;

namespace tor {
	struct IP {
		int octets[4];

		string ip_string;
	};

	// for circuit
	union word16 {
		byte bytes[4];
		int data;
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
	};

	/*
	connects to server and get data
	*/
	int GetSocketData(string socket_ip, u_short socket_port, string& data, string query = "");

	int Base64Decode(string data, byte* output_data);
	int Base32Decode(byte* data, int data_length, byte* &output_data, unsigned long& output_length);
	int Base32Encode(byte* data, int data_length, byte* &output_data, unsigned long& output_length);

	int GetSHA1(byte* date, int data_length, byte* hash);

	int RSAEncrypt(byte* input_data, int input_size, byte* output_data, int& output_size, RSAES_OAEP_SHA_Encryptor &encryptor);
	int AESEncrypt(byte* input_data, int input_size, byte* output_data, int& output_size, SecByteBlock key);

	string HashToString(byte* hash, int hash_length = HASH_LEN);
	int ExpandIpStructure(IP& ip_struct);
	const wchar_t* GetWC(const char* c);
}