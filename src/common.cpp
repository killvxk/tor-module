#include "common.h"

/*
Get data from ip, port, query by win socket
0 - succes
1 - can't connect
2 - recieved 0 bytes

*/
int tor::GetSocketData(string socket_ip, u_short socket_port, string& data, string query)
{
	SOCKET Socket = socket(PF_INET, SOCK_STREAM, 0);
	struct sockaddr_in sin;
	struct hostent* hp;

	char buffer[100];
	int recieved = 0, data_length = 0;
	int sent;

	
	sin.sin_family = AF_INET;
	sin.sin_port = htons(socket_port);
	hp = gethostbyname(socket_ip.c_str());
	if (!(hp == NULL)) {
		memcpy(&sin.sin_addr, hp->h_addr, 4);
	}

	if (connect(Socket, (struct sockaddr*) &sin, sizeof(sin)) == SOCKET_ERROR)
	{
		return 1;
	}

	if (!query.empty())
		sent = send(Socket, const_cast<char*>(query.c_str()), query.length(), 0);

	while (true) {
		recieved = ::recv(Socket, buffer, 100, 0);

		if (recieved) {
			data.append(buffer, recieved);

			data_length += recieved;
		}
		else {
			break;
		}
	}
	
	if (!data_length) {
		return 2;
	}

	closesocket(Socket);

	return 0;
}

int tor::Base64Decode(string data, byte* output_data)
{
	Base64Decoder decoder;
	decoder.Put(reinterpret_cast<const byte*>(data.data()), data.size());
	decoder.MessageEnd();

	size_t size = decoder.MaxRetrievable();
	if (size && size <= SIZE_MAX)
	{
		byte* buffer_data = new byte[size];
		decoder.Get(buffer_data, size);
		memcpy(output_data, buffer_data, size);
		delete[] buffer_data;
	}
	else
		return 1;

	return 0;
}

int tor::Base32Decode(byte* data, int data_length, byte* &output_data, unsigned long& output_length)
{
	//makes standart alphabet
	int lookup[256];
	const byte ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	Base32Decoder::InitializeDecodingLookupArray(lookup, ALPHABET, 32, true);
	AlgorithmParameters params = MakeParameters(Name::DecodingLookupArray(), (const int*)lookup);

	Base32Decoder  decoder;
	decoder.IsolatedInitialize(params);
	decoder.Put(data, data_length);
	decoder.MessageEnd();

	output_length = decoder.MaxRetrievable();
	output_data = new byte[output_length];
	decoder.Get(output_data, output_length);

	return 0;
}

int tor::Base32Encode(byte* data, int data_length, byte* &output_data, unsigned long& output_length)
{
	//makes standart alphabet
	const byte ALPHABET[] = "abcdefghijklmnopqrstuvwxyz234567";//ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
	AlgorithmParameters params = MakeParameters(Name::EncodingLookupArray(), (const byte*)ALPHABET);

	Base32Encoder encoder;
	encoder.IsolatedInitialize(params);
	encoder.Put(data, data_length);
	encoder.MessageEnd();

	output_length = encoder.MaxRetrievable();
	output_data = new byte[output_length];
	encoder.Get(output_data, output_length);

	return 0;
}

int tor::GetSHA1(byte* date, int data_length, byte* hash)
{
	SHA1().CalculateDigest(hash, date, data_length);

	return 0;
}

int tor::RSAEncrypt(byte* input_data, int input_size, byte* output_data, int& output_size, RSAES_OAEP_SHA_Encryptor& encryptor)
{
	AutoSeededRandomPool random_pool;
	size_t ecl = encryptor.CiphertextLength(input_size);
	SecByteBlock ciphertext(ecl);

	encryptor.Encrypt(random_pool, input_data, input_size, ciphertext);

	output_size = ciphertext.size();
	memcpy(output_data, ciphertext.data(), output_size);

	return 0;
}

int tor::AESEncrypt(byte* input_data, int input_size, byte* output_data, int& output_size, SecByteBlock key)
{
	byte* iv = new byte[16];
	memset(iv, 0, 16);

	CTR_Mode<AES>::Encryption encryptor;
	encryptor.SetKeyWithIV(key, key.size(), iv);
	encryptor.ProcessData(output_data, input_data, input_size);

	output_size = input_size;

	delete[] iv;

	return 0;
}

/*
transform byte hash to string like 'FFAB99'
*/
string tor::HashToString(byte* hash, int hash_length)
{
	string output_string = "";
	char buffer[3];

	for (int i = 0; i < hash_length; i++) {
		_itoa_s(static_cast<int>(hash[i]), buffer, 3,  16);

		if (hash[i] < 0x10) { // if it has only 1 byte, then expand it
			output_string += '0';
		}

		output_string += buffer;
	}

	return output_string;
}


/*
Expands IP structure by its string
*/
int tor::ExpandIpStructure(IP& ip_struct)
{
	string buffer_string = "";
	int i = 0, b = 0;

	while (i != ip_struct.ip_string.length()) {
		if (ip_struct.ip_string[i] == '.' || i == (ip_struct.ip_string.length() - 1)) {
			if (i == (ip_struct.ip_string.length() - 1)) {
				buffer_string += ip_struct.ip_string[i];
			}

			ip_struct.octets[b] = stoi(buffer_string.c_str());
			b++;

			buffer_string.clear();
		}
		else {
			buffer_string += ip_struct.ip_string[i];
		}

		i++;
	}

	return 0;
}


const wchar_t* tor::GetWC(const char* c)
{
	const size_t cSize = strlen(c) + 1;
	wchar_t* wc = new wchar_t[cSize];
	mbstowcs(wc, c, cSize);

	return wc;
}