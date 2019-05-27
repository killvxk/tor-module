#include "common.h"

/*
Get data from ip, port, query by win socket
0 - succes
1 - can't connect
2 - recieved 0 bytes

*/
int GetSocketData(string socket_ip, u_short socket_port, string& data, string query)
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
		cout << WSAGetLastError() << endl;
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

int Base64Decode(string data, byte* output_data)
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

/*
transform byte hash to string like 'FFAB99'
*/
string HashToString(byte* hash, int hash_length)
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
int ExpandIpStructure(IP& ip_struct)
{
	string buffer_string = "";
	int i = 0, b = 0;

	while (i != ip_struct.ip_string.length()) {
		if (ip_struct.ip_string[i] == '.' || i == (ip_struct.ip_string.length() - 1)) {
			if (i == (ip_struct.ip_string.length() - 1)) {
				buffer_string += ip_struct.ip_string[i];
			}

			ip_struct.octets[b] = stoi(ip_struct.ip_string.c_str());
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
