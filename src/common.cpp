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
