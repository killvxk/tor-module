#include "Cell.h"

#ifdef _CRTDBG_MAP_ALLOC
#define new new( _NORMAL_BLOCK, __FILE__, __LINE__)
#endif

tor::Cell::Cell(CellType cell_type, CellMode cell_mode, unsigned long circuit_id, short stream_id) :
	cell_type(cell_type), cell_mode(cell_mode), circuit_id(circuit_id), stream_id(stream_id)
{
	if (cell_mode == tor::Cell::CellMode::GET)
		return;
	if (cell_type == CellType::VERSIONS) {
		cell_size = 9;
		cell_bytes = new byte[cell_size];
	}
	else {
		cell_size = 514;
		cell_bytes = new byte[cell_size];
		memset(cell_bytes, 0, cell_size);

		cell_bytes[4] = cell_type;
	}
}

tor::Cell::Cell(CellType cell_type, PayloadCellType cell_payload_type, CellMode cell_mode, unsigned long circuit_id, short stream_id) :
	cell_type(cell_type), cell_payload_type(cell_payload_type), cell_mode(cell_mode), circuit_id(circuit_id), stream_id(stream_id)
{
	if (cell_mode == tor::Cell::CellMode::GET)
		return;

	cell_size = 514;
	cell_bytes = new byte[cell_size];
	memset(cell_bytes, 0, cell_size);

	cell_bytes[4] = cell_type;
	cell_bytes[5] = cell_payload_type;
}

tor::Cell::~Cell()
{
	if (cell_bytes != nullptr && cell_size)
		delete[] cell_bytes;

	cell_size = 0;
}

int tor::Cell::FillCircuitId()
{
	// TODO: remake it with memory tricks
	unsigned char* bytes = reinterpret_cast<unsigned char*>(&circuit_id);

	cell_bytes[0] = static_cast<byte>(bytes[3]);
	cell_bytes[1] = static_cast<byte>(bytes[2]);
	cell_bytes[2] = static_cast<byte>(bytes[1]);
	cell_bytes[3] = static_cast<byte>(bytes[0]);

	return 0;
}

int tor::Cell::FillRelayPayload(byte* payload, short payload_size)
{
	cell_bytes[6] = 0; // 'recognized'
	cell_bytes[7] = 0; // must be zeros

	cell_bytes[8] = HIGH(stream_id); // StreamID
	cell_bytes[9] = LOW(stream_id);

	cell_bytes[10] = 0; // digest
	cell_bytes[11] = 0;
	cell_bytes[12] = 0;
	cell_bytes[13] = 0;

	cell_bytes[14] = HIGH(payload_size); // length
	cell_bytes[15] = LOW(payload_size);

	// copy payload
	if (payload_size) 
		memcpy(&cell_bytes[16], payload, payload_size);

	return 0;
}

int tor::Cell::ComputeDigest(vector<byte> &forward_bytes)
{
	// compute digest
	int old_length = forward_bytes.size();
	forward_bytes.resize(old_length + (cell_size - 5));
	memcpy(&forward_bytes[old_length], &cell_bytes[5], cell_size - 5);

	byte digest[CryptoPP::SHA1::DIGESTSIZE];
	GetSHA1(forward_bytes.data(), forward_bytes.size(), digest);

	memcpy(&cell_bytes[10], digest, 4); // digest

	return 0;
}

int tor::Cell::FillVersions()
{
	if (cell_type == CellType::VERSIONS) {
		cell_bytes[0] = 0; // circuit id
		cell_bytes[1] = 0;
		cell_bytes[2] = CellType::VERSIONS; //cell type
		cell_bytes[3] = 0; // payload length
		cell_bytes[4] = 4;
		cell_bytes[5] = 0; // payload
		cell_bytes[6] = 4;
		cell_bytes[7] = 0;
		cell_bytes[8] = 5;
	}
	else {
		return 1;
	}

	return 0;
}

int tor::Cell::FillNetInfo(sockaddr_in& sin)
{ 
	time_t rawtime;
	time(&rawtime);

	unsigned long number = static_cast<uint32_t>(rawtime);
	unsigned char* timestamp_bytes = reinterpret_cast<unsigned char*>(&number);

	cell_bytes[5] = static_cast<byte>(timestamp_bytes[3]); // timestamp
	cell_bytes[6] = static_cast<byte>(timestamp_bytes[2]);
	cell_bytes[7] = static_cast<byte>(timestamp_bytes[1]);
	cell_bytes[8] = static_cast<byte>(timestamp_bytes[0]);


	cell_bytes[9] = 4; // type 4 = IPv4
	cell_bytes[10] = 4; // addr length 4
	cell_bytes[11] = sin.sin_addr.S_un.S_un_b.s_b1; // address
	cell_bytes[12] = sin.sin_addr.S_un.S_un_b.s_b2;
	cell_bytes[13] = sin.sin_addr.S_un.S_un_b.s_b3;
	cell_bytes[14] = sin.sin_addr.S_un.S_un_b.s_b4;

	cell_bytes[15] = 1; // number of addresses
	cell_bytes[16] = 4; // type
	cell_bytes[17] = 4; // length
	cell_bytes[18] = 0; // address
	cell_bytes[19] = 0;
	cell_bytes[20] = 0;
	cell_bytes[21] = 0;

	return 0;
}

int tor::Cell::FillCreate2(byte* onion_skin, short onion_skin_size)
{
	FillCircuitId();

	cell_bytes[5] = 0;
	cell_bytes[6] = 0; // TAP handshake
	cell_bytes[7] = HIGH(onion_skin_size); // handshake data length
	cell_bytes[8] = LOW(onion_skin_size);

	memcpy(&cell_bytes[9], onion_skin, onion_skin_size); // handshake data

	return 0;
}

int tor::Cell::FillCreate(byte* onion_skin, short onion_skin_size)
{
	FillCircuitId();

	memcpy(&cell_bytes[5], onion_skin, onion_skin_size); // handshake data

	return 0;
}

int tor::Cell::FillExtend2(byte* onion_skin, short onion_skin_size, tor::IP relay_ip, short relay_port)
{
	FillCircuitId();

	// create cell payload
	short payload_size = 1 + 1 + 1 + 4 + 2 + 2 + 2 + onion_skin_size; // num of spec, spec type, spec length, ip, port, handshake type, handshake data
	byte* payload = new byte[payload_size];
	payload[0] = 1; // spec num
	payload[1] = 0; // ipv4 type
	payload[2] = 6; // ip + port
	payload[3] = relay_ip.octets[0]; // ip
	payload[4] = relay_ip.octets[1];
	payload[5] = relay_ip.octets[2];
	payload[6] = relay_ip.octets[3];
	payload[7] = HIGH(relay_port); // port
	payload[8] = LOW(relay_port);
	payload[9] = 0; // tap handshake
	payload[10] = 0;
	payload[11] = HIGH(onion_skin_size);
	payload[12] = LOW(onion_skin_size);
	memcpy(&payload[13], onion_skin, onion_skin_size); // handshake data

	FillRelayPayload(payload, payload_size);

	delete[] payload;

	return 0;
}

int tor::Cell::FillExtend(byte* onion_skin, short onion_skin_size, tor::IP relay_ip, short relay_port, byte* fingerprint)
{
	FillCircuitId();

	// create cell payload
	short payload_size = 4 + 2 + onion_skin_size + HASH_LEN; // num of spec, spec type, spec length, ip, port, handshake type, handshake data
	byte* payload = new byte[payload_size];
	payload[0] = relay_ip.octets[0]; // ip
	payload[1] = relay_ip.octets[1];
	payload[2] = relay_ip.octets[2];
	payload[3] = relay_ip.octets[3];
	payload[4] = HIGH(relay_port); // port
	payload[5] = LOW(relay_port);
	memcpy(&payload[6], onion_skin, onion_skin_size); // handshake data
	memcpy(&payload[6] + onion_skin_size, fingerprint, HASH_LEN); // fingerprint

	FillRelayPayload(payload, payload_size);

	delete[] payload;

	return 0;
}

int tor::Cell::FillHttpGet(string service_address, string query)
{
	FillCircuitId();

	string payload = "GET " + query + " HTTP/1.0\r\nHost: " + service_address + "\r\n\r\n";

	FillRelayPayload((byte*)payload.c_str(), payload.length());

	return 0;
}

int tor::Cell::FillFetchDescriptor(vector<byte> descriptor_id, string host_ip)
{
	FillCircuitId();

	string payload = "GET /tor/rendezvous2/";
	for (int i = 0; i < descriptor_id.size(); i++)
		payload += descriptor_id[i];
	payload += " HTTP/1.0\r\nHost: " + host_ip + "\r\n\r\n";

	FillRelayPayload((byte*)payload.c_str(), payload.length());

	return 0;
}

int tor::Cell::FillRendezvous(byte* rendezvous_cookie)
{
	FillCircuitId();

	// create cell payload
	short payload_size = 20; // rendezvous cookie size = 20
	byte* payload = new byte[payload_size];
	memcpy(&payload[0], rendezvous_cookie, payload_size); // rendezvous cookie

	FillRelayPayload(payload, payload_size);

	delete[] payload;

	return 0;
}

int tor::Cell::FillBeginStream(string service_address, short service_port)
{
	FillCircuitId();

	string payload;

	if (service_address.find(".onion") != string::npos) {
		payload += service_address.substr(0, service_address.find(".onion") - 1);
	}
	else {
		payload += service_address;
	}
	payload += ':';
	payload += to_string(service_port);
	payload += '\0';

	FillRelayPayload((byte*)payload.data(), payload.length());

	return 0;
}

int tor::Cell::FillIntroduce1()
{
	FillCircuitId();
	/*
	// create cell payload
	short payload_size = 20 + 1 + 2 + 
	byte* payload = new byte[payload_size];
	payload[0] = relay_ip.octets[0]; // ip
	payload[1] = relay_ip.octets[1];
	payload[2] = relay_ip.octets[2];
	payload[3] = relay_ip.octets[3];
	payload[4] = HIGH(relay_port); // port
	payload[5] = LOW(relay_port);
	memcpy(&payload[6], onion_skin, onion_skin_size); // handshake data
	memcpy(&payload[6] + onion_skin_size, fingerprint, HASH_LEN); // fingerprint

	FillRelayPayload(payload, payload_size);
	*/
	return 0;
}
