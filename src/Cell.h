#pragma once
#include "common.h"

namespace tor {

	class Cell {
	public:
		enum CellType {
			PADDING = 0,
			CREATE,
			CREATED,
			RELAY,
			DESTROY,
			CREATE_FAST,
			CREATED_FAST,
			VERSIONS,
			NETINFO,
			RELAY_EARLY,
			CREATE2,
			CREATED2,
			PADDING_NEGOTIATE,

			VPADDING = 128,
			CERTS,
			AUTH_CHALLENGE,
			AUTHENTICATE,
			AUTHORIZE
		} cell_type;

		enum PayloadCellType {
			RELAY_BEGIN = 1,
			RELAY_DATA,
			RELAY_END,
			RELAY_CONNECTED,
			RELAY_SENDME,
			RELAY_EXTEND,
			RELAY_EXTENDED,
			RELAY_TRUNCATE,
			RELAY_TRUNCATED,
			RELAY_DROP,
			RELAY_RESOLVE,
			RELAY_RESOLVED,
			RELAY_BEGIN_DIR,
			RELAY_EXTEND2,
			RELAY_EXTENDED2,

			RELAY_COMMAND_ESTABLISH_INTRO = 32,
			RELAY_COMMAND_ESTABLISH_RENDEZVOUS,
			RELAY_COMMAND_INTRODUCE1,
			RELAY_COMMAND_INTRODUCE2,
			RELAY_COMMAND_RENDEZVOUS1,
			RELAY_COMMAND_RENDEZVOUS2,
			RELAY_COMMAND_INTRO_ESTABLISHED,
			RELAY_COMMAND_RENDEZVOUS_ESTABLISHED,
			RELAY_COMMAND_INTRODUCE_ACK
		} cell_payload_type;

		enum CellMode {
			SEND = 0,
			GET
		} cell_mode;

		Cell(CellType cell_type, CellMode cell_mode, unsigned long circuit_id);
		Cell(CellType cell_type, PayloadCellType cell_payload_type, CellMode cell_mode, unsigned long circuit_id);
		~Cell();


		byte* cell_bytes;
		int cell_size = 0;
		unsigned long circuit_id;

		int FillCircuitId();
		int FillRelayPayload(byte* payload, short payload_size, short stream_id = 0);
		int ComputeDigest(vector<byte> &forward_bytes);

		int FillVersions();
		int FillNetInfo(sockaddr_in& sin);
		int FillCreate2(byte* onion_skin, short onion_skin_size);
		int FillCreate(byte* onion_skin, short onion_skin_size);
		int FillExtend2(byte* onion_skin, short onion_skin_size, tor::IP relay_ip, short relay_port);
		int FillExtend(byte* onion_skin, short onion_skin_size, tor::IP relay_ip, short relay_port, byte *fingerprint);

		int CreateDirStream(byte* aesKey, vector<byte>& hashBytes);
		int FillDescriptor(string descriptorId, string hostIp, vector<byte>& hashBytes);
		int FillIntroduce(byte* payload, int payloadSize, vector<byte>& hashBytes);
		int FillRendezvous(byte* cookie, vector<byte>& hashBytes);
		int FillStartData(string host, int port, vector<byte>& hashBytes);

		int FormHttpQueryGet(string query, string onionUrl, vector<byte>& hashBytes);

		//void FinishHandshakeExtended(SecByteBlock& pubB, SecByteBlock& privA, SecByteBlock& secretKey, DH& dh, byte* keyMaterial);
	};
} // namespace tor