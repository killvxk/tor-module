#include "common.h"
#include "Circuit.h"

tor::Circuit::Circuit(string onion_url, Consensus& consensus) : onion_url(onion_url), consensus(consensus)
{
}

// TODO: remake constructors
int tor::Circuit::Initialize(string onion_url, Consensus& consensus, vector<ByteSeq> descriptors, vector<Relay*> descriptor_relays)
{
	Circuit::onion_url = onion_url;
	Circuit::consensus = consensus;
	Circuit::descriptors = descriptors;
	Circuit::descriptor_relays = descriptor_relays;
	circuit_id = 0x80000002; // rand() % 4294967295;

	return 0;
}

int tor::Circuit::Initialize(string onion_url, Consensus& consensus)
{
	Circuit::onion_url = onion_url;
	Circuit::consensus = consensus;
	circuit_id = 0x80000003; // rand() % 4294967295;

	return 0;
}

int tor::Circuit::Initialize(string onion_url, Consensus& consensus, IntroductionPoint* introduction_point, CircuitRelay* rendzvous_relay, CircuitRelay* onion_relay, byte* rendezvous_cookie)
{
	Circuit::onion_url = onion_url;
	Circuit::consensus = consensus;
	Circuit::introduction_point = introduction_point;
	Circuit::rendzvous_relay = rendzvous_relay;
	Circuit::onion_relay = onion_relay;
	Circuit::rendezvous_cookie = rendezvous_cookie;
	circuit_id = 0x80000004; // rand() % 4294967295;

	return 0;
}

int tor::Circuit::SetCircuit(int hops_number, CircuitType circuit_type)
{
	switch (circuit_type) {
	case CircuitType::DescriptorFetch: {
		EstablishConnection(2, *descriptor_relays[0]);

		CreateDirStream();
		FetchDescriptor(descriptors[0], circuit_relays.back().relay_ip.ip_string, introduction_points_string);

		break;
	}
	case CircuitType::Rendezvous: {
		EstablishConnection(2);

		rendezvous_cookie = new byte[20];
		for (int i = 0; i < 20; i++) {
			rendezvous_cookie[i] = rand() % 100;
		}

		EstablishRendezvous(rendezvous_cookie);

		break;
	}
	case CircuitType::Introducing: {
		introduction_point_relay = &consensus.relays[introduction_point->relay_number];

		EstablishConnection(2, *introduction_point_relay);

		MakeIntroduce();

		break;
	}
	}

	return 0;
}

int tor::Circuit::EstablishConnection(int hops_number)
{
	for (int i = 0; i < hops_number; i++) {
		if (i == 0) {
			RelayFlags flags;
			flags.Fast = true;
			flags.Running = true;
			flags.Valid = true;
			flags.Guard = true;

			AddRelayToCircuit(GetRandomRelayWithFlags(flags));
		}
		else {
			if (i == hops_number - 1) {
				RelayFlags flags;
				flags.Fast = true;
				flags.Running = true;
				flags.Valid = true;
				flags.Exit = true;

				AddRelayToCircuit(GetRandomRelayWithFlags(flags));
			}
			else {
				RelayFlags flags;
				flags.Fast = true;
				flags.Running = true;
				flags.Valid = true;

				AddRelayToCircuit(GetRandomRelayWithFlags(flags));
			}
		}
	}

	return 0;
}

int tor::Circuit::EstablishConnection(int hops_number, Relay& end_relay)
{
	EstablishConnection(hops_number - 1);
	AddRelayToCircuit(end_relay);

	return 0;
}

int tor::Circuit::AddRelayToCircuit(Relay& relay)
{
	CircuitRelay circuit_relay(relay, circuit_id);

	if (circuit_relays.size() == 0) { // that means it's enter relay
		consensus.FillPublicKey(circuit_relay);
		circuit_relays.push_back(circuit_relay);
		ConnectToRelay(circuit_relays[0]);

		cout << "Connected to relay: " << circuit_relays[0].relay_name << endl;
	}
	else {
		consensus.FillPublicKey(circuit_relay);
		circuit_relays.push_back(circuit_relay);
		ExtendToRelay(circuit_relays.back());

		cout << "Extended to relay: " << circuit_relays.back().relay_name << endl;
	}

	return 0;
}

int tor::Circuit::CreateRelayStream(short service_port)
{
	Cell cell_begin_stream(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_BEGIN, Cell::CellMode::SEND, circuit_id, 4);
	cell_begin_stream.FillBeginStream(onion_url, service_port);

	cell_begin_stream.ComputeDigest(circuit_relays.back().hash_forward_bytes);
	FullEncryptCell(cell_begin_stream.cell_bytes, cell_begin_stream.cell_size);

	circuit_relays[0].ssl_socket.SendData(cell_begin_stream.cell_bytes, cell_begin_stream.cell_size);

	Cell cell_connected(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_CONNECTED, Cell::CellMode::GET, circuit_id, 4);
	circuit_relays[0].ssl_socket.GetData(cell_connected.cell_bytes, cell_connected.cell_size);

	FullDecryptCell(cell_connected.cell_bytes, cell_connected.cell_size);

	if (cell_connected.cell_bytes[5] == Cell::PayloadCellType::RELAY_CONNECTED) {
		cout << "Stream created." << endl;
	}
	else {
		cout << "Stream creation error." << endl;
	}

	onion_port = service_port;

	return 0;
}

int tor::Circuit::MakeStreamRequest(string data, string& output)
{
	cout << "Make http query." << endl;

	Cell cell_data(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_DATA, Cell::CellMode::SEND, circuit_id, 4);
	cell_data.FillHttpGet(onion_url, data);

	cell_data.ComputeDigest(circuit_relays.back().hash_forward_bytes);
	FullEncryptCell(cell_data.cell_bytes, cell_data.cell_size);

	circuit_relays[0].ssl_socket.SendData(cell_data.cell_bytes, cell_data.cell_size);


	Cell cell_data_answer(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_DATA, Cell::CellMode::GET, circuit_id, 4);
	GetFullStreamData(cell_data_answer.cell_bytes, cell_data_answer.cell_size);

	for (int b = 0; b < cell_data_answer.cell_size / 514; b++) {
		for (int i = 16; i < 514; i++) {
			if (cell_data_answer.cell_bytes[b * 514 + i] != 0) output += cell_data_answer.cell_bytes[b * 514 + i];
		}
	}

	return 0;
}

int tor::Circuit::CreateDirStream()
{
	Cell cell_begin_dir(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_BEGIN_DIR, Cell::CellMode::SEND, circuit_id, 3);
	cell_begin_dir.FillCircuitId();
	cell_begin_dir.FillRelayPayload(nullptr, 0);

	cell_begin_dir.ComputeDigest(circuit_relays.back().hash_forward_bytes);
	FullEncryptCell(cell_begin_dir.cell_bytes, cell_begin_dir.cell_size);

	circuit_relays[0].ssl_socket.SendData(cell_begin_dir.cell_bytes, cell_begin_dir.cell_size);

	Cell cell_connected(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_CONNECTED, Cell::CellMode::GET, circuit_id, 3);
	circuit_relays[0].ssl_socket.GetData(cell_connected.cell_bytes, cell_connected.cell_size);

	FullDecryptCell(cell_connected.cell_bytes, cell_connected.cell_size);

	return 0;
}

int tor::Circuit::GetFullStreamData(byte* &data, int& data_size)
{
	data_size = 0;
	byte* buffer = new byte[8000];
	int recieved = 0;
	bool is_end = false;

	while (true) {
		circuit_relays[0].ssl_socket.GetData(buffer, recieved);

		for (int b = 0; b < recieved / 514; b++) {
			FullDecryptCell(buffer + b * 514, 514);

			/*
			cout << "Cell#" << b << endl;
			for (int i = 0; i < 514; i++) {
				cout << std::hex << (int)buffer[b * 514 + i] << " ";
			}
			cout << endl;
			*/

			if (buffer[b * 514 + 16] == 6) // end of stream
				is_end = true;
		}

		data = (byte*)realloc(data, data_size + recieved);
		memcpy(data + data_size, buffer, recieved);
		data_size += recieved;

		if (is_end)
			break;
	}

	delete[] buffer;

	return 0;
}

int tor::Circuit::FetchDescriptor(ByteSeq descriptor_id, string host_ip, string& descriptor)
{
	Cell cell_fetch_descriptor(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_DATA, Cell::CellMode::SEND, circuit_id, 3);
	cell_fetch_descriptor.FillFetchDescriptor(descriptor_id, host_ip);
	cell_fetch_descriptor.ComputeDigest(circuit_relays.back().hash_forward_bytes);

	FullEncryptCell(cell_fetch_descriptor.cell_bytes, cell_fetch_descriptor.cell_size);
	circuit_relays[0].ssl_socket.SendData(cell_fetch_descriptor.cell_bytes, cell_fetch_descriptor.cell_size);

	Cell cell_descriptor(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_DATA, Cell::CellMode::GET, circuit_id, 3);
	GetFullStreamData(cell_descriptor.cell_bytes, cell_descriptor.cell_size);

	/*
	for (int b = 0; b < cellR2.cellSize / 514; b++) {
		cout << "Checking 1 part: " << (int)cellR2.cellBytes[b * 514] << endl;
		for (int i = 0; i < relays.size(); i++) {
			relays[i]->DecryptRelayCell(cellR2.cellBytes + b * 514);
		}
		cout << "Checking 2 part: " << (int)cellR2.cellBytes[b * 514] << endl;

		cout << "Cell#" << b << endl;
		for (int i = 0; i < 514; i++) {
			cout << std::hex << (int)cellR2.cellBytes[b * 514 + i] << " ";
		}
		cout << endl;
	}
	*/
	
	for (int b = 0; b < cell_descriptor.cell_size / 514; b++) {
		for (int i = 16; i < 514; i++) {
			if (cell_descriptor.cell_bytes[b * 514 + i] != 0) descriptor += cell_descriptor.cell_bytes[b * 514 + i];
		}
	}

	return 0;
}

int tor::Circuit::EstablishRendezvous(byte* cookie)
{
	Cell cell_establish_rendezvous(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_COMMAND_ESTABLISH_RENDEZVOUS, Cell::CellMode::SEND, circuit_id, 2);
	cell_establish_rendezvous.FillRendezvous(cookie);
	cell_establish_rendezvous.ComputeDigest(circuit_relays.back().hash_forward_bytes);

	FullEncryptCell(cell_establish_rendezvous.cell_bytes, cell_establish_rendezvous.cell_size);
	circuit_relays[0].ssl_socket.SendData(cell_establish_rendezvous.cell_bytes, cell_establish_rendezvous.cell_size);


	Cell cell_rendezvous_established(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_COMMAND_RENDEZVOUS_ESTABLISHED, Cell::CellMode::GET, circuit_id, 2);
	circuit_relays[0].ssl_socket.GetData(cell_rendezvous_established.cell_bytes, cell_rendezvous_established.cell_size);

	FullDecryptCell(cell_rendezvous_established.cell_bytes, cell_rendezvous_established.cell_size);

	if (cell_rendezvous_established.cell_bytes[5] == Cell::PayloadCellType::RELAY_COMMAND_RENDEZVOUS_ESTABLISHED) {
		cout << "Rendezvous established step 1" << endl;
	}
	else {
		cout << "Rendezvous error step 1" << endl;
	}

	return 0;
}

int tor::Circuit::MakeIntroduce()
{
	int rendezvous_onion_key_size = rendzvous_relay->onion_key_bytes_size;

	// non-encrypted part
	byte* service_key_hash = new byte[20];
	GetSHA1(introduction_point->dec_service_key.pointer, introduction_point->dec_service_key.size, service_key_hash);

	// encrypted part
	int encrypted_part_size = 1 + 4 + 2 + 20 + 2 + rendzvous_relay->onion_key_bytes_size + 20 + 128;
	byte* encrypted_part = new byte[encrypted_part_size];

	// fill payload
	encrypted_part[0] = 2; // version
	encrypted_part[1] = rendzvous_relay->relay_ip.octets[0]; // rendezvous ip
	encrypted_part[2] = rendzvous_relay->relay_ip.octets[1];
	encrypted_part[3] = rendzvous_relay->relay_ip.octets[2];
	encrypted_part[4] = rendzvous_relay->relay_ip.octets[3];
	encrypted_part[5] = HIGH(rendzvous_relay->relay_orport); // rendezvous or port
	encrypted_part[6] = LOW(rendzvous_relay->relay_orport);
	memcpy(&encrypted_part[7], rendzvous_relay->relay_identity, 20); // ident
	encrypted_part[27] = HIGH(rendezvous_onion_key_size); // rendezvous onion key size
	encrypted_part[28] = LOW(rendezvous_onion_key_size);
	memcpy(&encrypted_part[29], rendzvous_relay->onion_key_bytes, rendezvous_onion_key_size); // rendezvous onion key
	memcpy(&encrypted_part[29 + rendezvous_onion_key_size], rendezvous_cookie, 20); // rendezvous cookie

	// initialize DH
	onion_relay->DHInititalize();

	memcpy(&encrypted_part[49 + rendezvous_onion_key_size], onion_relay->public_a_number.data(), 128);//DF 1 part

	byte * buffer = new byte[500];
	int payload_size = 0;

	// hybrid encription using onion service key(holds in intro point)
	tor::HybridEncryption(buffer, payload_size, encrypted_part, encrypted_part_size, introduction_point->encryptor_service);

	byte * payload = new byte[payload_size + 20];
	memcpy(payload, service_key_hash, 20);
	memcpy(payload + 20, buffer, payload_size);

	Cell cell_introduce(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_COMMAND_INTRODUCE1, Cell::CellMode::SEND, circuit_id, 3);
	cell_introduce.FillCircuitId();
	cell_introduce.FillRelayPayload(payload, payload_size + 20);

	cell_introduce.ComputeDigest(circuit_relays.back().hash_forward_bytes);
	FullEncryptCell(cell_introduce.cell_bytes, cell_introduce.cell_size);

	circuit_relays[0].ssl_socket.SendData(cell_introduce.cell_bytes, cell_introduce.cell_size);


	Cell cell_introduce_ack(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_COMMAND_INTRODUCE_ACK, Cell::CellMode::GET, circuit_id, 3);
	circuit_relays[0].ssl_socket.GetData(cell_introduce_ack.cell_bytes, cell_introduce_ack.cell_size);

	FullDecryptCell(cell_introduce_ack.cell_bytes, cell_introduce_ack.cell_size);

	if (cell_introduce_ack.cell_bytes[5] == Cell::PayloadCellType::RELAY_COMMAND_INTRODUCE_ACK) {
		cout << "Introduced successfull." << endl;
	}
	else {
		cout << "Introduced with error." << endl;
	}

	return 0;
}

int tor::Circuit::FinishRendezvous(CircuitRelay* onion_relay)
{
	Cell cell_rendezvous2(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_COMMAND_RENDEZVOUS2, Cell::CellMode::GET, circuit_id, 5);
	circuit_relays[0].ssl_socket.GetData(cell_rendezvous2.cell_bytes, cell_rendezvous2.cell_size);

	FullDecryptCell(cell_rendezvous2.cell_bytes, cell_rendezvous2.cell_size);

	onion_relay->FinishTapHandshake(&cell_rendezvous2.cell_bytes[16], 148);

	circuit_relays.push_back(*onion_relay);

	if (cell_rendezvous2.cell_bytes[5] == Cell::PayloadCellType::RELAY_COMMAND_RENDEZVOUS2) {
		cout << "Rendezvous established step 2." << endl;
	}
	else {
		cout << "Rendezvous error step 2." << endl;
	}

	return 0;
}

int tor::Circuit::EstablishIntroduction()
{
	Cell cell_introduce1(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_COMMAND_INTRODUCE1, Cell::CellMode::SEND, circuit_id);
	cell_introduce1.FillIntroduce1();
	cell_introduce1.ComputeDigest(circuit_relays.back().hash_forward_bytes);

	FullEncryptCell(cell_introduce1.cell_bytes, cell_introduce1.cell_size);

	circuit_relays[0].ssl_socket.SendData(cell_introduce1.cell_bytes, cell_introduce1.cell_size);


	Cell cell_introduce_ack(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_COMMAND_INTRODUCE_ACK, Cell::CellMode::GET, circuit_id);
	circuit_relays[0].ssl_socket.GetData(cell_introduce_ack.cell_bytes, cell_introduce_ack.cell_size);

	FullDecryptCell(cell_introduce_ack.cell_bytes, cell_introduce_ack.cell_size);

	return 0;
}

int tor::Circuit::ConnectToRelay(CircuitRelay& relay)
{
	relay.ConnectSsl();

	Cell cell_versions(Cell::CellType::VERSIONS, Cell::CellMode::SEND, 0);
	cell_versions.FillVersions();
	relay.ssl_socket.SendData(cell_versions.cell_bytes, cell_versions.cell_size);

	Cell cell_versions_get(Cell::CellType::VERSIONS, Cell::CellMode::GET, 0);
	relay.ssl_socket.GetData(cell_versions_get.cell_bytes, cell_versions_get.cell_size);

	Cell cell_netinfo(Cell::CellType::NETINFO, Cell::CellMode::SEND, 0);
	cell_netinfo.FillNetInfo(relay.ssl_socket.sin);
	relay.ssl_socket.SendData(cell_netinfo.cell_bytes, cell_netinfo.cell_size);

	int onion_skin_size;
	byte* onion_skin = new byte[186];
	relay.CreateOnionSkin(onion_skin_size, onion_skin);

	Cell cell_create2(Cell::CellType::CREATE2, Cell::CellMode::SEND, circuit_id);
	cell_create2.FillCreate2(onion_skin, (short)onion_skin_size);

	relay.ssl_socket.SendData(cell_create2.cell_bytes, cell_create2.cell_size);

	Cell cell_created2(Cell::CellType::CREATED, Cell::CellMode::GET, circuit_id);
	relay.ssl_socket.GetData(cell_created2.cell_bytes, cell_created2.cell_size);

	// TODO: fix me
	relay.FinishTapHandshake(&cell_created2.cell_bytes[7], cell_created2.cell_bytes[6]);

	delete[] onion_skin;

	return 0;
}

int tor::Circuit::ExtendToRelay(CircuitRelay& relay)
{
	Cell cell_extend(Cell::CellType::RELAY_EARLY, Cell::PayloadCellType::RELAY_EXTEND, Cell::CellMode::SEND, circuit_id);
	
	int onion_skin_size;
	byte* onion_skin = new byte[186];
	relay.CreateOnionSkin(onion_skin_size, onion_skin);

	//cell_extend2.FillExtend2(onion_skin, onion_skin_size, relay.relay_ip, relay.relay_orport);
	cell_extend.FillExtend(onion_skin, onion_skin_size, relay.relay_ip, relay.relay_orport, relay.relay_identity);
	cell_extend.ComputeDigest(circuit_relays[0].hash_forward_bytes);
	FullEncryptCell(cell_extend.cell_bytes, cell_extend.cell_size);
	circuit_relays[0].ssl_socket.SendData(cell_extend.cell_bytes, cell_extend.cell_size);
	
	Cell cell_extended2(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_EXTENDED2, Cell::CellMode::GET, circuit_id);
	circuit_relays[0].ssl_socket.GetData(cell_extended2.cell_bytes, cell_extended2.cell_size);
	FullDecryptCell(cell_extended2.cell_bytes, cell_extended2.cell_size);

	// TODO: fix me
	relay.FinishTapHandshake(&cell_extended2.cell_bytes[16], cell_extended2.cell_bytes[15]);

	delete[] onion_skin;

	return 0;
}

int tor::Circuit::FullEncryptCell(byte* cell_bytes, int cell_size)
{
	// reverse order because of tor's specifications
	for (int i = circuit_relays.size() - 1; i >= 0; i--) {
		//TODO: fix me
		if (!circuit_relays[i].is_crypto_initialized)
			continue; // it's like an error in some situations

		circuit_relays[i].EncryptCell(cell_bytes, cell_size);
	}

	return 0;
}

int tor::Circuit::FullDecryptCell(byte* cell_bytes, int cell_size)
{
	for (int i = 0; i < circuit_relays.size(); i++) {
		//TODO: fix me
		if (!circuit_relays[i].is_crypto_initialized)
			continue; // it's like an error in some situations

		circuit_relays[i].DecryptCell(cell_bytes, cell_size);
	}

	return 0;
}

tor::Relay& tor::Circuit::GetRandomRelayWithFlags(RelayFlags flags)
{
	int random_int = 0;

	while (true) {
	label1:
		random_int = rand() % consensus.relays_num;
		for (int i = 0; i < circuit_relays.size(); i++) {
			if (circuit_relays[i].relay_id == random_int)
				goto label1;
		}

		// check all flags
		if (consensus.relays[random_int].relay_flags.Authority != flags.Authority && flags.Authority ||
			consensus.relays[random_int].relay_flags.BadExit != flags.BadExit && flags.BadExit ||
			consensus.relays[random_int].relay_flags.Exit != flags.Exit && flags.Exit ||
			consensus.relays[random_int].relay_flags.Fast != flags.Fast && flags.Fast ||
			consensus.relays[random_int].relay_flags.Guard != flags.Guard && flags.Guard ||
			consensus.relays[random_int].relay_flags.HSDir != flags.HSDir && flags.HSDir ||
			consensus.relays[random_int].relay_flags.NoEdConsensus != flags.NoEdConsensus && flags.NoEdConsensus ||
			consensus.relays[random_int].relay_flags.Stable != flags.Stable && flags.Stable ||
			consensus.relays[random_int].relay_flags.StaleDesc != flags.StaleDesc && flags.StaleDesc ||
			consensus.relays[random_int].relay_flags.Running != flags.Running && flags.Running ||
			consensus.relays[random_int].relay_flags.Valid != flags.Valid && flags.Valid ||
			consensus.relays[random_int].relay_flags.V2Dir != flags.V2Dir && flags.V2Dir) {
			break;
		}
	}

	cout << "Found node: " << consensus.relays[random_int].relay_name << " ID: " << random_int << endl;

	return consensus.relays[random_int];
}