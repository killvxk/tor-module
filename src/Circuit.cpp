#include "common.h"
#include "Circuit.h"

tor::Circuit::Circuit(string onion_url, Consensus& consensus) : onion_url(onion_url), consensus(consensus)
{

}

int tor::Circuit::Initialize(string onion_url, Consensus& consensus, vector<string> descriptors, vector<Relay*> descriptor_relays)
{
	Circuit::onion_url = onion_url;
	Circuit::consensus = consensus;
	Circuit::descriptors = descriptors;
	Circuit::descriptor_relays = descriptor_relays;
	circuit_id = 0x80000002; // rand() % 4294967295;

	return 0;
}

int tor::Circuit::SetCircuit(int hops_number, CircuitType circuit_type)
{
	switch (circuit_type) {
	case CircuitType::DescriptorFetch: {
		EstablishConnection(2, *descriptor_relays[1]);

		CreateDirStream();

		break;
	}
	case CircuitType::Rendezvous: {


		break;
	}
	case CircuitType::Introducing: {


		break;
	}
	}

	return 0;
}

int tor::Circuit::EstablishConnection(int hops_number, Relay& end_relay)
{
	for (int i = 0; i < hops_number; i++) {
		if (i == 0) {
			RelayFlags flags;
			flags.Fast = true;
			flags.Running = true;
			flags.Valid = true;

			AddRelayToCircuit(GetRandomRelayWithFlags(flags));
		}
		else {
			if (i == hops_number - 1) {
				AddRelayToCircuit(end_relay);
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

int tor::Circuit::CreateDirStream()
{
	Cell cell_begin_dir(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_BEGIN_DIR, Cell::CellMode::SEND, circuit_id);
	cell_begin_dir.FillCircuitId();
	cell_begin_dir.FillRelayPayload(nullptr, 0, 3);

	cell_begin_dir.ComputeDigest(circuit_relays.back().hash_forward_bytes);
	for (int i = 0; i < cell_begin_dir.cell_size; i++) {
		cout << hex << (int)(byte)cell_begin_dir.cell_bytes[i] << " ";
	}
	cout << endl;
	FullEncryptCell(cell_begin_dir.cell_bytes, cell_begin_dir.cell_size);

	circuit_relays[0].ssl_socket.SendData(cell_begin_dir.cell_bytes, cell_begin_dir.cell_size);

	Cell cell_connected(Cell::CellType::RELAY, Cell::PayloadCellType::RELAY_CONNECTED, Cell::CellMode::GET, circuit_id);
	circuit_relays[0].ssl_socket.GetData(cell_connected.cell_bytes, cell_connected.cell_size);

	FullDecryptCell(cell_connected.cell_bytes, cell_connected.cell_size);

	for (int i = 0; i < cell_connected.cell_size; i++) {
		cout << hex << (int)(byte)cell_connected.cell_bytes[i] << " ";
	}
	cout << endl;

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