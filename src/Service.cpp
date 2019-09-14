#include "Service.h"

#ifdef _CRTDBG_MAP_ALLOC
#define new new( _NORMAL_BLOCK, __FILE__, __LINE__)
#endif

tor::Service::Service(Consensus& consensus, string onion_url) : 
	consensus(consensus), 
	onion_url(onion_url), 
	onion_relay("onion_relay"),
	circuit_descriptor(onion_url, consensus, circuit_inc++),
	circuit_rendezvous(onion_url, consensus, circuit_inc++),
	circuit_introducing(onion_url, consensus, circuit_inc++)
{
	
}

tor::Service::~Service()
{
	//circuit_rendezvous.~Circuit();

}

int tor::Service::ConnectToService()
{
	if (GetResponsibleDirectories()) {
		return 1;
	}

	// set first circuit to get descriptor
	circuit_descriptor.Initialize(onion_url, consensus, descriptors, descriptor_relays);

	// tries max 3 times, then if unsuccess - return an error
	int attempts = 0;
	while (true) {
		attempts++;

		int code = circuit_descriptor.SetCircuit(2, Circuit::CircuitType::DescriptorFetch);
		if (code) {
			if (attempts >= max_circuit_reset_attempts)
				return 1;
			else {
				circuit_descriptor.ClearCircuit();
				continue;
			}
		}
		else
			break;
	}

	ParseIntroductionPoints(circuit_descriptor.introduction_points_string);
	circuit_descriptor.~Circuit();


	// set second circuit to rendezvous
	circuit_rendezvous.Initialize(onion_url, consensus);

	// tries max 3 times, then if unsuccess - return an error
	attempts = 0;
	while (true) {
		attempts++;

		int code = circuit_rendezvous.SetCircuit(2, Circuit::CircuitType::Rendezvous);
		if (code) {
			if (attempts >= max_circuit_reset_attempts)
				return 2;
			else {
				circuit_rendezvous.ClearCircuit();
				continue;
			}
		}
		else
			break;
	}

	// set third circuit to introduce our rendezvous circuit
	circuit_introducing.Initialize(onion_url, consensus, &introduction_points[1], &circuit_rendezvous.circuit_relays.back(), &onion_relay, circuit_rendezvous.rendezvous_cookie);

	// tries max 3 times, then if unsuccess - return an error
	attempts = 0;
	while (true) {
		attempts++;

		int code = circuit_introducing.SetCircuit(2, Circuit::CircuitType::Introducing);
		if (code) {
			if (attempts >= max_circuit_reset_attempts)
				return 3;
			else {
				circuit_introducing.ClearCircuit();
				continue;
			}
		}
		else
			break;
	}

	// finish introducing
	int code = circuit_rendezvous.FinishRendezvous(&onion_relay);
	if (code) {
		return 4;
	}

	circuit_introducing.~Circuit();

	return 0;
}

int tor::Service::MakeRequest(string query, string& answer)
{
	int code = circuit_rendezvous.CreateRelayStream(onion_port);
	if (code) {
		return 1;
	}

	code = circuit_rendezvous.MakeStreamRequest(query, answer);
	if (code) {
		return 2;
	}

	return 0;
}

int tor::Service::GetResponsibleDirectories()
{
	int z_part_length = onion_url.length() - 6;

	byte* z_part = new byte[z_part_length];
	memcpy(z_part, onion_url.c_str(), z_part_length);

	byte* permanent_id;
	unsigned long permanent_id_size;
	Base32Decode(z_part, z_part_length, permanent_id, permanent_id_size);

	int time_period = (time(0) + (int)permanent_id[0] * 86400 / 256) / 86400;
	byte first_sha_bytes[5];

	for (int replica = 0; replica < 2; replica++) {
		word16 temp;
		temp.data = time_period;
		first_sha_bytes[0] = temp.bytes[3];
		first_sha_bytes[1] = temp.bytes[2];
		first_sha_bytes[2] = temp.bytes[1];
		first_sha_bytes[3] = temp.bytes[0];
		first_sha_bytes[4] = (byte)replica;

		byte first_hash[CryptoPP::SHA1::DIGESTSIZE];
		GetSHA1(first_sha_bytes, 5, first_hash);

		byte* second_sha_bytes = new byte[permanent_id_size + CryptoPP::SHA1::DIGESTSIZE];

		memcpy(second_sha_bytes, permanent_id, permanent_id_size);
		memcpy(second_sha_bytes + permanent_id_size, first_hash, CryptoPP::SHA1::DIGESTSIZE);

		byte second_hash[CryptoPP::SHA1::DIGESTSIZE];
		GetSHA1(second_sha_bytes, permanent_id_size + CryptoPP::SHA1::DIGESTSIZE, second_hash);

		delete[] second_sha_bytes;

		byte* descriptor;
		unsigned long descriptor_size;
		Base32Encode(second_hash, CryptoPP::SHA1::DIGESTSIZE, descriptor, descriptor_size);

		vector<byte> descriptor_struct;
		descriptor_struct.resize(descriptor_size);
		memcpy(descriptor_struct.data(), descriptor, descriptor_size);

		descriptors.push_back(descriptor_struct);

		delete[] descriptor;

		int counter = 0, found_count = 0;

		while (true) {
			if (consensus.relays[counter].relay_flags.HSDir && memcmp(consensus.relays[counter].relay_identity.data(), second_hash, 20) > 0) {
				found_count++;
				descriptor_relays.push_back(&consensus.relays[counter]);
			}
			if (found_count >= 3) {
				break;
			}

			counter++;
		}
	}

	//clean
	delete[] z_part;
	delete[] permanent_id;

	return 0;
}

int tor::Service::ParseIntroductionPoints(string descriptor)
{
	string raw_points_list;
	int begin_position = 0, end_position = 0;
	begin_position = descriptor.find("-----BEGIN MESSAGE-----");
	end_position = descriptor.find("-----END MESSAGE-----");
	// cut the list message
	raw_points_list = descriptor.substr(begin_position + 23, end_position - begin_position - 23);

	// erase all \n chars
	while (raw_points_list.find("\n") != string::npos) {
		raw_points_list.erase(raw_points_list.begin() + raw_points_list.find("\n"));
	}

	string points_list;
	Base64Decode(raw_points_list, points_list);
	
	// TODO: rewrite it
	tor::IntroductionPoint buffer_point;
	while (points_list.find("introduction-point") != string::npos) {
		int i = 0;

		//identifier
		while (points_list[i] != ' ') {
			i++;
		}
		i++;
		string identifier = "";
		while (points_list[i] != '\n') {
			identifier += points_list[i];
			i++;
		}
		i++;

		//ip
		while (points_list[i] != ' ') {
			i++;
		}
		i++;
		string ip = "";
		while (points_list[i] != '\n') {
			ip += points_list[i];
			i++;
		}
		i++;

		//port
		while (points_list[i] != ' ') {
			i++;
		}
		i++;
		string port = "";
		while (points_list[i] != '\n') {
			port += points_list[i];
			i++;
		}
		i++;

		//onion key
		begin_position = points_list.find("-----BEGIN RSA PUBLIC KEY-----");
		end_position = points_list.find("-----END RSA PUBLIC KEY-----");
		string onionKey = points_list.substr(begin_position + 30, end_position - begin_position - 30);
		points_list[begin_position + 2] = 'X';
		points_list[end_position + 2] = 'X';
		while (onionKey.find("\n") != string::npos) {
			onionKey.erase(onionKey.begin() + onionKey.find("\n"));
		}

		//service key
		begin_position = points_list.find("-----BEGIN RSA PUBLIC KEY-----");
		end_position = points_list.find("-----END RSA PUBLIC KEY-----");
		points_list[begin_position + 2] = 'X';
		points_list[end_position + 2] = 'X';
		string serviceKey = points_list.substr(begin_position + 30, end_position - begin_position - 30);
		while (serviceKey.find("\n") != string::npos) {
			serviceKey.erase(serviceKey.begin() + serviceKey.find("\n"));
		}

		points_list[0] = 'X';
		if (points_list.find("introduction-point") != string::npos) {
			points_list.erase(points_list.begin(), points_list.begin() + points_list.find("introduction-point"));
		}

		buffer_point.identifier = identifier;
		buffer_point.ip = ip;
		buffer_point.port = atoi(port.c_str());
		buffer_point.onion_key = onionKey;
		buffer_point.service_key = serviceKey;

		ByteQueue queue;
		Base64Decoder decoder;
		decoder.Attach(new Redirector(queue));
		decoder.Put((const byte*)onionKey.c_str(), onionKey.length());
		decoder.MessageEnd();
		buffer_point.public_onion_key.BERDecodePublicKey(queue, false, queue.MaxRetrievable());
		RSAES_OAEP_SHA_Encryptor encryptorDop(buffer_point.public_onion_key);
		buffer_point.encryptor_onion = encryptorDop;

		ByteQueue queue2;
		Base64Decoder decoder2;
		decoder2.Attach(new Redirector(queue2));
		decoder2.Put((const byte*)serviceKey.c_str(), serviceKey.length());
		decoder2.MessageEnd();
		buffer_point.public_service_key.BERDecodePublicKey(queue2, false, queue2.MaxRetrievable());
		RSAES_OAEP_SHA_Encryptor encryptorDop2(buffer_point.public_service_key);
		buffer_point.encryptor_service = encryptorDop2;


		for (int i = 0; i < consensus.relays_num; i++) {
			if (consensus.relays[i].relay_ip.ip_string == ip && consensus.relays[i].relay_orport == atoi(port.c_str())) {
				buffer_point.relay_number = i;
			}
		}

		Base64Decoder decoder3;
		decoder3.Put((byte*)serviceKey.data(), serviceKey.size());
		decoder3.MessageEnd();

		word64 size = decoder3.MaxRetrievable();
		if (size && size <= SIZE_MAX)
		{
			buffer_point.dec_service_key.resize(size);
			decoder3.Get(buffer_point.dec_service_key.data(), size);
		}

		introduction_points.push_back(buffer_point);
	}

	/*
	cout << endl;
	for (int i = 0; i < introduction_points.size(); i++) {
		cout << "Intro point #" << i << endl;
		cout << "Relay num: " << introduction_points[i].relay_number << endl;
		cout << "identifier: " << introduction_points[i].identifier << endl;
		cout << "ip: " << introduction_points[i].ip << endl;
		cout << "port: " << introduction_points[i].port << endl;
		cout << "onionKey: " << introduction_points[i].onion_key << endl;
		cout << "serviceKey: " << introduction_points[i].service_key << endl;
		cout << endl;
	}
	cout << endl;
	*/
	
	return 0;
}
