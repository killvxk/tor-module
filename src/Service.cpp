#include "Service.h"
tor::Service::Service(Consensus& consensus, string onion_url) : 
	consensus(consensus), 
	onion_url(onion_url), 
	circuit_descriptor(onion_url, consensus),
	circuit_rendezvous(onion_url, consensus),
	circuit_introducing(onion_url, consensus)
{
	
}

int tor::Service::ConnectToService()
{
	int return_code = 0;
	return_code = GetResponsibleDirectories();
	if (return_code) {
		return 1;
	}

	// set first circuit to get descriptor
	circuit_descriptor.Initialize(onion_url, consensus, descriptors, descriptor_relays);
	circuit_descriptor.SetCircuit(2, Circuit::CircuitType::DescriptorFetch);

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

#ifdef CIRCUIT_DEBUG_INFO
		for (int i = 0; i < 5; i++) {
			cout << (int)first_sha_bytes[i] << " ";
		}
		cout << endl;
#endif

		byte first_hash[CryptoPP::SHA1::DIGESTSIZE];
		GetSHA1(first_sha_bytes, 5, first_hash);

#ifdef CIRCUIT_DEBUG_INFO
		HexEncoder hexEncoder;
		hexEncoder.Put(first_hash, CryptoPP::SHA1::DIGESTSIZE);
		hexEncoder.MessageEnd();

		word64 sizeHex = hexEncoder.MaxRetrievable();
		byte* firstHex = new byte[sizeHex];
		hexEncoder.Get(firstHex, sizeHex);

		cout << "First sha1: " << sizeHex << " " << permanent_id_size << endl;
		for (int i = 0; i < sizeHex; i++) {
			cout << firstHex[i];
		}
		cout << endl;
		delete firstHex;
#endif

		byte* second_sha_bytes = new byte[permanent_id_size + CryptoPP::SHA1::DIGESTSIZE];

		memcpy(second_sha_bytes, permanent_id, permanent_id_size);
		memcpy(second_sha_bytes + permanent_id_size, first_hash, CryptoPP::SHA1::DIGESTSIZE);

		byte second_hash[CryptoPP::SHA1::DIGESTSIZE];
		GetSHA1(second_sha_bytes, permanent_id_size + CryptoPP::SHA1::DIGESTSIZE, second_hash);

		delete[] second_sha_bytes;

#ifdef CIRCUIT_DEBUG_INFO
		HexEncoder hexEncoder2;
		hexEncoder2.Put(second_hash, CryptoPP::SHA1::DIGESTSIZE);
		hexEncoder2.MessageEnd();

		sizeHex = hexEncoder2.MaxRetrievable();
		byte* secondHex = new byte[sizeHex];
		hexEncoder2.Get(secondHex, sizeHex);

		cout << "Second sha1: " << sizeHex << endl;
		for (int i = 0; i < sizeHex; i++) {
			cout << secondHex[i];
		}
		cout << endl;
		delete secondHex;
#endif

		byte* descriptor;
		unsigned long descriptor_size;
		Base32Encode(second_hash, CryptoPP::SHA1::DIGESTSIZE, descriptor, descriptor_size);

		descriptors.push_back(string(reinterpret_cast<char*>(descriptor)));

		delete[] descriptor;

		int counter = 0, found_count = 0;

		while (true) {
			if (consensus.relays[counter].relay_flags.HSDir && memcmp(consensus.relays[counter].relay_identity, second_hash, 20) > 0) {
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
