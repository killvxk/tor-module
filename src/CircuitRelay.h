#pragma once

#include "common.h"
#include "Relay.h"

namespace tor {

	class CircuitRelay : public Relay {
	public:
		// circuit info
		unsigned long circuit_id = 0;

		SSLSocket ssl_socket;

		// crypto objects

		bool is_crypto_initialized = false;
		// RSA
		RSA::PublicKey onion_key; // public onion-key rsa (uses in CREATE, EXTEND cells)
		RSAES_OAEP_SHA_Encryptor onion_encryptor;
		string onion_key_string;
		byte* onion_key_bytes = nullptr;
		int onion_key_bytes_size = 0;
		// DH
		SecByteBlock private_a_number;
		SecByteBlock public_a_number;
		SecByteBlock public_b_number;
		SecByteBlock secret_key_number;
		DH dh_handle;
		// AES
		CTR_Mode<AES>::Encryption *encryptor_forward = new CTR_Mode<AES>::Encryption();
		CTR_Mode<AES>::Decryption *encryptor_backward = new CTR_Mode<AES>::Decryption();
		byte iv[16] = {0, 0, 0 , 0, 0, 0, 0 , 0, 0, 0, 0 , 0, 0, 0, 0 , 0 };
		// SHA1
		vector<byte> hash_backward_bytes;
		vector<byte> hash_forward_bytes;
		// keys
		/*
		d_forward is used to seed the integrity-checking hash for the stream of data going from the OP to the OR.
		d_backward seeds the integrity-checking hash for the data stream from the OR to the OP.
		key_forward is used to encrypt the stream of data going from the OP to the OR.
		key_backward is used to encrypt the stream of data going from the OR to the OP.
	   */
		byte d_forward[HASH_LEN], d_backward[HASH_LEN], key_forward[KEY_LEN], key_backward[KEY_LEN];

		CircuitRelay();
		CircuitRelay(Relay relay, unsigned int circuit_id);

		int ConnectSsl();

		// TAP handshake
		int CreateOnionSkin(int& output_size, byte* output_data);
		int HybridEncryption(byte* output_data, int& output_size, byte* input_data, int input_size);
		int FinishTapHandshake(byte *key_part, short key_part_size);

		int EncryptCell(byte* cell_bytes, int cell_size);
		int DecryptCell(byte* cell_bytes, int cell_size);

		int DHInititalize();
	};

}// namespace tor