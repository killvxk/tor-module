#include "CircuitRelay.h"

tor::CircuitRelay::CircuitRelay()
{
}

tor::CircuitRelay::CircuitRelay(Relay relay, unsigned int circuit_id) : Relay(relay.full_relay_string), circuit_id(circuit_id)
{
	
}

tor::CircuitRelay::~CircuitRelay()
{
	//if (onion_key_bytes)
		//delete[] onion_key_bytes;
}

int tor::CircuitRelay::ConnectSsl()
{
	ssl_socket.Connect(relay_ip.ip_string, relay_orport);

	return 0;
}

int tor::CircuitRelay::CreateOnionSkin(int& output_size, byte* output_data)
{
	Integer dh_prime("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF");
	Integer dh_generator = 2;

	AutoSeededRandomPool random_pool;

	dh_handle.AccessGroupParameters().Initialize(dh_prime, dh_generator);

	private_a_number = SecByteBlock(dh_handle.PrivateKeyLength());
	public_a_number = SecByteBlock(dh_handle.PublicKeyLength());
	public_b_number = SecByteBlock(dh_handle.PublicKeyLength());
	secret_key_number = SecByteBlock(dh_handle.AgreedValueLength());
	
	dh_handle.GenerateKeyPair(random_pool, private_a_number, public_a_number);

	int public_key_size = public_a_number.size();
	byte* data = new byte[public_a_number.size()];
	memcpy(data, public_a_number.data(), public_key_size);

	HybridEncryption(output_data, output_size, data, public_key_size);

	delete[] data;

	return 0;
}

int tor::CircuitRelay::HybridEncryption(byte* output_data, int& output_size, byte* input_data, int input_size)
{
	tor::HybridEncryption(output_data, output_size, input_data, input_size, onion_encryptor);

	return 0;
}

int tor::CircuitRelay::FinishTapHandshake(byte* key_part, short key_part_size)
{
	byte* key_material = new byte[SHA1::DIGESTSIZE * 5];

	memcpy(public_b_number.BytePtr(), key_part, DH_LEN); // copy public b number

	dh_handle.Agree(secret_key_number, private_a_number, public_b_number); // compute secret key

	byte* secret_key_bytes = new byte[secret_key_number.SizeInBytes() + 1];
	memcpy(secret_key_bytes, secret_key_number.BytePtr(), secret_key_number.SizeInBytes()); // copy secret number to buffer

	byte digest[SHA1::DIGESTSIZE];

	for (byte i = 0; i < 5; i++) {
		memset(secret_key_bytes + secret_key_number.SizeInBytes(), i, 1); // set byte for hashing
		GetSHA1(secret_key_bytes, secret_key_number.SizeInBytes() + 1, digest);
		memcpy(key_material + i * SHA1::DIGESTSIZE, digest, SHA1::DIGESTSIZE);
	}

	if (!memcmp(key_material, key_part + DH_LEN, HASH_LEN)) { // compare our KH with control number, sent by OR
		cout << "Handshake success" << endl;

		is_crypto_initialized = true;
	}
	else {
		cout << "Handshake error" << endl;
		return 1;
	}

	// initialize keys
	memcpy(d_forward, key_material + HASH_LEN, HASH_LEN);
	memcpy(d_backward, key_material + HASH_LEN * 2, HASH_LEN);
	memcpy(key_forward, key_material + HASH_LEN * 3, KEY_LEN);
	memcpy(key_backward, key_material + HASH_LEN * 3 + KEY_LEN, KEY_LEN);

	// initialize ecryptors and hashers
	encryptor_forward->SetKeyWithIV(key_forward, AES::DEFAULT_KEYLENGTH, iv);
	encryptor_backward->SetKeyWithIV(key_backward, AES::DEFAULT_KEYLENGTH, iv);

	// initialize hashing bytes
	hash_forward_bytes.resize(HASH_LEN);
	memcpy(hash_forward_bytes.data(), d_forward, HASH_LEN);
	hash_backward_bytes.resize(HASH_LEN);
	memcpy(hash_backward_bytes.data(), d_backward, HASH_LEN);
	
	//clean
	delete[] secret_key_bytes;
	delete[] key_material;

	return 0;
}

int tor::CircuitRelay::EncryptCell(byte* cell_bytes, int cell_size)
{
	encryptor_forward->ProcessData(cell_bytes + 5, cell_bytes + 5, cell_size - 5);

	return 0;
}

int tor::CircuitRelay::DecryptCell(byte* cell_bytes, int cell_size)
{
	encryptor_backward->ProcessData(cell_bytes + 5, cell_bytes + 5, cell_size - 5);

	return 0;
}

int tor::CircuitRelay::DHInititalize()
{
	Integer dh_prime("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF");
	Integer dh_generator = 2;

	AutoSeededRandomPool random_pool;

	dh_handle.AccessGroupParameters().Initialize(dh_prime, dh_generator);

	private_a_number = SecByteBlock(dh_handle.PrivateKeyLength());
	public_a_number = SecByteBlock(dh_handle.PublicKeyLength());
	public_b_number = SecByteBlock(dh_handle.PublicKeyLength());
	secret_key_number = SecByteBlock(dh_handle.AgreedValueLength());

	dh_handle.GenerateKeyPair(random_pool, private_a_number, public_a_number);

	return 0;
}
