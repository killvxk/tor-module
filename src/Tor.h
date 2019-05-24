#pragma once
#include "common.h"
#include "Consensus.h"

namespace tor {

	class Tor {
	public:
		Consensus consensus;

		Tor();
		void Initialize();
		string GetOnionData(string onion_url, string query);
	};

}// namespace tor