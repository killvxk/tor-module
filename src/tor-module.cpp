#include "common.h"
#include "Tor.h"

using namespace tor;

int main()
{
	Tor tor;
	tor.Initialize();
	
	//http://duskgytldkxiuqc6.onion/fedpapers/federndx.htm
	tor.ConnectToOnionServer("duskgytldkxiuqc6.onion");

	system("pause");
}