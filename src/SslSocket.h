#pragma once
#include "common.h"

using namespace std;

class SSLSocket {
public:

	void SSLSocketDelete();
	int Connect(string ipI, int portI);
	int SendData(BYTE* message, int size);
	int GetData(BYTE*& message, int& size);

	struct sockaddr_in sin;
	struct hostent* hp;

private:
	int Initialize();
	bool LoadSecurityLibrary();
	void UnloadSecurityLibrary();


	SECURITY_STATUS CreateCredentials();
	int ConnectToServer(char* pszServerName, int iPortNumber);
	SECURITY_STATUS PerformClientHandshake(LPSTR pszServerName, SecBuffer* pExtraData);
	SECURITY_STATUS ClientHandshakeLoop(BOOL fDoInitialRead, SecBuffer* pExtraData);
	void GetNewClientCredentials();
	long DisconnectFromServer();
	SECURITY_STATUS ReadDecrypt(PCredHandle phCreds, CtxtHandle* phContext, PBYTE pbIoBuffer, DWORD cbIoBufferLength, int& size);
	void DebugLog(string error);



	WSADATA WsaData;
	SOCKET  Socket;

	CredHandle hClientCreds;
	CtxtHandle hContext;

	SecBuffer  ExtraData;
	SECURITY_STATUS Status;
	PCCERT_CONTEXT pRemoteCertContext;
	SecPkgContext_StreamSizes Sizes;

	DWORD   dwProtocol = SP_PROT_TLS1_2;
	ALG_ID  aiKeyExch = 0;

	HCERTSTORE hMyCertStore = NULL;
	HMODULE g_hSecurity = NULL;

	SCHANNEL_CRED SchannelCred;
	PSecurityFunctionTable g_pSSPI = new SecurityFunctionTable;

	bool fCredsInitialized = false;
	bool fContextInitialized = false;

	string ip;
	int port;
	bool isDebug = true;

	static const DWORD recv_timeout = 4000;
};