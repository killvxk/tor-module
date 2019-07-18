#include "SslSocket.h"


void SSLSocket::Connect(string ipI, int portI)
{
	ip = ipI;
	port = portI;

	if (isDebug) {
		ofstream ofs("debug.txt", ios_base::trunc);
		ofs.close();
	}

	Initialize();

	cout << "SSL connected" << endl;
}

void SSLSocket::SSLSocketDelete()
{
	if (DisconnectFromServer())
	{
		DebugLog("Error disconnecting from server");
	}
	fContextInitialized = FALSE;
	Socket = INVALID_SOCKET;
	DebugLog("Disconnected From Server");


	DebugLog("Begin Cleanup");

	if (pRemoteCertContext)
	{
		CertFreeCertificateContext(pRemoteCertContext);
		pRemoteCertContext = NULL;
	}

	if (fContextInitialized)
	{
		g_pSSPI->DeleteSecurityContext(&hContext);
		fContextInitialized = FALSE;
	}

	if (fCredsInitialized)
	{
		g_pSSPI->FreeCredentialsHandle(&hClientCreds);
		fCredsInitialized = FALSE;
	}

	if (Socket != INVALID_SOCKET) closesocket(Socket);

	WSACleanup();

	if (hMyCertStore) CertCloseStore(hMyCertStore, 0);

	UnloadSecurityLibrary();

	DebugLog("All Done");
}

int SSLSocket::SendData(BYTE * message, int size)
{
	BYTE* pbIoBuffer = (PBYTE)LocalAlloc(LMEM_FIXED, Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer);

	memcpy(pbIoBuffer + Sizes.cbHeader, message, size);

	SECURITY_STATUS    scRet;
	SecBufferDesc        Message;
	SecBuffer                Buffers[4];
	DWORD                        cbMessage, cbData;
	PBYTE                        pbMessage;

	pbMessage = pbIoBuffer + Sizes.cbHeader;
	cbMessage = size;
	DebugLog("Sending " + to_string(cbMessage) + " bytes of plaintext");


	Buffers[0].pvBuffer = pbIoBuffer;
	Buffers[0].cbBuffer = Sizes.cbHeader;
	Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

	Buffers[1].pvBuffer = pbMessage;
	Buffers[1].cbBuffer = cbMessage;
	Buffers[1].BufferType = SECBUFFER_DATA;

	Buffers[2].pvBuffer = pbMessage + cbMessage;
	Buffers[2].cbBuffer = Sizes.cbTrailer;
	Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

	Buffers[3].pvBuffer = SECBUFFER_EMPTY;
	Buffers[3].cbBuffer = SECBUFFER_EMPTY;
	Buffers[3].BufferType = SECBUFFER_EMPTY;


	Message.ulVersion = SECBUFFER_VERSION;
	Message.cBuffers = 4;
	Message.pBuffers = Buffers;
	scRet = g_pSSPI->EncryptMessage(&hContext, 0, &Message, 0);

	if (FAILED(scRet)) {
		DebugLog("Error returned by EncryptMessage | scRet:" + to_string(scRet));
		return scRet;
	}

	cbData = send(Socket, (char*)pbIoBuffer, Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer, 0);

	DebugLog(to_string(cbData) + " bytes of encrypted data sent");

	LocalFree(pbIoBuffer);

	return 0;
}

int SSLSocket::GetData(BYTE* &message, int& size)
{
	PBYTE pbIoBuffer;
	DWORD cbIoBufferLength;
	ULONG scRet;

	cbIoBufferLength = Sizes.cbHeader + Sizes.cbMaximumMessage + Sizes.cbTrailer;
	pbIoBuffer = (PBYTE)LocalAlloc(LMEM_FIXED, cbIoBufferLength);


	SecBuffer                ExtraBuffer;
	SecBuffer* pDataBuffer, * pExtraBuffer;


	SecBufferDesc        Message;
	SecBuffer                Buffers[4];

	DWORD                        cbIoBuffer, length;
	int cbData = 0;
	int i;

	DebugLog("Start to Get Data " + to_string(Sizes.cbMaximumMessage));

	cbIoBuffer = 0;
	scRet = 0;

	read_more_data:
	if (cbIoBuffer == 0 || scRet == SEC_E_INCOMPLETE_MESSAGE)
	{
		cbData = recv(Socket, (char*)pbIoBuffer + cbIoBuffer, cbIoBufferLength - cbIoBuffer, 0);

		if (cbData == SOCKET_ERROR)
		{
			DebugLog("Error reading data from server | WSAGetLastError:" + to_string(WSAGetLastError()));
			scRet = SEC_E_INTERNAL_ERROR;
			return 1;
		}
		else if (cbData == 0)
		{
			if (cbIoBuffer)
			{
				DebugLog("Server unexpectedly disconnected");
				scRet = SEC_E_INTERNAL_ERROR;
				return 2;
			}
			else {
				return 3;//all done
			}
		}
		else
		{
			DebugLog(to_string(cbData) + " bytes of encrypted application data received");
			cbIoBuffer += cbData;
		}
	}

	Buffers[0].pvBuffer = pbIoBuffer;
	Buffers[0].cbBuffer = cbIoBuffer;
	Buffers[0].BufferType = SECBUFFER_DATA;
	Buffers[1].BufferType = SECBUFFER_EMPTY;
	Buffers[2].BufferType = SECBUFFER_EMPTY;
	Buffers[3].BufferType = SECBUFFER_EMPTY;

	Message.ulVersion = SECBUFFER_VERSION;
	Message.cBuffers = 4;
	Message.pBuffers = Buffers;
	scRet = g_pSSPI->DecryptMessage(&hContext, &Message, 0, NULL);

	if (scRet != SEC_E_OK &&
		scRet != SEC_I_RENEGOTIATE &&
		scRet != SEC_I_CONTEXT_EXPIRED)
	{
		if (scRet == SEC_E_INCOMPLETE_MESSAGE)
			goto read_more_data;

		DebugLog("Error returned by DecryptMessage | scRet:" + to_string(scRet));
		return scRet;
	}


	pDataBuffer = NULL;
	pExtraBuffer = NULL;
	for (i = 1; i < 4; i++)
	{
		if (pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA) pDataBuffer = &Buffers[i];
		if (pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA) pExtraBuffer = &Buffers[i];
	}


	if (pDataBuffer)
	{
		length = pDataBuffer->cbBuffer;
		size = length;
		if (length)
		{
			//buff = (PBYTE)pDataBuffer->pvBuffer;
			message = new byte[size];
			memcpy(message, pDataBuffer->pvBuffer, size);
			DebugLog("Decrypted data: " + to_string(length) + " bytes");

			ofstream ofs("cells.txt", ios_base::app);
			ofs.write((char*)message, size);
			ofs.close();
		}
	}



	if (pExtraBuffer)
	{
		MoveMemory(pbIoBuffer, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
		cbIoBuffer = pExtraBuffer->cbBuffer;
	}
	else
		cbIoBuffer = 0;


	if (scRet == SEC_I_RENEGOTIATE)
	{
		DebugLog("Server requested renegotiate");
		scRet = ClientHandshakeLoop(FALSE, &ExtraBuffer);
		if (scRet != SEC_E_OK) return scRet;

		if (ExtraBuffer.pvBuffer)
		{
			MoveMemory(pbIoBuffer, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
			cbIoBuffer = ExtraBuffer.cbBuffer;
		}
	}

	LocalFree(pbIoBuffer);

	return 0;
}

int SSLSocket::Initialize()
{
	bool result;
	result = LoadSecurityLibrary();
	if (!result) {
		DebugLog("Error loading library");
		return 1;
	}
	DebugLog("Secur32.dll was loaded");

	if (CreateCredentials())
	{
		DebugLog("Error creating credentials");
		return 3;
	}
	fCredsInitialized = true;
	DebugLog("Credentials Initialized");

	if (ConnectToServer((char*)ip.c_str(), port))
	{
		DebugLog("Error connecting to server");
		return 4;
	}
	DebugLog("Connected To Server");

	if (PerformClientHandshake((LPSTR)ip.c_str(), &ExtraData))
	{
		DebugLog("Error performing handshake");
		return 5;
	}
	fContextInitialized = true;
	DebugLog("Client Handshake Performed");

	Status = g_pSSPI->QueryContextAttributes(&hContext, SECPKG_ATTR_REMOTE_CERT_CONTEXT, (PVOID)& pRemoteCertContext);
	if (Status != SEC_E_OK)
	{
		DebugLog("Error querying remote certificate | Status:" + to_string(Status));
		return 6;
	}
	DebugLog("Server Credentials Authenticated");


	CertFreeCertificateContext(pRemoteCertContext);
	pRemoteCertContext = NULL;
	DebugLog("Server certificate context released");

	SECURITY_STATUS scRet;
	scRet = g_pSSPI->QueryContextAttributes(&hContext, SECPKG_ATTR_STREAM_SIZES, &Sizes);
	if (scRet != SEC_E_OK)
	{
		DebugLog("Error reading SECPKG_ATTR_STREAM_SIZES | scRet:" + to_string(scRet));
	}

	return 0;
}

bool SSLSocket::LoadSecurityLibrary()
{
	INIT_SECURITY_INTERFACE pInitSecurityInterface;
	OSVERSIONINFO VerInfo;

	g_hSecurity = LoadLibraryA("Secur32.dll");
	if (g_hSecurity == NULL) {
		DebugLog("Error loading Secur32.dll | GetLastError:" + to_string(GetLastError()));
		return false;
	}

	pInitSecurityInterface = (INIT_SECURITY_INTERFACE)GetProcAddress(g_hSecurity, "InitSecurityInterfaceA");
	if (pInitSecurityInterface == NULL) {
		DebugLog("Error reading InitSecurityInterface entry point | GetLastError:" + to_string(GetLastError()));
		return false;
	}

	g_pSSPI = pInitSecurityInterface();
	if (g_pSSPI == NULL) {
		DebugLog("Error reading security interface | GetLastError:" + to_string(GetLastError()));
		return false;
	}

	return true;
}

void SSLSocket::UnloadSecurityLibrary()
{
	FreeLibrary(g_hSecurity);
	g_hSecurity = NULL;
}

SECURITY_STATUS SSLSocket::CreateCredentials()
{
	TimeStamp        tsExpiry;
	SECURITY_STATUS  Status;
	DWORD            cSupportedAlgs = 0;
	ALG_ID           rgbSupportedAlgs[16];
	PCCERT_CONTEXT   pCertContext = NULL;


	if (hMyCertStore == NULL)
	{
		hMyCertStore = CertOpenSystemStoreA(0, "MY");
		if (!hMyCertStore)
		{
			DebugLog("Error returned by CertOpenSystemStore | GetLastError:" + to_string(GetLastError()));
			return SEC_E_NO_CREDENTIALS;
		}
	}

	ZeroMemory(&SchannelCred, sizeof(SchannelCred));

	SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
	if (pCertContext)
	{
		SchannelCred.cCreds = 1;
		SchannelCred.paCred = &pCertContext;
	}

	SchannelCred.grbitEnabledProtocols = dwProtocol;

	if (aiKeyExch) rgbSupportedAlgs[cSupportedAlgs++] = aiKeyExch;

	if (cSupportedAlgs)
	{
		SchannelCred.cSupportedAlgs = cSupportedAlgs;
		SchannelCred.palgSupportedAlgs = rgbSupportedAlgs;
	}

	SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
	SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;


	Status = g_pSSPI->AcquireCredentialsHandle(NULL,
		const_cast<char*>(UNISP_NAME),
		SECPKG_CRED_OUTBOUND,
		NULL,
		&SchannelCred,
		NULL,
		NULL,
		&hClientCreds,
		&tsExpiry);

	if (Status != SEC_E_OK) DebugLog("Error returned by AcquireCredentialsHandle | Status:" + to_string((ULONG)Status));

	if (pCertContext) CertFreeCertificateContext(pCertContext);

	return Status;
}

int SSLSocket::ConnectToServer(char* pszServerName, int iPortNumber)
{
	Socket = socket(PF_INET, SOCK_STREAM, 0);
	if (Socket == INVALID_SOCKET)
	{
		DebugLog("Error creating socket | WSAGetLastError:" + to_string(WSAGetLastError()));
		return WSAGetLastError();
	}


	sin.sin_family = AF_INET;
	sin.sin_port = htons((u_short)iPortNumber);
	if ((hp = gethostbyname(pszServerName)) == NULL)
	{
		DebugLog("Error returned by gethostbyname | WSAGetLastError:" + to_string(WSAGetLastError()));
		return WSAGetLastError();
	}
	else
		memcpy(&sin.sin_addr, hp->h_addr, 4);


	if (connect(Socket, (struct sockaddr*) & sin, sizeof(sin)) == SOCKET_ERROR)
	{
		DebugLog("Error connecting to server | WSAGetLastError:" + to_string(WSAGetLastError()));
		DebugLog(string(pszServerName) + " " + to_string(iPortNumber));
		closesocket(Socket);
		return WSAGetLastError();
	}

	return SEC_E_OK;
}

SECURITY_STATUS SSLSocket::PerformClientHandshake(LPSTR pszServerName, SecBuffer * pExtraData)
{
	SecBufferDesc   OutBuffer;
	SecBuffer       OutBuffers[1];
	DWORD           dwSSPIFlags, dwSSPIOutFlags, cbData;
	TimeStamp       tsExpiry;
	SECURITY_STATUS scRet;


	dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
		ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;


	OutBuffers[0].pvBuffer = NULL;
	OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	OutBuffers[0].cbBuffer = 0;

	OutBuffer.cBuffers = 1;
	OutBuffer.pBuffers = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;

	scRet = g_pSSPI->InitializeSecurityContext(&hClientCreds,
		NULL,
		const_cast<char*>(pszServerName),
		dwSSPIFlags,
		0,
		SECURITY_NATIVE_DREP,
		NULL,
		0,
		&hContext,
		&OutBuffer,
		&dwSSPIOutFlags,
		&tsExpiry);

	if (scRet != SEC_I_CONTINUE_NEEDED) {
		DebugLog("Error returned by InitializeSecurityContext | scRet:" + to_string((unsigned long)scRet));
		return scRet;
	}

	if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
	{
		cbData = send(Socket, (char*)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
		if (cbData == SOCKET_ERROR || cbData == 0)
		{
			DebugLog("Error sending data to server | WSAGetLastError:" + to_string(WSAGetLastError()));
			g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
			g_pSSPI->DeleteSecurityContext(&hContext);
			return SEC_E_INTERNAL_ERROR;
		}
		DebugLog(to_string(cbData) + " bytes of handshake data sent");
		g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
		OutBuffers[0].pvBuffer = NULL;
	}

	return ClientHandshakeLoop(TRUE, pExtraData);
}

SECURITY_STATUS SSLSocket::ClientHandshakeLoop(BOOL fDoInitialRead, SecBuffer * pExtraData)
{
	SecBufferDesc   OutBuffer, InBuffer;
	SecBuffer       InBuffers[2], OutBuffers[1];
	DWORD           dwSSPIFlags, dwSSPIOutFlags, cbData, cbIoBuffer;
	TimeStamp       tsExpiry;
	SECURITY_STATUS scRet;
	PUCHAR          IoBuffer;
	BOOL            fDoRead;


	dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
		ISC_RET_EXTENDED_ERROR | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

	IoBuffer = (PUCHAR)LocalAlloc(LMEM_FIXED, IO_BUFFER_SIZE);
	if (IoBuffer == NULL) {
		DebugLog("Out of memory(1)");
		return SEC_E_INTERNAL_ERROR;
	}
	cbIoBuffer = 0;
	fDoRead = fDoInitialRead;


	scRet = SEC_I_CONTINUE_NEEDED;

	while (scRet == SEC_I_CONTINUE_NEEDED ||
		scRet == SEC_E_INCOMPLETE_MESSAGE ||
		scRet == SEC_I_INCOMPLETE_CREDENTIALS)
	{
		if (0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE) // Read data from server.
		{
			if (fDoRead)
			{
				cbData = recv(Socket, (char*)IoBuffer + cbIoBuffer, IO_BUFFER_SIZE - cbIoBuffer, 0);
				if (cbData == SOCKET_ERROR)
				{
					DebugLog("Error reading data from server | WSAGetLastError:" + to_string(WSAGetLastError()));
					scRet = SEC_E_INTERNAL_ERROR;
					break;
				}
				else if (cbData == 0)
				{
					DebugLog("Server unexpectedly disconnected");
					scRet = SEC_E_INTERNAL_ERROR;
					break;
				}
				DebugLog(to_string(cbData) + " bytes of handshake data received");
				cbIoBuffer += cbData;
			}
			else
				fDoRead = TRUE;
		}


		InBuffers[0].pvBuffer = IoBuffer;
		InBuffers[0].cbBuffer = cbIoBuffer;
		InBuffers[0].BufferType = SECBUFFER_TOKEN;

		InBuffers[1].pvBuffer = NULL;
		InBuffers[1].cbBuffer = 0;
		InBuffers[1].BufferType = SECBUFFER_EMPTY;

		InBuffer.cBuffers = 2;
		InBuffer.pBuffers = InBuffers;
		InBuffer.ulVersion = SECBUFFER_VERSION;


		OutBuffers[0].pvBuffer = NULL;
		OutBuffers[0].BufferType = SECBUFFER_TOKEN;
		OutBuffers[0].cbBuffer = 0;

		OutBuffer.cBuffers = 1;
		OutBuffer.pBuffers = OutBuffers;
		OutBuffer.ulVersion = SECBUFFER_VERSION;


		scRet = g_pSSPI->InitializeSecurityContext(&hClientCreds,
			&hContext,
			NULL,
			dwSSPIFlags,
			0,
			SECURITY_NATIVE_DREP,
			&InBuffer,
			0,
			NULL,
			&OutBuffer,
			&dwSSPIOutFlags,
			&tsExpiry);


		if (scRet == SEC_E_OK ||
			scRet == SEC_I_CONTINUE_NEEDED ||
			FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))
		{
			if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
			{
				cbData = send(Socket, (char*)OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
				if (cbData == SOCKET_ERROR || cbData == 0)
				{
					DebugLog("Error sending data to server | WSAGetLastError:" + to_string(WSAGetLastError()));
					g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
					g_pSSPI->DeleteSecurityContext(&hContext);
					return SEC_E_INTERNAL_ERROR;
				}
				DebugLog(to_string(cbData) + " bytes of handshake data sent");

				g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
				OutBuffers[0].pvBuffer = NULL;
			}
		}



		if (scRet == SEC_E_INCOMPLETE_MESSAGE) continue;


		if (scRet == SEC_E_OK)
		{
			DebugLog("Handshake was successful");

			if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
			{
				pExtraData->pvBuffer = LocalAlloc(LMEM_FIXED, InBuffers[1].cbBuffer);
				if (pExtraData->pvBuffer == NULL) {
					DebugLog("Out of memory(2)");
					return SEC_E_INTERNAL_ERROR;
				}

				MoveMemory(pExtraData->pvBuffer,
					IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
					InBuffers[1].cbBuffer);

				pExtraData->cbBuffer = InBuffers[1].cbBuffer;
				pExtraData->BufferType = SECBUFFER_TOKEN;

				DebugLog(to_string(pExtraData->cbBuffer) + " bytes of app data was bundled with handshake data");
			}
			else
			{
				pExtraData->pvBuffer = NULL;
				pExtraData->cbBuffer = 0;
				pExtraData->BufferType = SECBUFFER_EMPTY;
			}
			break;
		}


		if (FAILED(scRet)) {
			DebugLog("Error returned by InitializeSecurityContext | scRet:" + to_string((unsigned long)scRet));
			break;
		}

		if (scRet == SEC_I_INCOMPLETE_CREDENTIALS)
		{
			GetNewClientCredentials();

			fDoRead = FALSE;
			scRet = SEC_I_CONTINUE_NEEDED;
			continue;
		}

		if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
		{
			MoveMemory(IoBuffer, IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer), InBuffers[1].cbBuffer);
			cbIoBuffer = InBuffers[1].cbBuffer;
		}
		else
			cbIoBuffer = 0;
	}

	if (FAILED(scRet)) g_pSSPI->DeleteSecurityContext(&hContext);
	LocalFree(IoBuffer);

	return scRet;
}

void SSLSocket::GetNewClientCredentials()
{
	CredHandle                        hCreds;
	SecPkgContext_IssuerListInfoEx    IssuerListInfo;
	PCCERT_CHAIN_CONTEXT              pChainContext;
	CERT_CHAIN_FIND_BY_ISSUER_PARA    FindByIssuerPara;
	PCCERT_CONTEXT                    pCertContext;
	TimeStamp                         tsExpiry;
	SECURITY_STATUS                   Status;


	Status = g_pSSPI->QueryContextAttributes(&hContext, SECPKG_ATTR_ISSUER_LIST_EX, (PVOID)& IssuerListInfo);
	if (Status != SEC_E_OK) {
		DebugLog("Error querying issuer list info | Status:" + to_string(Status));
		return;
	}

	ZeroMemory(&FindByIssuerPara, sizeof(FindByIssuerPara));

	FindByIssuerPara.cbSize = sizeof(FindByIssuerPara);
	FindByIssuerPara.pszUsageIdentifier = szOID_PKIX_KP_CLIENT_AUTH;
	FindByIssuerPara.dwKeySpec = 0;
	FindByIssuerPara.cIssuer = IssuerListInfo.cIssuers;
	FindByIssuerPara.rgIssuer = IssuerListInfo.aIssuers;

	pChainContext = NULL;

	while (TRUE)
	{   // Find a certificate chain.
		pChainContext = CertFindChainInStore(hMyCertStore,
			X509_ASN_ENCODING,
			0,
			CERT_CHAIN_FIND_BY_ISSUER,
			&FindByIssuerPara,
			pChainContext);
		if (pChainContext == NULL) {
			DebugLog("Error finding cert chain | GetLastError:" + to_string(GetLastError()));
			break;
		}

		DebugLog("Crtificate chain found");

		pCertContext = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;

		SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
		SchannelCred.cCreds = 1;
		SchannelCred.paCred = &pCertContext;

		Status = g_pSSPI->AcquireCredentialsHandle(NULL,
			const_cast<char*>(UNISP_NAME),
			SECPKG_CRED_OUTBOUND,
			NULL,
			&SchannelCred,
			NULL,
			NULL,
			&hCreds,
			&tsExpiry);

		if (Status != SEC_E_OK) {
			DebugLog("Error returned by AcquireCredentialsHandle | Status:" + to_string(Status));
			continue;
		}

		DebugLog("New schannel credential created");

		g_pSSPI->FreeCredentialsHandle(&hClientCreds);
	}
	return;
}

long SSLSocket::DisconnectFromServer()
{

	PBYTE                    pbMessage;
	DWORD                    dwType, dwSSPIFlags, dwSSPIOutFlags, cbMessage, cbData, Status;
	SecBufferDesc OutBuffer;
	SecBuffer     OutBuffers[1];
	TimeStamp     tsExpiry;


	dwType = SCHANNEL_SHUTDOWN;

	OutBuffers[0].pvBuffer = &dwType;
	OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	OutBuffers[0].cbBuffer = sizeof(dwType);

	OutBuffer.cBuffers = 1;
	OutBuffer.pBuffers = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;

	Status = g_pSSPI->ApplyControlToken(&hContext, &OutBuffer);
	if (FAILED(Status)) {
		DebugLog("Error returned by ApplyControlToken | Status:" + to_string(Status));
		goto cleanup;
	}


	dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT |
		ISC_REQ_REPLAY_DETECT |
		ISC_REQ_CONFIDENTIALITY |
		ISC_RET_EXTENDED_ERROR |
		ISC_REQ_ALLOCATE_MEMORY |
		ISC_REQ_STREAM;

	OutBuffers[0].pvBuffer = NULL;
	OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	OutBuffers[0].cbBuffer = 0;

	OutBuffer.cBuffers = 1;
	OutBuffer.pBuffers = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;

	Status = g_pSSPI->InitializeSecurityContext(&hClientCreds,
		&hContext,
		NULL,
		dwSSPIFlags,
		0,
		SECURITY_NATIVE_DREP,
		NULL,
		0,
		&hContext,
		&OutBuffer,
		&dwSSPIOutFlags,
		&tsExpiry);

	if (FAILED(Status)) {
		DebugLog("Error returned by InitializeSecurityContext | Status:" + to_string((unsigned long)Status));
		goto cleanup;
	}

	pbMessage = (PBYTE)OutBuffers[0].pvBuffer;
	cbMessage = OutBuffers[0].cbBuffer;


	if (pbMessage != NULL && cbMessage != 0)
	{
		cbData = send(Socket, (char*)pbMessage, cbMessage, 0);
		if (cbData == SOCKET_ERROR || cbData == 0)
		{
			Status = WSAGetLastError();
			DebugLog("Error sending close notify | Status:" + to_string(Status));
			goto cleanup;
		}
		DebugLog("Sending Close Notify");
		DebugLog(to_string(cbData) + " bytes of handshake data sent");
		g_pSSPI->FreeContextBuffer(pbMessage);
	}


cleanup:
	g_pSSPI->DeleteSecurityContext(&hContext);
	closesocket(Socket);

	return Status;
}


SECURITY_STATUS SSLSocket::ReadDecrypt(PCredHandle phCreds, CtxtHandle * phContext, PBYTE pbIoBuffer, DWORD cbIoBufferLength, int& size)
{
	SecBuffer                ExtraBuffer;
	SecBuffer* pDataBuffer, * pExtraBuffer;

	SECURITY_STATUS    scRet;
	SecBufferDesc        Message;
	SecBuffer                Buffers[4];

	DWORD                        cbIoBuffer, cbData, length;
	PBYTE                        buff = new BYTE[100];
	int i;


	cbIoBuffer = 0;
	scRet = 0;
	if (cbIoBuffer == 0 || scRet == SEC_E_INCOMPLETE_MESSAGE)
	{
		cbData = recv(Socket, (char*)pbIoBuffer + cbIoBuffer, cbIoBufferLength - cbIoBuffer, 0);
		if (cbData == SOCKET_ERROR)
		{
			DebugLog("Error reading data from server | WSAGetLastError:" + to_string(WSAGetLastError()));
			scRet = SEC_E_INTERNAL_ERROR;
			return 1;
		}
		else if (cbData == 0)
		{
			if (cbIoBuffer)
			{
				DebugLog("Server unexpectedly disconnected");
				scRet = SEC_E_INTERNAL_ERROR;
				return 2;
			}
			else return 3;
		}
		else
		{
			DebugLog(to_string(cbData) + " bytes of encrypted application data received");
			cbIoBuffer += cbData;
		}
	}


	Buffers[0].pvBuffer = pbIoBuffer;
	Buffers[0].cbBuffer = cbIoBuffer;
	Buffers[0].BufferType = SECBUFFER_DATA;
	Buffers[1].BufferType = SECBUFFER_EMPTY;
	Buffers[2].BufferType = SECBUFFER_EMPTY;
	Buffers[3].BufferType = SECBUFFER_EMPTY;

	Message.ulVersion = SECBUFFER_VERSION;
	Message.cBuffers = 4;
	Message.pBuffers = Buffers;
	scRet = g_pSSPI->DecryptMessage(phContext, &Message, 0, NULL);

	if (scRet != SEC_E_OK &&
		scRet != SEC_I_RENEGOTIATE &&
		scRet != SEC_I_CONTEXT_EXPIRED)
	{
		DebugLog("Error returned by DecryptMessage | scRet:" + to_string(scRet));
		return scRet;
	}


	pDataBuffer = NULL;
	pExtraBuffer = NULL;
	for (i = 1; i < 4; i++)
	{
		if (pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA) pDataBuffer = &Buffers[i];
		if (pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA) pExtraBuffer = &Buffers[i];
	}


	if (pDataBuffer)
	{
		length = pDataBuffer->cbBuffer;
		if (length)
		{
			buff = (PBYTE)pDataBuffer->pvBuffer;
			DebugLog("Decrypted data: " + to_string(length) + " bytes");

			//ofstream ofs("cells.txt", ios_base::trunc);
			//ofs.write((char*)buff, length);
			//ofs.close();
		}
	}



	if (pExtraBuffer)
	{
		MoveMemory(pbIoBuffer, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
		cbIoBuffer = pExtraBuffer->cbBuffer;
	}
	else
		cbIoBuffer = 0;


	if (scRet == SEC_I_RENEGOTIATE)
	{
		DebugLog("Server requested renegotiate");
		scRet = ClientHandshakeLoop(FALSE, &ExtraBuffer);
		if (scRet != SEC_E_OK) return scRet;

		if (ExtraBuffer.pvBuffer)
		{
			MoveMemory(pbIoBuffer, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
			cbIoBuffer = ExtraBuffer.cbBuffer;
		}
	}

	size = length;
	RtlMoveMemory(pbIoBuffer, buff, length);

	return SEC_E_OK;
}


void SSLSocket::DebugLog(string error)
{
	if (isDebug) {
		ofstream ofs("debug.txt", ios_base::app);
		ofs << error << endl;
		ofs.close();
	}
	return;
}
