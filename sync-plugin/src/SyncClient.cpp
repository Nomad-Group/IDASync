#include "SyncClient.h"
#include "SyncPlugin.h"

#include "packets/HandshakePacket.h"

SyncClient* g_client = nullptr;

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

SyncClient::~SyncClient()
{
	Disconnect();
	WSACleanup();
}

bool SyncClient::Connect(const std::string& ip, uint16_t port)
{
	// WSA
	int resultCode = WSAStartup(MAKEWORD(2, 2), &m_wsaData);
	if (resultCode != 0) {
		g_plugin->ShowInfoDialog("WSAStartup failed!");
		return false;
	}

	struct addrinfo *result = NULL,
		*ptr = NULL,
		hints;

	// Hints
	ZeroMemory( &hints, sizeof(hints) );
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve Address
	resultCode = getaddrinfo(ip.c_str(), std::to_string(port).c_str(), &hints, &result);
	if (resultCode != 0) {
		g_plugin->ShowInfoDialog("getaddrinfo failed for " + ip + ":" + std::to_string(port));
		return false;
	}

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
	{
		// Socket
		m_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (m_socket == INVALID_SOCKET) {
			g_plugin->ShowInfoDialog("socket failed!");
			
			freeaddrinfo(result);
			return false;
		}

		// Connect
		resultCode = connect(m_socket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (resultCode == SOCKET_ERROR) {
			closesocket(m_socket);
			m_socket = INVALID_SOCKET;

			continue;
		}

		break;
	}

	// Cleanup
	freeaddrinfo(result);

	// Check
	if (m_socket == INVALID_SOCKET)
	{
		g_plugin->ShowInfoDialog("Unable to connect to " + ip + ":" + std::to_string(port));
		return false;
	}
	
	// Connected
	return true;
}

void SyncClient::LaunchThread()
{
	m_thread = std::thread([=]() {
		this->_Worker();
	});

	m_thread.detach();
}

bool SyncClient::_send(BasePacket* pPacket, size_t stSize)
{
	if (pPacket == nullptr)
		return false;

	pPacket->packetSize = static_cast<uint16_t>(stSize);

#ifdef _DEBUG
	g_plugin->Log("DEBUG: Sending " + std::string(PacketTypeToString(pPacket->packetType)));
#endif

	auto resultCode = send(m_socket, (const char*) pPacket, stSize, 0);
	if (resultCode == SOCKET_ERROR)
	{
		g_plugin->ShowInfoDialog("send() failed!");
		return false;
	}

	return resultCode == stSize;
}

bool SyncClient::_expect(PacketType ePacketType, BasePacket* pPacket, size_t stSize)
{
	if (pPacket == nullptr)
		return false;

	// Packet Header
	auto resultCode = recv(m_socket, (char*)pPacket, sizeof(BasePacket), 0);
	if (resultCode == SOCKET_ERROR)
	{
		g_plugin->ShowInfoDialog("recv() failed!");
		return false;
	}

	// Check Packet Type
	if (pPacket->packetType != ePacketType)
	{
		g_plugin->ShowInfoDialog("Expected Packet " + std::string(PacketTypeToString(ePacketType)) + ", got " + PacketTypeToString(pPacket->packetType) + " instead!");
		return false;
	}

	// Read rest of Packet
	resultCode = recv(m_socket, ((char*)pPacket) + sizeof(BasePacket), pPacket->packetSize - sizeof(BasePacket), 0);
	if (resultCode == SOCKET_ERROR)
	{
		g_plugin->ShowInfoDialog("recv() failed!");
		return false;
	}

	// Done
	return true;
}

void SyncClient::Disconnect()
{
	if (m_socket == INVALID_SOCKET)
		return;

	// Join Thread
	if(m_thread.joinable())
		m_thread.join();

	// Destroy Socket
	closesocket(m_socket);
	m_socket = INVALID_SOCKET;
}

void SyncClient::_Worker()
{
	// Timeout
	DWORD timeout = 100;
	setsockopt(g_client->m_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

	// Buffer
	BasePacket packetHeader;

	while (true)
	{
		// Packet Header
		auto recvSize = recv(g_client->m_socket, (char*)&packetHeader, sizeof(packetHeader), 0);
		if (recvSize == SOCKET_ERROR)
		{
			// Timeout
			if (WSAGetLastError() == WSAETIMEDOUT)
				continue;

			// Failed
			g_plugin->ShowInfoDialog("recv() 1 failed!");
			return;
		}

		// Packet Contents
		auto packetBuffer = (char*) malloc(packetHeader.packetSize);
		memcpy(packetBuffer, &packetHeader, sizeof(BasePacket));

		size_t remainingSize = packetHeader.packetSize - sizeof(BasePacket);
		recvSize = recv(g_client->m_socket, ((char*)&packetHeader) + sizeof(BasePacket), remainingSize, 0);

		if (recvSize == SOCKET_ERROR)
		{
			delete packetBuffer;

			// Failed
			g_plugin->ShowInfoDialog("recv() 2 failed!");
			return;
		}

		if (recvSize < remainingSize)
		{
			delete packetBuffer;

			// Failed
			g_plugin->ShowInfoDialog("recv() failed: Packet was smaller than expected!");
			return;
		}

		// Queue
		auto packetType = PacketTypeToString(((BasePacket*)packetBuffer)->packetType);
		g_plugin->Log("Received Packet " + std::string(packetType));
	}
}

std::string SyncClient::GetHardwareId()
{
	HW_PROFILE_INFO hwProfileInfo;
	if (!GetCurrentHwProfile(&hwProfileInfo))
	{
		g_plugin->ShowErrorDialog("GetCurrentHwProfile failed!");
		return std::string();
	}

	return std::string(hwProfileInfo.szHwProfileGuid);
}