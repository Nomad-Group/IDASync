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
		g_plugin->ShowErrorDialog("WSAStartup failed!");
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
		g_plugin->ShowErrorDialog("getaddrinfo failed for " + ip + ":" + std::to_string(port));
		return false;
	}

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
	{
		// Socket
		m_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (m_socket == INVALID_SOCKET) {
			g_plugin->ShowErrorDialog("socket failed!");
			
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
		g_plugin->ShowErrorDialog("Unable to connect to " + ip + ":" + std::to_string(port));
		return false;
	}

	// Hardware ID
	auto hardwareId = GetHardwareId();
	g_plugin->Log("Connected to " + ip + " - sending Hardware ID...");

	HandshakePacket packet;
	packet.packetType = PacketType::Handshake;
	memcpy(&packet.guid, hardwareId.c_str(), sizeof(packet.guid));

	if (!Send(&packet))
	{
		g_plugin->ShowErrorDialog("Handshake failed!");
		return false;
	}

	// Connected
	return true;
}

bool SyncClient::_send(BasePacket* pPacket, size_t stSize)
{
	if (pPacket == nullptr)
		return false;

	pPacket->packetSize = stSize;

#ifdef _DEBUG
	g_plugin->Log("DEBUG: Sending " + std::string(PacketTypeToString(pPacket->packetType)));
#endif

	auto resultCode = send(m_socket, (const char*) pPacket, stSize, 0);
	if (resultCode == SOCKET_ERROR)
	{
		g_plugin->ShowErrorDialog("send() failed!");
		return false;
	}

	return resultCode == stSize;
}

void SyncClient::Disconnect()
{
	if (m_socket != INVALID_SOCKET)
		closesocket(m_socket);
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