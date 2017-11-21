#include "network/NetworkClient.h"
#include "network/SocketEventDispatcher.h"
#include "SyncPlugin.h"

NetworkClient* g_client = nullptr;

NetworkClient::~NetworkClient()
{
	Disconnect();
	WSACleanup();
}

bool NetworkClient::StartListening(INetworkClientEventListener* eventListener)
{
	if (m_eventDispatcher)
		delete m_eventDispatcher;
	
	m_eventDispatcher = new SocketEventDispatcher(m_socket.GetHandle());
	m_listener = eventListener;

	return m_eventDispatcher->StartListening(this);
}

bool NetworkClient::SendPacketInternal(BasePacket* pPacket, size_t stSize)
{
	if (pPacket == nullptr)
		return false;

#ifdef _DEBUG
	g_plugin->Log("DEBUG: Sending " + std::string(PacketTypeToString(pPacket->packetType)));
#endif

	// Adjust Packet
	pPacket->packetSize = static_cast<uint16_t>(stSize);

	// Send
	size_t stBytesSent = 0;
	return
		ErrorCheck(m_socket.Send((const char*)pPacket, stSize, &stBytesSent)) &&
		stBytesSent == stSize;
}

BasePacket* NetworkClient::ReadPacketInternal()
{
	// Packet Header
	BasePacket packetHeader;
	if (!ErrorCheck(m_socket.Receive((char*)&packetHeader, sizeof(BasePacket))) || packetHeader.packetSize < sizeof(BasePacket))
		return nullptr;

	// Allocate Packet Buffer
	auto pPacket = (BasePacket*) malloc(packetHeader.packetSize);
	memcpy((void*)pPacket, (const void*) &packetHeader, sizeof(BasePacket));

	// Read rest of Packet
	size_t remainingSize = pPacket->packetSize - sizeof(BasePacket);

	if (remainingSize > 0)
	{
		if (!ErrorCheck(m_socket.Receive(
			((char*)pPacket) + sizeof(BasePacket),
			pPacket->packetSize - sizeof(BasePacket)
		)))
		{
			delete pPacket;
			return nullptr;
		}
	}

	// Success
	return (BasePacket*) pPacket;
}

bool NetworkClient::ReadPacketInternal(PacketType ePacketType, BasePacket* pPacket, size_t stSize)
{
	if (pPacket == nullptr)
		return false;

	// Packet Header
	if (!ErrorCheck(m_socket.Receive((char*)pPacket, sizeof(BasePacket))))
		return false;

	// Check Packet Type
	if (pPacket->packetType != ePacketType)
	{
		g_plugin->ShowInfoDialog(
			"Expected Packet " + std::string(PacketTypeToString(ePacketType)) +
			", got " + PacketTypeToString(pPacket->packetType) + " instead!"
		);
		
		return false;
	}

	// Read rest of Packet
	size_t remainingSize = pPacket->packetSize - sizeof(BasePacket);
	if (remainingSize == 0)
		return true;

	return ErrorCheck(m_socket.Receive(
		((char*)pPacket) + sizeof(BasePacket),
		pPacket->packetSize - sizeof(BasePacket)
	));
}

bool NetworkClient::OnSocketEvent(SocketEvent socketEvent)
{
	if (socketEvent == SocketEvent::Read)
	{
		auto pPacket = ReadPacketInternal();
		if (pPacket)
			m_listener->OnPacket(pPacket);
	}

	return false;
}

bool NetworkClient::ErrorCheck(Socket::StatusCode statusCode)
{
	if (statusCode == Socket::StatusCode::Success)
		return true;

	g_plugin->ShowInfoDialog("Socket Error! Code: " + std::to_string((int)statusCode));
	return false;
}