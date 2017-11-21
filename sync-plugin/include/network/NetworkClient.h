#pragma once
#include <string>
#include <thread>
#include <stdint.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "packets/BasePacket.h"
#include "Socket.h"
#include "SocketEvent.h"

class SocketEventDispatcher;
class NetworkClient : public ISocketEventListener
{
protected:
	// Socket
	Socket m_socket;
	bool ErrorCheck(Socket::StatusCode);

	// Event Handling
	SocketEventDispatcher* m_eventDispatcher = nullptr;

	// Packets
	bool SendPacketInternal(BasePacket*, size_t);
	bool ExpectPacketInternal(PacketType, BasePacket*, size_t);

public:
	NetworkClient() = default;
	~NetworkClient();

	// Connection
	inline bool Connect(const std::string& ip, uint16_t port = 4523) { return ErrorCheck(m_socket.Connect(ip, port)); };
	inline bool Disconnect() { return m_socket.Close(); };

	// Socket Events
	bool StartListening();
	virtual bool OnSocketEvent(SocketEvent) override;

	/*
	 * Packets
	 */
	template <class T>
	inline bool Send(T* pPacket, size_t stSize = sizeof(T))
	{
		return SendPacketInternal((BasePacket*)pPacket, stSize);
	}
	template <class T>
	inline bool ExpectPacket(T* pPacket, size_t stSize = sizeof(T))
	{
		return ExpectPacketInternal(T::Enum, (BasePacket*)pPacket, stSize);
	}
};

extern NetworkClient* g_client;