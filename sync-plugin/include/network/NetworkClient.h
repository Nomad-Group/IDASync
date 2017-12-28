#pragma once
#include <string>
#include <thread>
#include <stdint.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "packets/BasePacket.h"
#include "Socket.h"
#include "SocketEvent.h"
#include "NetworkBuffer.h"

struct INetworkClientEventListener
{
	virtual ~INetworkClientEventListener() = default;

	virtual bool OnPacket(NetworkBufferT<BasePacket>*) = 0;
	virtual void OnConnectionClosed() = 0;
};

class SocketEventDispatcher;
class NetworkBuffer;

class NetworkClient : public ISocketEventListener
{
protected:
	// Socket
	Socket m_socket;
	bool ErrorCheck(Socket::StatusCode);

	// Event Handling
	SocketEventDispatcher* m_eventDispatcher = nullptr;
	INetworkClientEventListener* m_listener = nullptr;

	// Packets
	bool SendPacketInternal(BasePacket*, size_t);

	BasePacket* ReadPacketInternal();
	bool ReadPacketInternal(PacketType, NetworkBufferT<BasePacket>*);

public:
	NetworkClient() = default;
	~NetworkClient();

	// Connection
	inline bool Connect(const std::string& ip, uint16_t port = 4523) { return ErrorCheck(m_socket.Connect(ip, port)); };
	inline bool IsConnected() const { return m_socket.IsValid(); };
	bool Disconnect();

	// Socket Events
	bool StartListening(INetworkClientEventListener*);
	virtual bool OnSocketEvent(SocketEvent) override;

	// Send
	bool Send(NetworkBuffer*);

	template <class T>
	inline bool Send(NetworkBufferT<T>* pBuffer)
	{
		return Send((NetworkBuffer*)pBuffer);
	}

	// Receive
	bool Read(NetworkBuffer*);

	/*
	 * Packets
	 */
	/*template <class T>
	inline bool Send(T* pPacket, size_t stSize = sizeof(T))
	{
		return SendPacketInternal((BasePacket*) pPacket, stSize);
	}*/

	template <class T>
	inline bool ReadPacket(NetworkBufferT<T>* pPacket)
	{
		return ReadPacketInternal(PacketType::UnknownAny, (NetworkBufferT<BasePacket>*) pPacket);
	}

	template <class T>
	inline bool ReadPacket(PacketType packetType, NetworkBufferT<T>* pPacket)
	{
		return ReadPacketInternal(packetType, (NetworkBufferT<BasePacket>*) pPacket);
	}
};

extern NetworkClient* g_client;