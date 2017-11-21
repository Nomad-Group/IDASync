#pragma once
#include <string>
#include <thread>
#include <stdint.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "packets/BasePacket.h"

class SyncClient
{
	WSAData m_wsaData;
	SOCKET m_socket = INVALID_SOCKET;

	bool _send(BasePacket*, size_t);
	bool _expect(PacketType, BasePacket*, size_t);

	std::thread m_thread;
	static void _Worker();

public:
	SyncClient() = default;
	~SyncClient();

	bool Connect(const std::string& ip, uint16_t port = 4523);
	void LaunchThread();
	void Disconnect();

	template <class T>
	inline bool Send(T* pPacket, size_t stSize = sizeof(T))
	{
		return _send((BasePacket*)pPacket, stSize);
	}

	template <class T>
	inline bool ExpectPacket(T* pPacket, size_t stSize = sizeof(T))
	{
		return _expect(T::Enum, (BasePacket*)pPacket, stSize);
	}

	// Utility
	static std::string GetHardwareId();
};

extern SyncClient* g_client;