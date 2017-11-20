#pragma once
#include <string>
#include <stdint.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "packets/BasePacket.h"

class SyncClient
{
	WSAData m_wsaData;
	SOCKET m_socket = INVALID_SOCKET;

	bool _send(BasePacket*, size_t);

	std::string GetHardwareId();

public:
	SyncClient() = default;
	~SyncClient();

	bool Connect(const std::string& ip, uint16_t port = 4523);
	void Disconnect();

	template <class T>
	inline bool Send(T* pPacket, size_t stSize = sizeof(T))
	{
		return _send((BasePacket*)pPacket, stSize);
	}
};

extern SyncClient* g_client;