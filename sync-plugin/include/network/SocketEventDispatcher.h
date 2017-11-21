#pragma once
#include <Windows.h>
#include <stdint.h>
#include <thread>

#include "SocketEvent.h"

class Socket;
class SocketEventDispatcher
{
	int32_t m_socket;
	inline bool IsSocketValid() { return m_socket != UINT32_MAX && m_socket != INVALID_SOCKET; }

	std::thread m_thread;
	HANDLE m_hEvent = nullptr;
	void _WorkerThread(ISocketEventListener* socketEventListener);

public:
	SocketEventDispatcher(int32_t);
	~SocketEventDispatcher();

	bool StartListening(ISocketEventListener*);
	void StopListening();
};