#pragma once
#include <Windows.h>
#include <stdint.h>
#include <thread>

#include "Socket.h"
#include "SocketEvent.h"

class Socket;
class SocketEventDispatcher
{
	socket_t m_socket;
	inline bool IsSocketValid() { return m_socket != SOCKET_T_INVALID && m_socket != SOCKET_T_ERROR; }

	std::thread m_thread;
	HANDLE m_hEvent = nullptr;
	void _WorkerThread(ISocketEventListener* socketEventListener);

public:
	SocketEventDispatcher(socket_t);
	~SocketEventDispatcher();

	bool StartListening(ISocketEventListener*);
	void StopListening();
};