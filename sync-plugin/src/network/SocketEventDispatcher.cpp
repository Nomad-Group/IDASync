#include <winsock2.h>
#include "network/Socket.h"
#include "network/SocketEventDispatcher.h"

SocketEventDispatcher::SocketEventDispatcher(int32_t socket) :
	m_socket(socket)
{}

SocketEventDispatcher::~SocketEventDispatcher()
{
	StopListening();
}

bool SocketEventDispatcher::StartListening(ISocketEventListener* socketEventListener)
{
	if (!IsSocketValid())
		return false;

	// Event
	m_hEvent = WSACreateEvent();
	if (m_hEvent == nullptr)
		return false;

	// Network Events
	if (WSAEventSelect(m_socket, m_hEvent, FD_READ | FD_WRITE | FD_CLOSE) != 0)
		return false;

	// Timeout
	DWORD dwTimeout = 100;
	setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&dwTimeout, sizeof(dwTimeout));

	// Create Thread
	m_thread = std::thread([=]() {
		this->_WorkerThread(socketEventListener);
	});
	m_thread.detach();

	// Done
	return true;
}

void SocketEventDispatcher::_WorkerThread(ISocketEventListener* socketEventListener)
{
	// Network Event
	WSANETWORKEVENTS wsaNetworkEvents;
	WSAResetEvent(&wsaNetworkEvents);

	// Event Loop
	while (IsSocketValid())
	{
		auto dwEvent = WSAWaitForMultipleEvents(1, &m_hEvent, false, WSA_INFINITE, false);
		if (WSAEnumNetworkEvents(m_socket, m_hEvent, &wsaNetworkEvents) != 0)
			continue; // Is this a good idea?

		// Socket Event
		SocketEvent socketEvent;
		if (wsaNetworkEvents.lNetworkEvents & FD_CLOSE)
			socketEvent = SocketEvent::Close;
		else if (wsaNetworkEvents.lNetworkEvents & FD_READ)
			socketEvent = SocketEvent::Read;
		else if (wsaNetworkEvents.lNetworkEvents & FD_WRITE)
			socketEvent = SocketEvent::Write;
		else
			continue;

		// Trigger
		socketEventListener->OnSocketEvent(socketEvent);
	}
}

void SocketEventDispatcher::StopListening()
{
	if (!IsSocketValid())
		return;

	// Socket
	if (m_socket != INVALID_SOCKET)
		WSAEventSelect(m_socket, nullptr, 0);
	
	m_socket = UINT32_MAX;

	// Join Thread
	if(m_thread.joinable())
		m_thread.join();
}