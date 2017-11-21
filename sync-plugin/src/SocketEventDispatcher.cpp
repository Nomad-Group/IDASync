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
	WSANETWORKEVENTS wsaNetworkEvents;

	while (IsSocketValid())
	{
		auto dwEvent = WSAWaitForMultipleEvents(1, &m_hEvent, false, WSA_INFINITE, false);
		WSAEnumNetworkEvents(m_socket, m_hEvent, &wsaNetworkEvents);

		// Error?
		/*if (wsaNetworkEvents.iErrorCode[0] != 0)
			DebugBreak();*/

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
}