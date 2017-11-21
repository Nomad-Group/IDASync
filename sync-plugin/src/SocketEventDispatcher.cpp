#define _WINSOCK_DEPRECATED_NO_WARNINGS // yea.. i know...
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

	// Create Window
	m_hwnd = CreateWindowEx(0, "STATIC", "SyncPlugin SocketEventDispatcher", 0, 0, 0, 0, 0, HWND_MESSAGE, 0, 0, socketEventListener);
	if (m_hwnd == nullptr)
		return false;

	// Hook WndProc
	m_wndproc = (WNDPROC)SetWindowLongPtr(m_hwnd, GWL_WNDPROC, (LONG_PTR)WndProc_Hook);
	if (m_wndproc == 0)
	{
		StopListening();
		return false;
	}

	// Socket => Window
	// TODO: THIS SHIT IS DEPRECATED
	if (WSAAsyncSelect(m_socket, m_hwnd, WM_USER, FD_READ | FD_WRITE | FD_CLOSE) == SOCKET_ERROR)
	{
		StopListening();
		return false;
	}

	// Done
	return true;
}

BOOL CALLBACK SocketEventDispatcher::WndProc_Hook(HWND hWnd, UINT uiMessage, WPARAM wParam, LPARAM lParam)
{
	auto pClient = (ISocketEventListener*) GetWindowLongPtr(hWnd, GWLP_USERDATA);
	if (uiMessage == WM_USER || pClient != nullptr)
		return false;
	
	// Error?
	if (WSAGETSELECTERROR(lParam))
		return pClient->OnSocketEvent(SocketEvent::Error);

	// Socket Event
	SocketEvent socketEvent;
	switch (WSAGETSELECTEVENT(lParam))
	{
	case FD_READ:
		socketEvent = SocketEvent::Read;
		break;

	case FD_WRITE:
		socketEvent = SocketEvent::Write;
		break;

	case FD_CLOSE:
		socketEvent = SocketEvent::Close;
		break;

	default:
		return true;
	}

	// Handle
	return pClient->OnSocketEvent(socketEvent);
}

void SocketEventDispatcher::StopListening()
{
	if (!IsSocketValid())
		return;

	// Socket
	if(m_socket != INVALID_SOCKET)
		WSAAsyncSelect(m_socket, m_hwnd, 0, 0);

	// Window
	if (m_hwnd != nullptr)
	{
		DestroyWindow(m_hwnd);
		m_hwnd = nullptr;
	}
}