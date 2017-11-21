#pragma once
#include <Windows.h>
#include <stdint.h>

#include "SocketEvent.h"

class Socket;
class SocketEventDispatcher
{
	int32_t m_socket;
	inline bool IsSocketValid() { return m_socket != UINT32_MAX && m_socket != INVALID_SOCKET; }

	HWND m_hwnd = nullptr;

	WNDPROC m_wndproc = nullptr;
	static BOOL CALLBACK WndProc_Hook(HWND hWnd, UINT uiMessage, WPARAM wParam, LPARAM lParam);

public:
	SocketEventDispatcher(int32_t);
	~SocketEventDispatcher();

	bool StartListening(ISocketEventListener*);
	void StopListening();
};