#include "network/Socket.h"

#include <WinSock2.h>
#include <ws2tcpip.h>

Socket::~Socket()
{
	Close();
}

Socket::StatusCode Socket::Connect(const std::string& ip, uint16_t port)
{
	// Valid?
	if (IsValid())
		Close();

	// Connection Hints
	struct addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve Address
	struct addrinfo* result = nullptr;

	auto resultCode = getaddrinfo(ip.c_str(), std::to_string(port).c_str(), &hints, &result);
	if (resultCode != 0)
		return StatusCode::ResolveAddressFailed;

	for (struct addrinfo* ptr = result; ptr != NULL; ptr = ptr->ai_next)
	{
		// Socket
		m_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (m_socket == INVALID_SOCKET) {
			freeaddrinfo(result);

			m_socket = UINT32_MAX;
			return StatusCode::CreateSocketFailed;
		}

		// Connect
		resultCode = connect(m_socket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (resultCode == SOCKET_ERROR) {
			closesocket(m_socket);
			m_socket = UINT32_MAX;

			continue;
		}

		break;
	}

	// Cleanup
	freeaddrinfo(result);

	// Check
	if (m_socket == INVALID_SOCKET)
	{
		m_socket = UINT32_MAX;
		return StatusCode::ConnectFailed;
	}

	return StatusCode::Success;
}

Socket::StatusCode Socket::Send(const char* buffer, size_t stSize, size_t* stBytesSent)
{
	if (!IsValid())
		return StatusCode::InvalidSocket;

	if (stBytesSent)
		*stBytesSent = 0;

	auto resultCode = send(m_socket, buffer, stSize, 0);
	if (resultCode == SOCKET_ERROR)
		return StatusCode::SendFailed;

	if(stBytesSent)
		*stBytesSent = resultCode;
	return StatusCode::Success;
}

Socket::StatusCode Socket::Receive(char* buffer, size_t stSize, size_t* stBytesRead)
{
	if (!IsValid())
		return StatusCode::InvalidSocket;

	if (stBytesRead)
		*stBytesRead = 0;

	auto resultCode = recv(m_socket, buffer, stSize, 0);
	if (resultCode == SOCKET_ERROR)
		return StatusCode::RecvFailed;

	if(stBytesRead)
		*stBytesRead = resultCode;
	return StatusCode::Success;
}

bool Socket::Close()
{
	return
		IsValid() &&
		closesocket(m_socket) == 0;
}