#include "network/Socket.h"

#undef SOCKET
#undef INVALID_SOCKET
#undef SOCKET_ERROR

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
		if (m_socket == SOCKET_T_INVALID) {
			freeaddrinfo(result);
			return StatusCode::CreateSocketFailed;
		}

		// Connect
		resultCode = connect(m_socket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (resultCode == SOCKET_T_ERROR) {
			Close();
			continue;
		}

		break;
	}

	// Cleanup
	freeaddrinfo(result);

	// Check
	if (m_socket == SOCKET_T_INVALID)
		return StatusCode::ConnectFailed;

	// Socket Timeout
	DWORD dwTimeout = 200;
	setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&dwTimeout, sizeof(dwTimeout));

	// Done
	return StatusCode::Success;
}

Socket::StatusCode Socket::Send(const char* buffer, size_t stSize, size_t* stBytesSent)
{
	if (!IsValid())
		return StatusCode::InvalidSocket;

	if (stBytesSent)
		*stBytesSent = 0;

	std::lock_guard<std::mutex> lock(m_sendMutex);

	auto resultCode = send(m_socket, buffer, stSize, 0);
	if (resultCode == SOCKET_T_ERROR)
		return StatusCode::SendFailed;

	if (stBytesSent)
		*stBytesSent = resultCode;

	return StatusCode::Success;
}

Socket::StatusCode Socket::Receive(char* buffer, size_t stSize, size_t* stBytesRead)
{
	if (!IsValid())
		return StatusCode::InvalidSocket;

	if (stBytesRead)
		*stBytesRead = 0;

	std::lock_guard<std::mutex> lock(m_recvMutex);
	auto resultCode = recv(m_socket, buffer, stSize, 0);
	if (resultCode == SOCKET_T_ERROR)
		return StatusCode::RecvFailed;

	if(stBytesRead)
		*stBytesRead = resultCode;

	return StatusCode::Success;
}

bool Socket::Close()
{
	auto s = m_socket;
	m_socket = SOCKET_T_INVALID;

	if (s != SOCKET_T_INVALID)
		return closesocket(s) == 0;
	
	return true;
}

const char* Socket::StatusCodeToString(StatusCode statusCode)
{
	switch (statusCode)
	{
	case StatusCode::Success:
		return "Success";

	case StatusCode::InvalidSocket:
		return "Invalid Socket";

	case StatusCode::ResolveAddressFailed:
		return "Failed to resolve Address";

	case StatusCode::CreateSocketFailed:
		return "Socket Creation failed";

	case StatusCode::ConnectFailed:
		return "Connection failed";

	case StatusCode::SendFailed:
		return "send() failed";

	case StatusCode::RecvFailed:
		return "recv() failed";

	default:
		return "Unknown Error";
	}
}