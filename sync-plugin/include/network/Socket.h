#pragma once
#include <stdint.h>
#include <string>

#include <mutex>

/**/
// WinSock2
// typedef UINT_PTR        SOCKET;
// #define INVALID_SOCKET  (SOCKET)(~0)
// #define SOCKET_ERROR            (-1)
using socket_t = uintptr_t;
const socket_t SOCKET_T_INVALID = (socket_t)(~0);
const socket_t SOCKET_T_ERROR = -1;
/**/

class Socket
{
	socket_t m_socket = SOCKET_T_INVALID;
	std::mutex m_sendMutex;
	std::mutex m_recvMutex;

public:
	enum class StatusCode : uint8_t
	{
		Success = 0,
		InvalidSocket,

		ResolveAddressFailed,
		CreateSocketFailed,
		ConnectFailed,

		SendFailed,
		RecvFailed
	};
	static const char* StatusCodeToString(StatusCode);

public:
	Socket() = default;
	~Socket();

	// Connect
	StatusCode Connect(const std::string& ip, uint16_t port);

	// Socket
	StatusCode Send(const char*, size_t, size_t* stBytesSent = nullptr);
	StatusCode Receive(char*, size_t, size_t* stBytesReceived = nullptr);

	bool Close();

	// Validity-Check
	inline bool IsValid() const { return m_socket != SOCKET_T_INVALID; };
	inline socket_t GetHandle() const { return m_socket; };
};