#pragma once
#include <stdint.h>
#include <string>

class Socket
{
	int32_t m_socket = INT32_MAX;

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
	inline bool IsValid() { return m_socket != INT32_MAX; };
	inline int32_t GetHandle() { return m_socket; };
};