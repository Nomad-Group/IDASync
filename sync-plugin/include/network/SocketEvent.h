#pragma once
#include <stdint.h>

enum class SocketEvent : uint8_t
{
	Error,
	Read,
	Write,
	Close
};

struct ISocketEventListener
{
	virtual ~ISocketEventListener() = default;

	virtual bool OnSocketEvent(SocketEvent) = 0;
};