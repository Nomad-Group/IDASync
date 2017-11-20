#pragma once
#include <stdint.h>

enum class PacketType : uint8_t
{
	Handshake = 0,
};

static const char* PacketTypeToString(PacketType packetType)
{
	switch (packetType)
	{
	case PacketType::Handshake:
		return "PacketType::Handshake";

	default:
		return "PacketType::_Unknown[Error]";
	}
}

struct BasePacket
{
	PacketType packetType;
	uint16_t packetSize;
};