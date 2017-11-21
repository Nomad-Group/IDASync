#pragma once
#include <stdint.h>

enum class PacketType : uint8_t
{
	Handshake = 0,
	HandshakeResponse,


};

static const char* PacketTypeToString(PacketType packetType)
{
	switch (packetType)
	{
	case PacketType::Handshake:
		return "PacketType::Handshake";

	case PacketType::HandshakeResponse:
		return "PacketType::HandshakeResponse";

	default:
		return "PacketType::_Unknown[Error]";
	}
}

struct BasePacket
{
	PacketType packetType;
	uint16_t packetSize;
};

template <PacketType TPacketType>
struct BasePacketEnumType : BasePacket
{
	static constexpr const PacketType Enum = TPacketType;
};