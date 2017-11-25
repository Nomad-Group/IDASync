#pragma once
#include <stdint.h>

enum class PacketType : uint16_t
{
	Handshake = 0,
	HandshakeResponse,

	Heartbeat,
	BroadcastMessage,

	IdbUpdate,

	UnknownAny = UINT16_MAX
};
static_assert(sizeof(PacketType) == 2, "PacketType size mismatch!");

static const char* PacketTypeToString(PacketType packetType)
{
	switch (packetType)
	{
	case PacketType::Handshake:
		return "PacketType::Handshake";

	case PacketType::HandshakeResponse:
		return "PacketType::HandshakeResponse";

	case PacketType::Heartbeat:
		return "PacketType::Heartbeat";

	case PacketType::BroadcastMessage:
		return "PacketType::BroadcastMessage";

	case PacketType::IdbUpdate:
		return "PacketType::IdbUpdate";

	default:
		return "PacketType::_Unknown[Error]";
	}
}

struct BasePacket
{
	uint16_t packetSize;
	PacketType packetType;
};
static_assert(sizeof(BasePacket) == 4, "BasePacket size mismatch!");

template <PacketType TPacketType>
struct BasePacketEnumType : BasePacket
{
	static constexpr const PacketType Enum = TPacketType;
};
static_assert(sizeof(BasePacketEnumType<PacketType::Heartbeat>) == sizeof(BasePacket), "BasePacketEnumType size mismatch!");

// Forward Defines
struct HandshakePacket;
struct HeartbeatPacket;
struct BroadcastMessagePacket;