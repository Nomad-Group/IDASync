#pragma once
#include <stdint.h>

enum class PacketType : uint16_t
{
	Handshake = 0,
	HandshakeResponse,

	Heartbeat,
	BroadcastMessage,

	IdbUpdate,
	IdbUpdateResponse,

	// Update Operation
	UpdateOperationStart = 1000,
	UpdateOperationProgress,
	UpdateOperationStop,
	UpdateOperationUpdateBurst,

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

	case PacketType::IdbUpdateResponse:
		return "PacketType::IdbUpdateResponse";

	case PacketType::UpdateOperationStart:
		return "PacketType::UpdateOperationStart";

	case PacketType::UpdateOperationProgress:
		return "PacketType::UpdateOperationProgress";

	case PacketType::UpdateOperationStop:
		return "PacketType::UpdateOperationStop";

	case PacketType::UpdateOperationUpdateBurst:
		return "PacketType::UpdateOperationUpdateBurst";

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