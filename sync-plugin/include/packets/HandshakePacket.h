#pragma once
#include "BasePacket.h"

struct HandshakePacket : BasePacketEnumType<PacketType::Handshake>
{
	char guid[38];
};

struct HandshakeResponsePacket : BasePacketEnumType<PacketType::HandshakeResponse>
{
	char username[32];
};