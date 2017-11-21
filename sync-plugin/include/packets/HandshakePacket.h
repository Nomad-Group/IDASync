#pragma once
#include "BasePacket.h"

struct HandshakePacket : BasePacketEnumType<PacketType::Handshake>
{
	char guid[38];
	uint8_t binarymd5[16];
};

struct HandshakeResponsePacket : BasePacketEnumType<PacketType::HandshakeResponse>
{
	char username[32];
	char project_name[32];
};