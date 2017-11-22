#pragma once
#include "BasePacket.h"

struct HandshakePacket : BasePacketEnumType<PacketType::Handshake>
{
	char guid[38];
	char binary_name[128];
	uint8_t binary_md5[16];
};

struct HandshakeResponsePacket : BasePacketEnumType<PacketType::HandshakeResponse>
{
	char username[32];
	char project_name[32];
};