#include "SyncPlugin.h"
#include "Utility.h"

#include "network/packets/BroadcastMessagePacket.h"

#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>

bool SyncPlugin::HandleNetworkPacket(NetworkBufferT<BasePacket>* packet)
{
	g_plugin->Log("DEBUG: Incoming " + std::string(PacketTypeToString(packet->t->packetType)));

	switch (packet->t->packetType)
	{
	case PacketType::BroadcastMessage:
		return HandleBroadcastMessagePacket((NetworkBufferT<BroadcastMessagePacket>*)packet);

	default:
		return false;
	}
}

void SyncPlugin::HandleDisconnect()
{
	g_client->Disconnect();
	Log("Connection lost!");
}

bool SyncPlugin::HandleBroadcastMessagePacket(NetworkBufferT<BroadcastMessagePacket>* packet)
{
	switch (packet->t->messageType)
	{
	case BroadcastMessageType::ClientFirstJoin:
		Log(std::string(packet->ReadString()) + " joined this project!");
		break;

	case BroadcastMessageType::ClientJoin:
		Log(std::string(packet->ReadString()) + " connected.");
		break;

	case BroadcastMessageType::ClientDisconnect:
		Log(std::string(packet->ReadString()) + " disconnected.");
		break;

	default:
		return false;
	}

	return true;
}

/*
bool SyncPlugin::HandleIdbNameAddressPacket(IdbNameAddressPacket* packet)
{
	if (!set_name(static_cast<ea_t>(packet->ptr), packet->name, (packet->local ? SN_LOCAL : 0) | SN_NOWARN))
		return false;

	Log("Naming Request at 0x" + number2hex(packet->ptr) + " to " + std::string(packet->name));
	return true;
}*/