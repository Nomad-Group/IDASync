#include "SyncPlugin.h"
#include "Utility.h"

#include "network/packets/BroadcastMessagePacket.h"

#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>

bool SyncPlugin::HandleNetworkPacket(BasePacket* packet)
{
	g_plugin->Log("DEBUG: Incoming " + std::string(PacketTypeToString(packet->packetType)));

	switch (packet->packetType)
	{
	case PacketType::BroadcastMessage:
		return HandleBroadcastMessagePacket((BroadcastMessagePacket*)packet);

	default:
		return false;
	}
}

void SyncPlugin::HandleDisconnect()
{
	g_client->Disconnect();
	Log("Connection lost!");
}

bool SyncPlugin::HandleBroadcastMessagePacket(BroadcastMessagePacket* packet)
{
	switch (packet->messageType)
	{
	case BroadcastMessageType::ClientFirstJoin:
		Log(std::string(packet->data) + " joined this project!");
		break;

	case BroadcastMessageType::ClientJoin:
		Log(std::string(packet->data) + " connected.");
		break;

	case BroadcastMessageType::ClientDisconnect:
		Log(std::string(packet->data) + " disconnected.");
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