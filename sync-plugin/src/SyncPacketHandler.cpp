#include "SyncPlugin.h"
#include "sync/SyncManager.h"
#include "ida/IdbManager.h"
#include "Utility.h"

#include "network/packets/HeartbeatPacket.h"
#include "network/packets/BroadcastMessagePacket.h"
#include "sync/IdbUpdate.h"

#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>

bool SyncPlugin::HandleNetworkPacket(NetworkBufferT<BasePacket>* packet)
{
	g_plugin->Log("DEBUG: Incoming " + std::string(PacketTypeToString(packet->t->packetType)));

	switch (packet->t->packetType)
	{
	case PacketType::Heartbeat:
		return HandleHeartbeat();

	case PacketType::BroadcastMessage:
		return HandleBroadcastMessagePacket(packet);

	case PacketType::IdbUpdate:
		return HandleIdbUpdatePacket(packet);

	case PacketType::IdbUpdateResponse:
		return HandleIdbUpdateResponsePacket(packet);

	default:
		return false;
	}
}

void SyncPlugin::HandleDisconnect()
{
	g_client->Disconnect();

	// Log
	Log("Connection lost!");
}

bool SyncPlugin::HandleHeartbeat()
{
	auto packet = new NetworkBufferT<HeartbeatPacket>();
	packet->t->packetType = PacketType::Heartbeat;

	g_client->Send(packet);
	delete packet;

	return true;
}

bool SyncPlugin::HandleBroadcastMessagePacket(NetworkBufferT<BasePacket>* packet)
{
	BroadcastMessageType messageType;
	packet->Read(&messageType);

	switch (messageType)
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

bool SyncPlugin::HandleIdbUpdatePacket(NetworkBufferT<BasePacket>* packet)
{
	// Decode
	auto updateData = g_syncManager->DecodePacket(packet);
	if (updateData == nullptr)
	{
		Log("ERROR: Failed to decode IdbUpdate Package!");
		return false;
	}
	
	// Apply
	if (!g_syncManager->ApplyUpdate(updateData))
	{
		Log("ERROR: Failed to apply IdbUpdate! Version: " + updateData->version);

		delete updateData;
		return false;
	}

	// Done
	delete updateData;
	return true;
}

bool SyncPlugin::HandleIdbUpdateResponsePacket(NetworkBufferT<BasePacket>* packet)
{
	uint32_t version;
	if (!packet->Read(&version))
		return false;

	g_idb->SetVersion(version);
	return true;
}