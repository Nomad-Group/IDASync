#include "SyncPlugin.h"
#include "sync/SyncManager.h"
#include "ida/IdbManager.h"
#include "Utility.h"
#include "UI/UIFunctions.h"

#include "network/packets/BroadcastMessagePacket.h"
#include "network/packets/UpdateOperationPackets.h"
#include "sync/IdbUpdateData.h"

#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>

bool SyncPlugin::HandleNetworkPacket(NetworkBufferT<BasePacket>* packet)
{
#ifdef _DEBUG
	g_plugin->Log("DEBUG: Incoming " + std::string(PacketTypeToString(packet->t->packetType)));
#endif

	switch (packet->t->packetType)
	{
	case PacketType::BroadcastMessage:
		return HandleBroadcastMessagePacket(packet);

	case PacketType::IdbUpdate:
		return HandleIdbUpdatePacket(packet);

	case PacketType::IdbUpdateResponse:
		return HandleIdbUpdateResponsePacket(packet);

	case PacketType::UpdateOperationStart:
	case PacketType::UpdateOperationProgress:
	case PacketType::UpdateOperationStop:
		return HandleUpdateOperationPacket(packet);

	default:
		return false;
	}
}

void SyncPlugin::HandleDisconnect()
{
	Log("Disconnected");

	// Status Bar
	UIStatusBarSetColor("red");
}

void SyncPlugin::HandleConnectionClosed()
{
	Log("Connection Closed!");

	// Status Bar
	UIStatusBarSetColor("red");
}

bool SyncPlugin::HandleBroadcastMessagePacket(NetworkBufferT<BasePacket>* packet)
{
	BroadcastMessageType messageType;
	packet->Read(&messageType);

	switch (messageType)
	{
	case BroadcastMessageType::ClientFirstJoin:
		Log(packet->ReadString() + " joined this project!");
		break;

	case BroadcastMessageType::ClientJoin:
		Log(packet->ReadString() + " connected.");
		break;

	case BroadcastMessageType::ClientDisconnect:
		Log(packet->ReadString() + " disconnected.");
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
		Log("ERROR: Failed to apply IdbUpdate! Version: " + std::to_string(updateData->version));

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

bool SyncPlugin::HandleUpdateOperationPacket(NetworkBufferT<BasePacket>* packet)
{
	switch (packet->t->packetType)
	{
	case PacketType::UpdateOperationStart:
	{
		auto pPacket = (NetworkBufferT<UpdateOperationStartPacket>*) packet;
		m_uiUpdateOperationTotalUpdates = pPacket->t->numTotalUpdates;

		UIShowUpdateOperationDialog();
		return true;
	}

	case PacketType::UpdateOperationProgress:
	{
		auto pPacket = (NetworkBufferT<UpdateOperationProgressPacket>*) packet;
		auto progress = ((float)(pPacket->t->numUpdatesSynced) / (float)m_uiUpdateOperationTotalUpdates) * 100.0f;
		auto text = std::to_string(pPacket->t->numUpdatesSynced) + " / " + std::to_string(m_uiUpdateOperationTotalUpdates);

		UIProgressUpdateOperationDialog(static_cast<int>(progress), text.c_str());
		return true;
	}

	case PacketType::UpdateOperationStop:
	{
		UIHideUpdateOperationDialog();
		return true;
	}

	default:
		return false;
	}
}