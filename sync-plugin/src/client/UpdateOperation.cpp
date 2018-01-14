#include "client/UpdateOperation.h"
#include "SyncPlugin.h"
#include "ida/IdbManager.h"
#include "UI/UIFunctions.h"

void UpdateOperation::Reset()
{
	m_bIsActive = false;
	m_uiTotalUpdates = 0;
}

bool UpdateOperation::HandlePacket(NetworkBufferT<BasePacket>* packet)
{
	switch (packet->t->packetType)
	{
	case PacketType::UpdateOperationStart:
		return OnStart((NetworkBufferT<UpdateOperationStartPacket>*) packet);

	case PacketType::UpdateOperationProgress:
		return OnProgress((NetworkBufferT<UpdateOperationProgressPacket>*) packet);

	case PacketType::UpdateOperationUpdateBurst:
		return OnUpdateBurst(packet);

	case PacketType::UpdateOperationStop:
		return OnEnd((NetworkBufferT<UpdateOperationStopPacket>*) packet);

	default:
		return false;
	}
}

bool UpdateOperation::OnStart(NetworkBufferT<UpdateOperationStartPacket>* packet)
{
	m_uiTotalUpdates = packet->t->numTotalUpdates;
	m_bIsActive = true;

	UIShowUpdateOperationDialog();
	return true;
}

bool UpdateOperation::OnProgress(NetworkBufferT<UpdateOperationProgressPacket>* packet)
{
	auto progress = ((float)(packet->t->numUpdatesSynced) / (float)m_uiTotalUpdates) * 100.0f;
	auto text = std::to_string(packet->t->numUpdatesSynced) + " / " + std::to_string(m_uiTotalUpdates);

	UIProgressUpdateOperationDialog(static_cast<int>(progress), text.c_str());
	return true;
}

bool UpdateOperation::OnUpdateBurst(NetworkBufferT<BasePacket>* packet)
{
	uint8_t uiNumUpdates = 0;
	packet->Read(&uiNumUpdates);

	while (uiNumUpdates > 0)
	{
		// Packet Header
		uint16_t uiPacketSize = 0;
		packet->Read(&uiPacketSize);

		PacketType uiPacketType = PacketType::UnknownAny;
		packet->Read(&uiPacketType);

		// Check Type
		if (uiPacketSize == 0 ||
			uiPacketType != PacketType::IdbUpdate)
			return false;

		// Handle Update
		// NOTE: Return type is not considered here, updates may fail and this
		// is fine.
		g_plugin->HandleIdbUpdatePacket(packet);
		uiNumUpdates--;
	}

	return true;
}

bool UpdateOperation::OnEnd(NetworkBufferT<UpdateOperationStopPacket>* packet)
{
	// UI
	UIHideUpdateOperationDialog();

	// Target Version
	g_idb->SetVersion(packet->t->version);
	g_plugin->Log("Update Operation finished! Synced " + std::to_string(m_uiTotalUpdates) + " updates!");
	g_plugin->Log("Local Version: " + std::to_string(packet->t->version));

	// Reset
	Reset();
	return true;
}