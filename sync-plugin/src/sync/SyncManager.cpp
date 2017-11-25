#include "sync/SyncManager.h"
#include "sync/IdbUpdate.h"

#include "sync/NameSyncHandler.h"

SyncManager* g_syncManager = nullptr;

SyncManager::~SyncManager()
{
	for (int i = 0; i < NumSyncHandlers; i++)
		delete m_syncHandler[i];
}

bool SyncManager::Initialize()
{
	// Handler
	m_syncHandler[(size_t) SyncType::Name] = new NameSyncHandler();

	// Done
	return true;
}

ISyncHandler* SyncManager::GetSyncHandler(SyncType syncType)
{
	if (syncType >= SyncType::_Count)
		return nullptr;

	return m_syncHandler[(size_t) syncType];
}

IdbUpdate* SyncManager::DecodePacket(NetworkBufferT<BasePacket>* packet)
{
	IdbUpdate updateDataHeader;

	// Generic Data
	if (packet == nullptr ||
		!packet->Read(&updateDataHeader.version) ||
		!packet->Read(&updateDataHeader.syncType))
		return nullptr;

	// Sync Handler
	auto syncHandler = GetSyncHandler(updateDataHeader.syncType);
	if (syncHandler == nullptr)
		return nullptr;
	
	// Decode
	auto updateData = syncHandler->DecodePacket(packet);
	if (updateData)
	{
		updateData->version = updateDataHeader.version;
		updateData->syncType = updateDataHeader.syncType;
	}

	// Done
	return updateData;
}

NetworkBufferT<BasePacket>* SyncManager::EncodePacket(IdbUpdate* updateData)
{
	if (updateData == nullptr)
		return nullptr;

	// Packet
	auto packet = new NetworkBufferT<BasePacket>();
	packet->t->packetType = PacketType::IdbUpdate;

	packet->Write(updateData->version);
	packet->Write(updateData->syncType);

	// Sync Handler
	auto syncHandler = GetSyncHandler(updateData->syncType);
	if (syncHandler == nullptr)
		return nullptr;

	// Encode
	if (!syncHandler->EncodePacket(packet, updateData))
	{
		delete packet;
		return nullptr;
	}

	// Done
	return packet;
}

bool SyncManager::ApplyUpdate(IdbUpdate* updateData)
{
	// Sync Handler
	auto syncHandler = GetSyncHandler(updateData->syncType);
	if (syncHandler == nullptr)
		return false;

	// Apply
	return syncHandler->ApplyUpdate(updateData);
}