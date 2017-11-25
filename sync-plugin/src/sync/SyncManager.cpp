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

IdbUpdate* SyncManager::DecodePacket(NetworkBufferT<BasePacket>* packet)
{
	IdbUpdate updateDataHeader;

	// Generic Data
	if (packet == nullptr ||
		!packet->Read(&updateDataHeader.version) ||
		!packet->Read(&updateDataHeader.syncType))
		return nullptr;

	// Sync Handler
	if (updateDataHeader.syncType >= SyncType::_Count)
		return nullptr;

	auto syncHandler = m_syncHandler[(size_t)updateDataHeader.syncType];
	
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
	if (updateData->syncType >= SyncType::_Count)
		return nullptr;

	auto syncHandler = m_syncHandler[(size_t)updateData->syncType];
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
	if (updateData == nullptr || updateData->syncType >= SyncType::_Count)
		return false;

	auto syncHandler = m_syncHandler[(size_t)updateData->syncType];
	return syncHandler->ApplyUpdate(updateData);
}