#include "sync/handler/ChangeStructMemberSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"

#include "struct.hpp"

bool ChangeStructMemberSyncHandler::ApplyUpdateImpl(ChangeStructMemberUpdateData* updateData)
{
	

	return false;
}

bool ChangeStructMemberSyncHandler::HandleNotification(IdaNotification& notification, ChangeStructMemberUpdateData* updateData)
{
	

	return true;
}

void ChangeStructMemberSyncHandler::DecodePacketImpl(ChangeStructMemberUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	updateData->structName = packet->ReadString();

	packet->Read(&updateData->offset);
}

void ChangeStructMemberSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, ChangeStructMemberUpdateData* updateData)
{
	packet->WriteString(updateData->structName.c_str());

	packet->Write(updateData->offset);
}