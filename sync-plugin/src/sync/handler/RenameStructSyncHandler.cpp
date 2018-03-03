#include "sync/handler/RenameStructSyncHandler.h"
#include "sync/SyncManager.h"
#include "ida/IdbManager.h"
#include "SyncPlugin.h"

#include "struct.hpp"

bool RenameStructSyncHandler::ApplyUpdateImpl(RenameStructUpdateData* updateData)
{
	g_plugin->Log("struct " + updateData->oldName + " renamed to " + updateData->newName);

	tid_t t = get_struc_id(updateData->oldName.c_str());
	if (!set_struc_name(t, updateData->newName.c_str()))
		return false;

	g_idb->StoreStructName(t, updateData->newName);
	return true;
}

bool RenameStructSyncHandler::HandleNotification(IdaNotification& notification, RenameStructUpdateData* updateData)
{
	struc_t* pStruct = va_arg(notification.args, struc_t*);

	updateData->oldName = g_idb->GetStructName(pStruct->id);
	updateData->newName = get_struc_name(pStruct->id).c_str();

	g_idb->StoreStructName(pStruct->id, updateData->newName);
	return true;
}

void RenameStructSyncHandler::DecodePacketImpl(RenameStructUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	updateData->oldName = packet->ReadString();
	updateData->newName = packet->ReadString();
}

void RenameStructSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, RenameStructUpdateData* updateData)
{
	packet->WriteString(updateData->oldName.c_str());
	packet->WriteString(updateData->newName.c_str());
}