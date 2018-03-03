#include "sync/handler/DeleteStructSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "ida/IdbManager.h"

#include "struct.hpp"

bool DeleteStructSyncHandler::ApplyUpdateImpl(DeleteStructUpdateData* updateData)
{
	g_plugin->Log("deleted struct " + updateData->name);

	tid_t t = get_struc_id(updateData->name.c_str());
	return del_struc(get_struc(t));
}

bool DeleteStructSyncHandler::HandleNotification(IdaNotification& notification, DeleteStructUpdateData* updateData)
{
	tid_t t = va_arg(notification.args, tid_t);
	
	updateData->name = g_idb->GetStructName(t);
	return true;
}

void DeleteStructSyncHandler::DecodePacketImpl(DeleteStructUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	updateData->name = packet->ReadString();
}

void DeleteStructSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, DeleteStructUpdateData* updateData)
{
	packet->WriteString(updateData->name.c_str());
}