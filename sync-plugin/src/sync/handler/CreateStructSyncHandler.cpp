#include "sync/handler/CreateStructSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "ida/IdbManager.h"

#include "struct.hpp"

bool CreateStructSyncHandler::ApplyUpdateImpl(CreateStructUpdateData* updateData)
{
	g_plugin->Log("created struct " + updateData->name);

	tid_t t = add_struc(BADADDR, updateData->name.c_str(), updateData->isUnion);
	g_idb->StoreStructName(t, updateData->name);
	g_plugin->Log("debug: " + g_idb->GetStructName(t));


	return true;
}

bool CreateStructSyncHandler::HandleNotification(IdaNotification& notification, CreateStructUpdateData* updateData)
{
	tid_t t = va_arg(notification.args, tid_t);
	struc_t* pStruct = get_struc(t);

	updateData->name = get_struc_name(t).c_str();
	updateData->isUnion = pStruct->is_union();

	g_idb->StoreStructName(t, updateData->name);
	return true;
}

void CreateStructSyncHandler::DecodePacketImpl(CreateStructUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	updateData->name = packet->ReadString();
	updateData->isUnion = packet->ReadBool();
}

void CreateStructSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, CreateStructUpdateData* updateData)
{
	packet->WriteString(updateData->name);
	packet->WriteBool(updateData->isUnion);
}