#include "sync/handler/DeleteStructMemberSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"

#include "struct.hpp"

bool DeleteStructMemberSyncHandler::ApplyUpdateImpl(DeleteStructMemberUpdateData* updateData)
{
	struc_t* pStruct = get_struc(get_struc_id(updateData->structName.c_str()));
	g_plugin->Log("Delete offset " + std::to_string(updateData->offset));
	return del_struc_member(pStruct, updateData->offset);
}

bool DeleteStructMemberSyncHandler::HandleNotification(IdaNotification& notification, DeleteStructMemberUpdateData* updateData)
{
	struc_t* pStruct = va_arg(notification.args, struc_t*);
	/*tid_t t =*/ va_arg(notification.args, tid_t);
	ea_t offset = va_arg(notification.args, ea_t);

	updateData->structName = get_struc_name(pStruct->id).c_str();
	updateData->offset = static_cast<uint64_t>(offset);

	return true;
}

void DeleteStructMemberSyncHandler::DecodePacketImpl(DeleteStructMemberUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	updateData->structName = packet->ReadString();
	packet->Read(&updateData->offset);
}

void DeleteStructMemberSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, DeleteStructMemberUpdateData* updateData)
{
	packet->WriteString(updateData->structName.c_str());
	packet->Write(&updateData->offset);
}