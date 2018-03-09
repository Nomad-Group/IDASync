#include "sync/handler/RenameStructMemberSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"

#include "struct.hpp"

bool RenameStructMemberSyncHandler::ApplyUpdateImpl(RenameStructMemberUpdateData* updateData)
{
	struc_t* pStruct = get_struc(get_struc_id(updateData->structName.c_str()));
	return set_member_name(pStruct, static_cast<ea_t>(updateData->offset), updateData->memberName.c_str());
}

bool RenameStructMemberSyncHandler::HandleNotification(IdaNotification& notification, RenameStructMemberUpdateData* updateData)
{
	struc_t* pStruct = va_arg(notification.args, struc_t*);
	member_t* pMember = va_arg(notification.args, member_t*);

	updateData->structName = get_struc_name(pStruct->id).c_str();
	
	updateData->offset = pMember->soff;
	updateData->memberName = get_member_name2(pMember->id).c_str();

	return true;
}

void RenameStructMemberSyncHandler::DecodePacketImpl(RenameStructMemberUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	updateData->structName = packet->ReadString();

	packet->Read(&updateData->offset);
	updateData->memberName = packet->ReadString();
}

void RenameStructMemberSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, RenameStructMemberUpdateData* updateData)
{
	packet->WriteString(updateData->structName);

	packet->Write(&updateData->offset);
	packet->WriteString(updateData->memberName);
}