#include "sync/handler/StructMemberSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"

#include "struct.hpp"

bool StructMemberSyncHandler::ApplyUpdateImpl(StructMemberUpdateData* updateData)
{
	// Struct
	tid_t t = get_struc_id(updateData->structName.c_str());
	struc_t *s = get_struc(t);

	// Member
	opinfo_t ti;

	switch (updateData->memberType)
	{
	case StructMemberType::Struct:
		// TODO: ohoh, i think this is broken
		ti.tid = get_struc_id(updateData->targetStructName.c_str());
		break;

	case StructMemberType::String:
		ti.strtype = updateData->stringType;
		break;

	case StructMemberType::Offset:
		ti.ri = updateData->offsetRefInfo;
		break;
	}

	// Create / Change
	if (updateData->syncType == SyncType::CreateStructMember)
		return add_struc_member(s, updateData->memberName.c_str(), updateData->offset, updateData->flag, &ti, updateData->size) == STRUC_ERROR_MEMBER_OK;
	
	return set_member_type(s, updateData->offset, updateData->flag, &ti, updateData->size);
}

bool StructMemberSyncHandler::HandleNotification(IdaNotification& notification, StructMemberUpdateData* updateData)
{
	struc_t* pStruct = va_arg(notification.args, struc_t*);
	member_t* pMember = va_arg(notification.args, member_t*);

	updateData->structName = get_struc_name(pStruct->id).c_str();
		
	// Member
	updateData->memberName = get_member_name(pMember->id).c_str();

	updateData->offset = pMember->unimem() ? 0 : pMember->soff;
	updateData->size = (uint64_t)(pMember->unimem() ? pMember->eoff : (pMember->eoff - pMember->soff));
	updateData->flag = (uint32_t)pMember->flag;

	// Value
	opinfo_t ti;
	opinfo_t* pti = retrieve_member_info(&ti, pMember);

	if (pti)
	{
		// Struct
		if (is_struct(pMember->flag))
		{
			updateData->memberType = StructMemberType::Struct;
			updateData->targetStructName = get_struc_name(ti.tid).c_str();
		}
		// String
		else if (is_strlit(pMember->flag))
		{
			updateData->memberType = StructMemberType::String;
			updateData->stringType = ti.strtype;
		}
		// Offset
		else if (is_off0(pMember->flag) || is_off1(pMember->flag))
		{
			updateData->memberType = StructMemberType::Offset;
			updateData->offsetRefInfo = ti.ri;
		}
		// Enum (unsupported)
		else if (is_enum0(pMember->flag) || is_enum1(pMember->flag))
		{
			updateData->memberType = StructMemberType::Enum;
		}
	}
	else
	{
		// Data
		updateData->memberType = StructMemberType::Data;
	}

	// Update Type
	if (notification.code == idb_event::struc_member_created)
		updateData->syncType = SyncType::CreateStructMember;
	else
		updateData->syncType = SyncType::ChangeStructMember;

	return true;
}

void StructMemberSyncHandler::DecodePacketImpl(StructMemberUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	updateData->structName = packet->ReadString();
	updateData->memberName = packet->ReadString();
	packet->Read(&updateData->memberType);

	packet->Read(&updateData->offset);
	packet->Read(&updateData->size);
	packet->Read(&updateData->flag);

	switch (updateData->memberType)
	{
	case StructMemberType::Struct:
		updateData->targetStructName = packet->ReadString();
		break;

	case StructMemberType::String:
		packet->Read(&updateData->stringType);
		break;

	case StructMemberType::Offset:
	{
		packet->Read(&updateData->offsetRefInfo.target);
		packet->Read(&updateData->offsetRefInfo.base);
		packet->Read(&updateData->offsetRefInfo.tdelta);
		packet->Read(&updateData->offsetRefInfo.flags);
	} break;
	}
}

void StructMemberSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, StructMemberUpdateData* updateData)
{
	packet->WriteString(updateData->structName);
	packet->WriteString(updateData->memberName);
	packet->Write(updateData->memberType);

	packet->Write(&updateData->offset);
	packet->Write(&updateData->size);
	packet->Write(&updateData->flag);

	switch (updateData->memberType)
	{
	case StructMemberType::Struct:
		packet->WriteString(updateData->targetStructName);
		break;

	case StructMemberType::String:
		packet->Write(&updateData->stringType);
		break;

	case StructMemberType::Offset:
	{
		packet->Write(&updateData->offsetRefInfo.target);
		packet->Write(&updateData->offsetRefInfo.base);
		packet->Write(&updateData->offsetRefInfo.tdelta);
		packet->Write(&updateData->offsetRefInfo.flags);
	} break;
	}
}