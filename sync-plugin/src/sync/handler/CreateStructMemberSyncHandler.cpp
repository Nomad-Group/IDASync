#include "sync/handler/CreateStructMemberSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"

#include "struct.hpp"

bool CreateStructMemberSyncHandler::ApplyUpdateImpl(StructMemberUpdateData* updateData)
{
	// Struct
	tid_t t = get_struc_id(updateData->structName.c_str());
	struc_t *s = get_struc(t);

	// Member
	opinfo_t ti;

	switch (updateData->memberType)
	{
	case StructMemberType::Struct:
		ti.tid = get_struc_id(updateData->targetStructName.c_str());
		break;

	case StructMemberType::String:
		ti.strtype = updateData->stringType;
		break;

	case StructMemberType::Offset:
		ti.ri = updateData->offsetRefInfo;
		break;
	}

	// Create
	if (updateData->syncType == SyncType::CreateStructMember)
		add_struc_member(s, updateData->memberName.c_str(), updateData->offset, updateData->flag, &ti, updateData->size);
	else
		set_member_type(s, updateData->offset, updateData->flag, &ti, updateData->size);

	return true;
}

bool CreateStructMemberSyncHandler::HandleNotification(IdaNotification& notification, StructMemberUpdateData* updateData)
{
	struc_t* pStruct = va_arg(notification.args, struc_t*);
	member_t* pMember = va_arg(notification.args, member_t*);

	updateData->structName = get_struc_name(pStruct->id).c_str();
		
	// Member
	updateData->memberName = get_member_name2(pMember->id).c_str();

	updateData->offset = pMember->unimem() ? 0 : pMember->soff;
	updateData->size = (uint64_t)(pMember->unimem() ? pMember->eoff : (pMember->eoff - pMember->soff));
	updateData->flag = (uint32_t)pMember->flag;

	// Value
	opinfo_t ti;
	opinfo_t* pti = retrieve_member_info(pMember, &ti);

	if (pti)
	{
		// Struct
		if (isStruct(pMember->flag))
		{
			updateData->memberType = StructMemberType::Struct;
			updateData->targetStructName = get_struc_name(ti.tid).c_str();
		}
		// String
		else if (isASCII(pMember->flag))
		{
			updateData->memberType = StructMemberType::String;
			updateData->stringType = ti.strtype;
		}
		// Offset
		else if (isOff0(pMember->flag) || isOff1(pMember->flag))
		{
			updateData->memberType = StructMemberType::Offset;
			updateData->offsetRefInfo = ti.ri;
		}
		// Enum (unsupported)
		else if (isEnum0(pMember->flag) || isEnum1(pMember->flag))
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

void CreateStructMemberSyncHandler::DecodePacketImpl(StructMemberUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
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

void CreateStructMemberSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, StructMemberUpdateData* updateData)
{
	packet->WriteString(updateData->structName.c_str());
	packet->WriteString(updateData->memberName.c_str());
	packet->Write(updateData->memberType);

	packet->Write(&updateData->offset);
	packet->Write(&updateData->size);
	packet->Write(&updateData->flag);

	switch (updateData->memberType)
	{
	case StructMemberType::Struct:
		packet->WriteString(updateData->targetStructName.c_str());
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