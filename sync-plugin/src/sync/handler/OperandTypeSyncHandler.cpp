#include "sync/handler/OperandTypeSyncHandler.h"
#include "sync/SyncManager.h"
#include "SyncPlugin.h"
#include "Utility.h"
#include <offset.hpp>

bool OperandTypeSyncHandler::ApplyUpdateImpl(OperandTypeSyncUpdateData* updateData)
{
	g_plugin->Log(number2hex(updateData->ptr) + " operand type changed");

	// Operand Type
	if (updateData->operandType == OperandType::Offset)
	{
		refinfo_t ri;
		ri.init(
			updateData->dataOffset.flags,
			static_cast<ea_t>(updateData->dataOffset.base),
			static_cast<ea_t>(updateData->dataOffset.target),
			static_cast<adiff_t>(updateData->dataOffset.delta));

		return op_offset_ex(static_cast<ea_t>(updateData->ptr), updateData->numOperands, &ri);
	}
	else if(updateData->operandType == OperandType::Unknown)
	{
		return set_op_type(static_cast<ea_t>(updateData->ptr), updateData->flags, updateData->numOperands);
	}
	else
	{
		g_plugin->Log("ERROR: OperandTypeSyncHandler - Unsupported Operand Type!");
		return false;
	}
}

bool HandleOffset(OperandTypeSyncUpdateData* updateData)
{
	// Gather refinfo
	refinfo_t ri;
	if (!get_refinfo(&ri, static_cast<ea_t>(updateData->ptr), updateData->numOperands))
	{
		g_plugin->Log("ERROR: OperandTypeSyncHandler - Missing refinfo on offset " + number2hex(updateData->ptr));
		return false;
	}

	// Data
	updateData->dataOffset.flags = ri.flags;
	updateData->dataOffset.base = ri.base;
	updateData->dataOffset.target = ri.target;
	updateData->dataOffset.delta = ri.tdelta;

	// Done
	return true;
}

bool OperandTypeSyncHandler::HandleNotification(IdaNotification& notification, OperandTypeSyncUpdateData* updateData)
{
	ea_t ptr = va_arg(notification.args, ea_t);

	updateData->ptr = static_cast<uint64_t>(ptr);
	updateData->numOperands = va_arg(notification.args, int);
	updateData->flags = get_flags(ptr);

	// Operand Type
	if (updateData->numOperands == 0)
	{
		updateData->flags = get_optype_flags0(updateData->flags);

		if (is_enum0(updateData->flags))
			updateData->operandType = OperandType::_Unsupported; // OperandType::Enum;
		else if (is_stroff0(updateData->flags))
			updateData->operandType = OperandType::_Unsupported; // OperandType::StructOffset;
		else if (is_off0(updateData->flags))
			updateData->operandType = OperandType::Offset;
	}
	else if (updateData->numOperands == 1)
	{
		updateData->flags = get_optype_flags1(updateData->flags);

		if (is_enum1(updateData->flags))
			updateData->operandType = OperandType::_Unsupported; // OperandType::Enum;
		else if (is_stroff1(updateData->flags))
			updateData->operandType = OperandType::_Unsupported; // OperandType::StructOffset;
		else if (is_off1(updateData->flags))
			updateData->operandType = OperandType::Offset;
	}

	// Handle
	switch (updateData->operandType)
	{
	case OperandType::Offset:
		return HandleOffset(updateData);

	// Unsupported
	case OperandType::StructOffset:
	case OperandType::Enum:
	{
#ifdef _DEBUG
		g_plugin->Log("ERROR: OperandTypeSyncHandler - Unsupported Operand Type!");
#endif

		return true;
	}

	default:
		return false;
	}
}

void OperandTypeSyncHandler::DecodePacketImpl(OperandTypeSyncUpdateData* updateData, NetworkBufferT<BasePacket>* packet)
{
	packet->Read(&updateData->ptr);
	packet->Read(&updateData->numOperands);
	packet->Read(&updateData->flags);
	packet->Read(&updateData->operandType);

	// Data
	switch (updateData->operandType)
	{
	case OperandType::Offset:
	{
		packet->Read(&updateData->dataOffset.flags);
		packet->Read(&updateData->dataOffset.base);
		packet->Read(&updateData->dataOffset.target);
		packet->Read(&updateData->dataOffset.delta);
	} break;

	default:
		break;
	}
}

void OperandTypeSyncHandler::EncodePacketImpl(NetworkBufferT<BasePacket>* packet, OperandTypeSyncUpdateData* updateData)
{
	packet->Write(&updateData->ptr);
	packet->Write(&updateData->numOperands);
	packet->Write(&updateData->flags);
	packet->Write(&updateData->operandType);

	// Data
	switch (updateData->operandType)
	{
	case OperandType::Offset:
	{
		packet->Write(&updateData->dataOffset.flags);
		packet->Write(&updateData->dataOffset.base);
		packet->Write(&updateData->dataOffset.target);
		packet->Write(&updateData->dataOffset.delta);
	} break;

	default:
		break;
	}
}