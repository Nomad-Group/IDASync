import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';

export enum StructMemberType {
    Data,
    Struct,
    String,
    Enum,
    Offset
}

export class StructMemberUpdateData extends IdbUpdate {
    public structName: string;
    public memberName: string;
    public memberType: StructMemberType;

    public offset: Long;
    public size: Long;
    public flag: number;

    public targetStructName: string;
    public stringType: number;

    // Offset (Refinfo)
    public refinfoTarget: Long;
    public refinfoBase: Long;
    public refinfoDelta: Long;
    public refinfoFlags: number;
}

export class CreateStructMemberSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.CreateStructMember;

    public decodePacket(updateData: StructMemberUpdateData, packet: IdbUpdatePacket) {
        updateData.structName = packet.buffer.readString();
        updateData.memberName = packet.buffer.readString();
        updateData.memberType = packet.buffer.readUInt8();

        updateData.offset = packet.buffer.readUInt64();
        updateData.size = packet.buffer.readUInt64();
        updateData.flag = packet.buffer.readUInt32();

        switch (updateData.memberType) {
            case StructMemberType.Struct: {
                updateData.targetStructName = packet.buffer.readString();
                break;
            }

            case StructMemberType.String: {
                updateData.stringType = packet.buffer.readInt32();
                break;
            }

            case StructMemberType.Offset: {
                updateData.refinfoTarget = packet.buffer.readUInt64();
                updateData.refinfoBase = packet.buffer.readUInt64();
                updateData.refinfoDelta = packet.buffer.readUInt64();
                updateData.refinfoFlags = packet.buffer.readUInt32();
                break;
            }
        }
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: StructMemberUpdateData) {
        packet.buffer.writeString(updateData.structName);
        packet.buffer.writeString(updateData.memberName);
        packet.buffer.writeUInt8(updateData.memberType);

        packet.buffer.writeUInt64(updateData.offset);
        packet.buffer.writeUInt64(updateData.size);
        packet.buffer.writeUInt32(updateData.flag);

        switch (updateData.memberType) {
            case StructMemberType.Struct: {
                packet.buffer.writeString(updateData.targetStructName);
                break;
            }

            case StructMemberType.String: {
                packet.buffer.writeUInt32(updateData.stringType);
                break;
            }

            case StructMemberType.Offset: {
                packet.buffer.writeUInt64(updateData.refinfoTarget);
                packet.buffer.writeUInt64(updateData.refinfoBase);
                packet.buffer.writeUInt64(updateData.refinfoDelta);
                packet.buffer.writeUInt32(updateData.refinfoFlags);
                break;
            }
        }
    }

    public getUniqueIdentifier(update: StructMemberUpdateData) {
        return null;
    }

    public updateToString(updateData: any): string {
        return null;
    }
}