import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';

export class RenameStructMemberUpdateData extends IdbUpdate {
    public structName: string;

    public offset: Long;
    public memberName: string;
}

export class RenameStructMemberSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.RenameStructMember;

    public decodePacket(updateData: RenameStructMemberUpdateData, packet: IdbUpdatePacket) {
        updateData.structName = packet.buffer.readString();

        updateData.offset = packet.buffer.readUInt64();
        updateData.memberName = packet.buffer.readString();
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: RenameStructMemberUpdateData) {
        packet.buffer.writeString(updateData.structName);

        packet.buffer.writeUInt64(updateData.offset);
        packet.buffer.writeString(updateData.memberName);
    }

    public getUniqueIdentifier(update: RenameStructMemberUpdateData) {
        return null;
    }

    public updateToString(updateData: any): string {
        return null;
    }
}