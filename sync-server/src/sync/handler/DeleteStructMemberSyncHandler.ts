import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';

export class DeleteStructMemberUpdateData extends IdbUpdate {
    public structName: string;
    public offset: Long;
}

export class DeleteStructMemberSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.DeleteStructMember;

    public decodePacket(updateData: DeleteStructMemberUpdateData, packet: IdbUpdatePacket) {
        updateData.structName = packet.buffer.readString();
        updateData.offset = packet.buffer.readUInt64();
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: DeleteStructMemberUpdateData) {
        packet.buffer.writeString(updateData.structName);
        packet.buffer.writeUInt64(updateData.offset);
    }

    public getUniqueIdentifier(update: DeleteStructMemberUpdateData) {
        return null;
    }

    public updateToString(updateData: any): string {
        return null;
    }
}