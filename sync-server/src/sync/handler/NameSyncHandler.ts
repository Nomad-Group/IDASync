import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';

class NameSyncUpdateData extends IdbUpdate {
    public ptr: Long;
    public name: string;
    public local: boolean;
}

export class NameSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.Name;

    public decodePacket(updateData: NameSyncUpdateData, packet: IdbUpdatePacket) {
        updateData.ptr = packet.buffer.readUInt64();
        updateData.name = packet.buffer.readString();
        updateData.local = packet.buffer.readBoolean();
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: NameSyncUpdateData) {
        packet.buffer.writeUInt64(updateData.ptr);
        packet.buffer.writeString(updateData.name);
        packet.buffer.writeBoolean(updateData.local);
    }

    public getUniqueIdentifier(update: NameSyncUpdateData) {
        return {
            ptr: update.ptr
        }
    }

    public updateToString(updateData: any): string {
        return "renamed " + updateData.ptr.toString(16) + " to **" + updateData.name + "**";
    }
}