import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';

class ItemTypeSyncUpdate extends IdbUpdate {
    public ptr: Long;
    public itype: string;
    public fnames: string;
}

export class ItemTypeSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.Name;

    public decodePacket(updateData: ItemTypeSyncUpdate, packet: IdbUpdatePacket) {
        updateData.ptr = packet.buffer.readUInt64();
        updateData.itype = packet.buffer.readString();
        updateData.fnames = packet.buffer.readString();
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: ItemTypeSyncUpdate) {
        packet.buffer.writeUInt64(updateData.ptr);
        packet.buffer.writeString(updateData.itype);
        packet.buffer.writeString(updateData.fnames);
    }

    public getUniqueIdentifier(update: ItemTypeSyncUpdate) {
        return {
            ptr: update.ptr
        }
    }

    public updateToString(updateData: any): string {
        return null;
    }
}