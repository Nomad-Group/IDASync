import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';

export class RenameStructUpdateData extends IdbUpdate {
    public oldName: string;
    public newName: string;
}

export class RenameStructSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.RenameStruct;

    public decodePacket(updateData: RenameStructUpdateData, packet: IdbUpdatePacket) {
        updateData.oldName = packet.buffer.readString();
        updateData.newName = packet.buffer.readString();
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: RenameStructUpdateData) {
        packet.buffer.writeString(updateData.oldName);
        packet.buffer.writeString(updateData.newName);
    }

    public getUniqueIdentifier(update: RenameStructUpdateData) {
        return null;
    }

    public updateToString(updateData: any): string {
        return "renamed struct " + updateData.oldName + " to **" + updateData.newName + "**";
    }
}