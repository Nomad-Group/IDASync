import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';

export class DeleteStructUpdateData extends IdbUpdate {
    public name: string;
}

export class DeleteStructSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.DeleteStruct;

    public decodePacket(updateData: DeleteStructUpdateData, packet: IdbUpdatePacket) {
        updateData.name = packet.buffer.readString();
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: DeleteStructUpdateData) {
        packet.buffer.writeString(updateData.name);
    }

    public getUniqueIdentifier(update: DeleteStructUpdateData) {
        return null;
    }

    public updateToString(updateData: any): string {
        return "deleted struct **" + updateData.name + "**";
    }
}