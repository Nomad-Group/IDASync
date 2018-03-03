import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';

export class CreateStructUpdateData extends IdbUpdate {
    public name: string;
    public isUnion: boolean;
}

export class CreateStructSyncHandler implements ISyncHandler {
    public syncType: SyncType = SyncType.CreateStruct;

    public decodePacket(updateData: CreateStructUpdateData, packet: IdbUpdatePacket) {
        updateData.name = packet.buffer.readString();
        updateData.isUnion = packet.buffer.readBoolean();
    }

    public encodePacket(packet: IdbUpdatePacket, updateData: CreateStructUpdateData) {
        packet.buffer.writeString(updateData.name);
        packet.buffer.writeBoolean(updateData.isUnion);
    }

    public getUniqueIdentifier(update: CreateStructUpdateData) {
        return {
            name: update.name
        }
    }

    public updateToString(updateData: any): string {
        return "created struct **" + updateData.name + "**";
    }
}