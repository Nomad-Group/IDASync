import { IdbUpdate } from './../database/IdbUpdate';
import { NetworkBuffer } from './../network/NetworkBuffer';
import { IdbUpdatePacket } from './../network/packets/IdbUpdatePacket';
import { BasePacket } from './../network/packets/BasePacket';
import { NetworkClient } from './../network/NetworkClient';
import { ISyncHandler, SyncType } from './ISyncHandler';

class NameSyncUpdateData extends IdbUpdate {
    public ptr:number;
    public name:string;
}

export class NameSyncHandler implements ISyncHandler {
    public syncType:SyncType = SyncType.Name;

    public decodePacket(updateData:NameSyncUpdateData, packet:IdbUpdatePacket) {
        updateData.ptr = packet.buffer.readUInt64();
        updateData.name = packet.buffer.readString();
    }

    public encodePacket(packet:IdbUpdatePacket, updateData:NameSyncUpdateData) {
        packet.buffer.writeUInt64(updateData.ptr);
        packet.buffer.writeString("hello_fotze");// updateData.name);
    }
}