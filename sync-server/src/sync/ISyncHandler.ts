import { IdbUpdatePacket } from './../network/packets/IdbUpdatePacket';
import { BasePacket } from './../network/packets/BasePacket';
import { NetworkBuffer } from './../network/NetworkBuffer';
import { NetworkClient } from './../network/NetworkClient';

export enum SyncType {
    Name = 0,

    ItemComment,
    ItemType,

    AddFunc,
    Undefine,

    OperandType,
    MakeCode,

    AddReference,
    DeleteReference
}

export interface ISyncHandler {
    syncType: SyncType;

    decodePacket(updateData: any, packet: IdbUpdatePacket);
    encodePacket(packet: IdbUpdatePacket, updateData: any);

    getUniqueIdentifier(update: any): any;
}