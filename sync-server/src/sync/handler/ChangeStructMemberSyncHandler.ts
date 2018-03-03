import { Long } from 'mongodb';
import { IdbUpdate } from './../../database/IdbUpdate';
import { NetworkBuffer } from './../../network/NetworkBuffer';
import { IdbUpdatePacket } from './../../network/packets/IdbUpdatePacket';
import { BasePacket } from './../../network/packets/BasePacket';
import { NetworkClient } from './../../network/NetworkClient';
import { ISyncHandler, SyncType } from './../ISyncHandler';
import { StructMemberUpdateData, CreateStructMemberSyncHandler } from './CreateStructMemberSyncHandler';

export class ChangeStructMemberSyncHandler extends CreateStructMemberSyncHandler {
    public syncType: SyncType = SyncType.ChangeStructMember;
}