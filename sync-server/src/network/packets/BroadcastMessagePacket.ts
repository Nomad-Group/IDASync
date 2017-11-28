import { NetworkBuffer } from './../NetworkBuffer';
import { PacketType } from './PacketType';
import { BasePacket } from './BasePacket';

export enum BroadcastMessageType {
    ClientFirstJoin = 0,
    ClientJoin,
    ClientDisconnect
}

export class BroadcastMessagePacket extends BasePacket {
    public messageType: BroadcastMessageType;
    public data: string;

    public constructor() {
        super();

        this.packetType = PacketType.BroadcastMessage;
    }

    public decode(buffer: NetworkBuffer) {
        super.decode(buffer);

        this.messageType = buffer.readUInt8();
        this.data = buffer.readCharArray(64);
    }

    public encode(buffer: NetworkBuffer) {
        super.encode(buffer);

        buffer.writeUInt8(this.messageType);
        buffer.writeCharArray(this.data, 64);
    }
}