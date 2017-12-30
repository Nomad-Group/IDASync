import { PacketType } from './PacketType';
import { BasePacket } from './BasePacket';
import { NetworkBuffer } from '../NetworkBuffer';

export class Heartbeat extends BasePacket {
    public timestamp: number;

    public constructor() {
        super();

        this.packetType = PacketType.Heartbeat;
    }

    public encode(buffer: NetworkBuffer) {
        super.encode(buffer);

        buffer.writeUInt32(this.timestamp);
    }

    public decode(buffer: NetworkBuffer) {
        super.decode(buffer);

        this.timestamp = buffer.readUInt32();
    }
}