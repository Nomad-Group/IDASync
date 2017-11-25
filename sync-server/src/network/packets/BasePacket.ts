import { NetworkBuffer } from './../NetworkBuffer';
import { PacketType } from './PacketType';

export class BasePacket {
    public static HEADER_SIZE = 4;
    public constructor() {
        this.packetSize = BasePacket.HEADER_SIZE;
    }

    public packetSize:number;
    public packetType:PacketType;

    public decode(buffer:NetworkBuffer) {
        this.packetSize = buffer.readUInt16();
        this.packetType = buffer.readUInt16();
    }

    public encode(buffer:NetworkBuffer) {
        buffer.writeUInt16(this.packetSize);
        buffer.writeUInt16(this.packetType);
    }

    // Optional, usually set when receiving
    public buffer:NetworkBuffer = null;
}