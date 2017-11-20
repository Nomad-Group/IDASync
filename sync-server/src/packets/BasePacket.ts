import { PacketType } from './PacketType';

export class BasePacket {
    public static HEADER_SIZE = 4;

    public packetType:PacketType;
    public packetSize:number;

    public decode(buffer:Buffer) {
        this.packetType = buffer.readUInt8(0);
        this.packetSize = buffer.readUInt16LE(2);
    }

    public encode(buffer:Buffer) {
        buffer.writeUInt8(this.packetType, 0);
        buffer.writeUInt16LE(this.packetSize, 2);
    }
}