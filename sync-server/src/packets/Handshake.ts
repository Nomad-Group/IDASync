import { PacketType } from './PacketType';
import { BasePacket } from './BasePacket';

export class Handshake extends BasePacket {
    public guid:string;
    public binarymd5:string;

    public constructor() {
        super();

        this.packetType = PacketType.Handshake;
        this.packetSize = 42;
    }

    public decode(buffer:Buffer) {
        super.decode(buffer);

        this.guid = buffer.toString("utf8", BasePacket.HEADER_SIZE, BasePacket.HEADER_SIZE + 38);
        this.binarymd5 = buffer.toString("utf8", BasePacket.HEADER_SIZE + 38, BasePacket.HEADER_SIZE + 38 + 16);
    }

    public encode(buffer:Buffer) {
        super.encode(buffer);

        buffer.write(this.guid, BasePacket.HEADER_SIZE, 38, "utf8");
        buffer.write(this.binarymd5, BasePacket.HEADER_SIZE + 38, 16, "utf8");
    }
}

export class HandshakeResponse extends BasePacket {
    public username:string;
    public project_name:string;

    public constructor() {
        super();

        this.packetType = PacketType.HandshakeResponse;
        this.packetSize = 36;
    }

    public decode(buffer:Buffer) {
        super.decode(buffer);

        this.username = buffer.toString("utf8", BasePacket.HEADER_SIZE, BasePacket.HEADER_SIZE + 32);
        this.project_name = buffer.toString("utf8", BasePacket.HEADER_SIZE + 32, BasePacket.HEADER_SIZE + 64);
    }

    public encode(buffer:Buffer) {
        super.encode(buffer);

        if(this.username != null) {
            buffer.write(this.username, BasePacket.HEADER_SIZE, 32, "utf8");
        }

        if(this.project_name != null) {
            buffer.write(this.project_name, BasePacket.HEADER_SIZE + 32, 32, "utf8");
        }
    }
}