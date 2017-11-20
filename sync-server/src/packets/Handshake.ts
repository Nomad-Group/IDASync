import { PacketType } from './PacketType';
import { BasePacket } from './BasePacket';

export class Handshake extends BasePacket {
    public guid:string;

    public constructor() {
        super();

        this.packetType = PacketType.Handshake;
        this.packetSize = 42;
    }

    public decode(buffer:Buffer) {
        super.decode(buffer);

        this.guid = buffer.toString("utf8", BasePacket.HEADER_SIZE, BasePacket.HEADER_SIZE + 38);
    }

    public encode(buffer:Buffer) {
        super.encode(buffer);

        buffer.write(this.guid, BasePacket.HEADER_SIZE, 38, "utf8");
    }
}

export class HandshakeResponse extends BasePacket {
    public username:string;

    public constructor() {
        super();

        this.packetType = PacketType.HandshakeResponse;
        this.packetSize = 36;
    }

    public decode(buffer:Buffer) {
        super.decode(buffer);

        this.username = buffer.toString("utf8", BasePacket.HEADER_SIZE, BasePacket.HEADER_SIZE + 32);
    }

    public encode(buffer:Buffer) {
        super.encode(buffer);

        if(this.username == null) {
            for(var i = 0; i < 32; i++)
                buffer[BasePacket.HEADER_SIZE + i] = 0;
        } else {
            buffer.write(this.username, BasePacket.HEADER_SIZE, 32, "utf8");
        }
    }
}