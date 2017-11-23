import { NetworkBuffer } from './../NetworkBuffer';
import { PacketType } from './PacketType';
import { BasePacket } from './BasePacket';

export class Handshake extends BasePacket {
    public guid:string;
    public binary_md5:string;
    public binary_name:string;
    public binary_version:number;

    public constructor() {
        super();

        this.packetType = PacketType.Handshake;
        this.packetSize = 42;
    }

    public decode(buffer:NetworkBuffer) {
        super.decode(buffer);

        this.guid = buffer.readCharArray(38);
        this.binary_name = buffer.readCharArray(128);
        this.binary_md5 = buffer.readCharArray(16);
        this.binary_version = buffer.readUInt32();
    }

    public encode(buffer:NetworkBuffer) {
        super.encode(buffer);

        buffer.writeCharArray(this.guid, 38);
        buffer.writeCharArray(this.binary_name, 128);
        buffer.writeCharArray(this.binary_md5, 16);
        buffer.writeUInt32(this.binary_version);
    }
}

export class HandshakeResponse extends BasePacket {
    public username:string;
    public project_name:string;

    public constructor() {
        super();

        this.packetType = PacketType.HandshakeResponse;
        this.packetSize = BasePacket.HEADER_SIZE + 96;
    }

    public decode(buffer:NetworkBuffer) {
        super.decode(buffer);

        this.username = buffer.readCharArray(32);
        this.project_name = buffer.readCharArray(64);
    }

    public encode(buffer:NetworkBuffer) {
        super.encode(buffer);

        buffer.writeCharArray(this.username, 32);
        buffer.writeCharArray(this.project_name, 64);
    }
}