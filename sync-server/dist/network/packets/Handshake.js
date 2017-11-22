"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const PacketType_1 = require("./PacketType");
const BasePacket_1 = require("./BasePacket");
class Handshake extends BasePacket_1.BasePacket {
    constructor() {
        super();
        this.packetType = PacketType_1.PacketType.Handshake;
        this.packetSize = 42;
    }
    decode(buffer) {
        super.decode(buffer);
        this.guid = buffer.readCharArray(38);
        this.binary_name = buffer.readCharArray(128);
        this.binary_md5 = buffer.readCharArray(16);
    }
    encode(buffer) {
        super.encode(buffer);
        buffer.writeCharArray(this.guid, 38);
        buffer.writeCharArray(this.binary_name, 128);
        buffer.writeCharArray(this.binary_md5, 16);
    }
}
exports.Handshake = Handshake;
class HandshakeResponse extends BasePacket_1.BasePacket {
    constructor() {
        super();
        this.packetType = PacketType_1.PacketType.HandshakeResponse;
        this.packetSize = BasePacket_1.BasePacket.HEADER_SIZE + 96;
    }
    decode(buffer) {
        super.decode(buffer);
        this.username = buffer.readCharArray(32);
        this.project_name = buffer.readCharArray(64);
    }
    encode(buffer) {
        super.encode(buffer);
        buffer.writeCharArray(this.username, 32);
        buffer.writeCharArray(this.project_name, 64);
    }
}
exports.HandshakeResponse = HandshakeResponse;
//# sourceMappingURL=Handshake.js.map