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
        this.guid = buffer.toString("utf8", BasePacket_1.BasePacket.HEADER_SIZE, BasePacket_1.BasePacket.HEADER_SIZE + 38);
    }
    encode(buffer) {
        super.encode(buffer);
        buffer.write(this.guid, BasePacket_1.BasePacket.HEADER_SIZE, 38, "utf8");
    }
}
exports.Handshake = Handshake;
class HandshakeResponse extends BasePacket_1.BasePacket {
    constructor() {
        super();
        this.packetType = PacketType_1.PacketType.HandshakeResponse;
        this.packetSize = 36;
    }
    decode(buffer) {
        super.decode(buffer);
        this.username = buffer.toString("utf8", BasePacket_1.BasePacket.HEADER_SIZE, BasePacket_1.BasePacket.HEADER_SIZE + 32);
    }
    encode(buffer) {
        super.encode(buffer);
        if (this.username == null) {
            for (var i = 0; i < 32; i++)
                buffer[BasePacket_1.BasePacket.HEADER_SIZE + i] = 0;
        }
        else {
            buffer.write(this.username, BasePacket_1.BasePacket.HEADER_SIZE, 32, "utf8");
        }
    }
}
exports.HandshakeResponse = HandshakeResponse;
//# sourceMappingURL=Handshake.js.map