"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class BasePacket {
    decode(buffer) {
        this.packetType = buffer.readUInt8(0);
        this.packetSize = buffer.readUInt16LE(2);
    }
    encode(buffer) {
        buffer.writeUInt8(this.packetType, 0);
        buffer.writeUInt16LE(this.packetSize, 2);
    }
}
BasePacket.HEADER_SIZE = 4;
exports.BasePacket = BasePacket;
//# sourceMappingURL=BasePacket.js.map