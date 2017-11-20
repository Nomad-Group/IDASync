"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const BasePacket_1 = require("./BasePacket");
class Handshake extends BasePacket_1.BasePacket {
    decode(buffer) {
        this.guid = buffer.toString("utf8", BasePacket_1.BasePacket.HEADER_SIZE, BasePacket_1.BasePacket.HEADER_SIZE + 38);
    }
}
exports.Handshake = Handshake;
//# sourceMappingURL=Handshake.js.map