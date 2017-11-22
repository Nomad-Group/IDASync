"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const PacketType_1 = require("./PacketType");
const BasePacket_1 = require("./BasePacket");
class Heartbeat extends BasePacket_1.BasePacket {
    constructor() {
        super();
        this.packetType = PacketType_1.PacketType.Heartbeat;
    }
}
exports.Heartbeat = Heartbeat;
//# sourceMappingURL=Heartbeat.js.map