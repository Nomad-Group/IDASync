"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Handshake_1 = require("./packets/Handshake");
const PacketType_1 = require("./packets/PacketType");
const net = require("net");
class Client {
}
class Server {
    constructor() {
        this.clients = [];
    }
    startServer() {
        this.server = net.createServer(this.onConnection.bind(this)).listen(Server.PORT);
    }
    onConnection(socket) {
        // Client
        var client = new Client();
        client.socket = socket;
        client.name = socket.remoteAddress + ":" + socket.remotePort;
        this.clients.push(client);
        // Log
        console.log("[Server] Client connected (" + client.name + ")");
        // Event Handler
        socket.on("end", this.onConnectionClosed.bind(this, client));
        socket.on("data", this.onClientData.bind(this, client));
    }
    onConnectionClosed(client) {
        console.log("[Server] Client disconnected (" + client.name + ")");
    }
    onClientData(client, data) {
        console.log("[Server] Data: " + data.toString());
        var packet = null;
        var packetType = data.readUInt8(0);
        switch (packetType) {
            case PacketType_1.PacketType.Handshake: {
                packet = new Handshake_1.Handshake();
            }
        }
        if (packet == null) {
            console.log("[Server] ERROR: Client (" + client.name + ") sent unknown Packet Type " + packetType.toString());
            return;
        }
        // Packet Header
        packet.packetType = packetType;
        packet.packetSize = data.readUInt16LE(2);
        // Decode Packet
        packet.decode(data);
        // DEBUG
        console.log(packet);
    }
}
Server.PORT = 4523;
exports.Server = Server;
//# sourceMappingURL=server.js.map