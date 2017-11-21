"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Heartbeat_1 = require("./packets/Heartbeat");
const Handshake_1 = require("./packets/Handshake");
const PacketType_1 = require("./packets/PacketType");
const net = require("net");
class Client {
}
class Server {
    constructor() {
        this.clients = [];
        setInterval(this.onHeartbeat.bind(this), 1000);
    }
    onHeartbeat() {
        var heartbeat = new Heartbeat_1.Heartbeat();
        this.clients.forEach(client => this.sendPacket(client, heartbeat));
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
        socket.on("close", this.onConnectionClosed.bind(this, client));
        socket.on("data", this.onClientData.bind(this, client));
        socket.on("error", this.onConnectionError.bind(this, client));
    }
    onConnectionClosed(client) {
        console.log("[Server] Client disconnected (" + client.name + ")");
        this.clients.splice(this.clients.indexOf(client));
    }
    onConnectionError(client, error) {
        console.error("[Server] Client (" + client.name + ") caused error: " + error.name + "\n" + error.message);
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
        if (packet.packetType == PacketType_1.PacketType.Handshake) {
            var response = new Handshake_1.HandshakeResponse();
            response.username = "You suck";
            console.log(response);
            this.sendPacket(client, response);
            setTimeout(() => {
                this.sendPacket(client, response);
            }, 1000);
        }
    }
    sendPacket(client, packet) {
        var buffer = new Buffer(packet.packetSize);
        packet.encode(buffer);
        client.socket.write(buffer);
        //client.socket.pipe(client.socket);
    }
}
Server.PORT = 4523;
exports.Server = Server;
//# sourceMappingURL=server.js.map