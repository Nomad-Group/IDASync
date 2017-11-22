import { projectsManager } from './app';
import { HandshakeHandler } from './server/HandshakeHandler';
import { NetworkBuffer } from './network/NetworkBuffer';
import { NetworkClient } from './network/NetworkClient';
import { Heartbeat } from './network/packets/Heartbeat';
import { BasePacket } from './network/packets/BasePacket';
import { Handshake, HandshakeResponse } from './network/packets/Handshake';
import { PacketType } from './network/packets/PacketType';
import * as net from 'net';

export class Server {
    public static readonly PORT:number = 4523;
    public server:net.Server;
    private clients:NetworkClient[] = [];

    public constructor() {
        setInterval(this.onHeartbeat.bind(this), 1000);
    }

    private onHeartbeat() {
        var heartbeat = new Heartbeat();
        this.clients.forEach(client => this.sendPacket(client, heartbeat));
    }

    public startServer() {
        this.server = net.createServer(this.onConnection.bind(this)).listen(Server.PORT);
    }

    private onConnection(socket:net.Socket) {
        // Client
        var client = new NetworkClient();
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

    private onConnectionClosed(client:NetworkClient) {
        console.log("[Server] Client disconnected (" + client.name + ")");
        projectsManager.removeActive(client);

        this.clients.splice(this.clients.indexOf(client));
    }

    private onConnectionError(client:NetworkClient, error:Error) {
        console.error("[Server] Client (" + client.name + ") caused error: " + error.name + "\n" + error.message);
    }

    private onClientData(client:NetworkClient, dataBuffer:Buffer) {
        var data = new NetworkBuffer(dataBuffer);
        console.log("[Server] Data: " + dataBuffer.toString());

        var packet:BasePacket = null;
        var packetType:PacketType = data.readUInt16();

        switch(packetType)
        {
            case PacketType.Handshake: {
                packet = new Handshake();
            }
        }

        if(packet == null) {
            console.log("[Server] ERROR: Client (" + client.name + ") sent unknown Packet Type " + packetType.toString());
            return;
        }

        // Packet Header
        packet.packetType = packetType;
        packet.packetSize = data.readUInt16();

        // Decode Packet
        data.offset = 0;
        packet.decode(data);

        // DEBUG
        console.log(packet);

        if(packet.packetType == PacketType.Handshake)
        {
            HandshakeHandler.handle(client, <Handshake> packet);
        }
    }

    public sendPacket(client:NetworkClient, packet:BasePacket) {
        // Network Buffer
        var buffer = new NetworkBuffer(new Buffer(packet.packetSize));
        packet.encode(buffer);

        // Send Packet
        return client.socket.write(buffer.buffer);
    }
}