import { HeartbeatService } from './server/HeartbeatService';
import { IdbUpdatePacket } from './network/packets/IdbUpdatePacket';
import { BroadcastMessagePacket } from './network/packets/BroadcastMessagePacket';
import { projectsManager } from './app';
import { HandshakeHandler } from './server/HandshakeHandler';
import { NetworkBuffer } from './network/NetworkBuffer';
import { NetworkClient, NetworkClientDisconnectReason } from './network/NetworkClient';
import { Heartbeat } from './network/packets/Heartbeat';
import { BasePacket } from './network/packets/BasePacket';
import { Handshake, HandshakeResponse } from './network/packets/Handshake';
import { PacketType } from './network/packets/PacketType';
import * as net from 'net';

export class Server {
    public static readonly PORT: number = 4523;
    public server: net.Server;
    public clients: NetworkClient[] = [];
    //private heartbeatService: HeartbeatService = new HeartbeatService();

    public startServer() {
        this.server = net.createServer(this.onConnection.bind(this)).listen(Server.PORT);
    }

    private onConnection(socket: net.Socket) {
        // Client
        var client = new NetworkClient();
        client.socket = socket;
        client.name = socket.remoteAddress + ":" + socket.remotePort;
        this.clients.push(client);

        // Log
        console.log("[Server] Incomming connection " + client.name);

        // Event Handler
        socket.on("close", this.onConnectionClosed.bind(this, client));
        socket.on("data", this.onClientData_wrap.bind(this, client));
        socket.on("error", this.onConnectionError.bind(this, client));
    }

    private onConnectionClosed(client: NetworkClient) {
        console.log("[Server] Client " + client.name + " disconnected (" + NetworkClientDisconnectReason[client.disconnectReason] + ")");
        projectsManager.removeActive(client);

        this.clients.splice(this.clients.indexOf(client), 1);
    }

    private onConnectionError(client: NetworkClient, error: Error) {
        //console.error("[Server] Client (" + client.name + ") caused error: " + error.name + "\n" + error.);
        client.disconnectReason = NetworkClientDisconnectReason.Error;
    }

    private onClientData(client: NetworkClient, dataBuffer: Buffer) {
        var data = new NetworkBuffer(dataBuffer);
        //console.log("[Server] Data: " + dataBuffer.toString());

        var packet: BasePacket = null;
        var packetType: PacketType = dataBuffer.readUInt16LE(2);

        switch (packetType) {
            case PacketType.Handshake: {
                packet = new Handshake();
                break;
            }

            case PacketType.IdbUpdate: {
                packet = new IdbUpdatePacket();
                break;
            }

            case PacketType.Heartbeat: {
                client.lastHeartbeat = Date.now();
                return;
            }

            default: {
                console.log("[Server] ERROR: Client (" + client.name + ") sent unknown Packet Type " + packetType.toString());
                return;
            }
        }

        // Decode Packet
        packet.buffer = data;
        packet.decode(data);

        // DEBUG
        //console.log(packet);

        if (packet.packetType == PacketType.Handshake) {
            HandshakeHandler.handle(client, <Handshake>packet);
            return;
        }

        // Project: Handle Packet
        if (client.activeProject && client.activeProject.onClientData(client, packet)) {
            return;
        }

        // Unhandled Packet
        console.error("[Server] Unhandled Packet from " + client.name + " (Type: " + PacketType[packet.packetType] + ")");
    }

    private onClientData_wrap(client: NetworkClient, dataBuffer: Buffer) {
        try {
            this.onClientData(client, dataBuffer);
        } catch (err) {
            client.socket.destroy();
            console.log("ERROR: Client " + client.name + ": " + err);
        }
    }

    public sendPacket(client: NetworkClient, packet: BasePacket, encode: boolean = true) {
        // Network Buffer
        if (encode) {
            var buffer = new NetworkBuffer();
            packet.encode(buffer);

            packet.buffer = buffer;
        }

        // Packet Size
        packet.packetSize = packet.buffer.getSize();
        packet.buffer.buffer.writeUInt16LE(packet.packetSize, 0);

        // Send Packet
        return client.socket.write(packet.buffer.buffer);
    }

    public sendPackets(clients: NetworkClient[], packet: BasePacket, encode: boolean = true) {
        // Network Buffer
        if (encode) {
            var buffer = new NetworkBuffer();
            packet.encode(buffer);

            packet.buffer = buffer;
        }

        // Packet Size
        packet.packetSize = packet.buffer.getSize();
        packet.buffer.buffer.writeUInt16LE(packet.packetSize, 0);

        // Send
        clients.forEach(client => client.socket.write(packet.buffer.buffer));
    }
}