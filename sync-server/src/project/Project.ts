import { BroadcastMessagePacket, BroadcastMessageType } from './../network/packets/BroadcastMessagePacket';
import { server, projectsManager, database } from './../app';
import { BasePacket } from './../network/packets/BasePacket';
import { NetworkClient } from './../network/NetworkClient';
import { ProjectData } from './../database/ProjectData';

export class Project {
    public active_clients:NetworkClient[] = [];
    public constructor(public data:ProjectData) {}

    public onClientJoined(client:NetworkClient, firstTime:boolean, localVersion:number) {
        // Join
        this.active_clients.push(client);

        // Join Broadcast
        var broadcast = new BroadcastMessagePacket();
        broadcast.messageType = firstTime ? BroadcastMessageType.ClientFirstJoin : BroadcastMessageType.ClientJoin;
        broadcast.data = client.user.username;

        server.sendPackets(this.active_clients, broadcast);

        // First Time?
        if(firstTime) {
            this.data.users.push(client.user._id);
            database.projects.update(this.data)
            .then(result => console.log(result))
        }

        // Log
        console.log("[Users] " + client.user.username + " joined " + this.data.name + (firstTime ? " (for the first time)" : ""));

        // Version
        if(localVersion < this.data.binary_version) {
            console.log("Version " + localVersion + " (client) vs. " + this.data.binary_version + " (server)");
        }
    }

    public onClientLeft(client:NetworkClient) {
        var index = this.active_clients.indexOf(client);
        if(index > -1)
            this.active_clients.slice(index);
    }

    public onClientPacket(client:NetworkClient, packet:BasePacket) {
        
    }
}