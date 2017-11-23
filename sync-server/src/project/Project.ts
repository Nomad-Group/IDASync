import { BaseIdbUpdatePacket } from './../network/packets/BaseIdbUpdatePacket';
import { ObjectID } from 'mongodb';
import { IdbUpdate } from './../database/IdbUpdate';
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
        client.active_project = this;

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
        console.log("Version " + localVersion + " (client) vs. " + this.data.binary_version + " (server)");
        if(localVersion < this.data.binary_version) {

            this.sendUpdates(client, localVersion, this.data.binary_version);
        }
    }

    public onClientData(client:NetworkClient, packet:BasePacket):boolean {
        // Idb Update
        var idbUpdatePacket = packet as BaseIdbUpdatePacket;
        if(idbUpdatePacket) {
            this.onIdbUpdatePacket(client, idbUpdatePacket);
            return true;
        }

        // Unhandled
        return false;
    }

    public onClientLeft(client:NetworkClient) {
        var index = this.active_clients.indexOf(client);
        if(index > -1) {
            this.active_clients.slice(index);
        }

        client.active_project = null;
    }

    private onIdbUpdatePacket(client:NetworkClient, packet:BaseIdbUpdatePacket) {
        console.log("[Project] " + client.name + " sent update (" + packet.constructor.name + ")");

        // Store
        this.applyUpdate(packet.getUpdateData(), client);
    }

    private applyUpdate(update:IdbUpdate, client:NetworkClient):Promise<ObjectID> {
        // Update Data
        update.project_id = this.data._id;
        update.user_id = client.user._id;

        // Binary Version
        this.data.binary_version++;
        update.version = this.data.binary_version;
        
        return new Promise<ObjectID>((resolve, reject) => {
            database.projects.update(this.data)
                .then(() => database.idbUpdates.create(update))
                .then(resolve)
        });
    }

    private sendUpdates(client:NetworkClient, version_start:number, version_to:number) {
        database.idbUpdates.findUpdates(this.data._id, version_start, version_to)
            .then(updates => {
                updates.forEach(update => this.sendUpdate(update, client))
            });
    }

    private sendUpdate(update:IdbUpdate, client:NetworkClient) {
        
    }
}