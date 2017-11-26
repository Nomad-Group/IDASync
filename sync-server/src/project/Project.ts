import { SyncType } from './../sync/ISyncHandler';
import { IdbUpdatePacket, IdbUpdateResponsePacket } from './../network/packets/IdbUpdatePacket';
import { ObjectID } from 'mongodb';
import { IdbUpdate } from './../database/IdbUpdate';
import { BroadcastMessagePacket, BroadcastMessageType } from './../network/packets/BroadcastMessagePacket';
import { server, projectsManager, database, syncManager } from './../app';
import { BasePacket } from './../network/packets/BasePacket';
import { NetworkClient } from './../network/NetworkClient';
import { ProjectData } from './../database/ProjectData';

export class Project {
    public activeClients:NetworkClient[] = [];
    public constructor(public data:ProjectData) {}

    public onClientJoined(client:NetworkClient, firstTime:boolean, localVersion:number) {
        // Join
        this.activeClients.push(client);
        client.activeProject = this;

        // Join Broadcast
        var broadcast = new BroadcastMessagePacket();
        broadcast.messageType = firstTime ? BroadcastMessageType.ClientFirstJoin : BroadcastMessageType.ClientJoin;
        broadcast.data = client.user.username;
        
        server.sendPackets(this.activeClients, broadcast);

        // First Time?
        if(firstTime) {
            this.data.users.push(client.user._id);
            database.projects.update(this.data)
            .then(result => console.log(result))
        }

        // Log
        console.log("[Project] " + client.user.username + " joined " + this.data.name + (firstTime ? " (for the first time)" : ""));

        // Version
        if(localVersion < this.data.binaryVersion) {
            this.sendUpdates(client, localVersion, this.data.binaryVersion);
        }
    }

    public onClientData(client:NetworkClient, packet:BasePacket):boolean {
        // Idb Update
        var idbUpdatePacket = packet as IdbUpdatePacket;
        if(idbUpdatePacket) {
            this.onIdbUpdatePacket(client, idbUpdatePacket);
            return true;
        }

        // Unhandled
        return false;
    }

    public onClientLeft(client:NetworkClient) {
        var index = this.activeClients.indexOf(client);
        if(index > -1) {
            this.activeClients.slice(index);
        }

        client.activeProject = null;
    }

    private onIdbUpdatePacket(client:NetworkClient, packet:IdbUpdatePacket) {
        console.log("[Project] " + client.name + " sent update (" + SyncType[packet.syncType] + ")");

        // Update Data
        var updateData = syncManager.decodePacket(packet);
        if(updateData == null) {
            return;
        }

        updateData.projectId = this.data._id;
        updateData.userId = client.user._id;

        // Store
        this.applyUpdate(updateData).then(() => {
            // Acknowledge
            var response = new IdbUpdateResponsePacket();
            response.version = updateData.version;

            server.sendPacket(client, response);

            // Broadcast
            this.broadcastUpdate(updateData, client);
        });
    }

    private applyUpdate(update:IdbUpdate):Promise<ObjectID> {
        // Binary Version
        this.data.binaryVersion++;
        update.version = this.data.binaryVersion;
        
        // Database
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
        var updatePacket = syncManager.encodePacket(update);
        server.sendPacket(client, updatePacket, false);
    }

    private broadcastUpdate(update:IdbUpdate, exception:NetworkClient) {
        var targetClients = this.activeClients.concat();
        if(exception) {
            targetClients = targetClients.filter(client => client != exception);
        }

        var updatePacket = syncManager.encodePacket(update);
        server.sendPackets(targetClients, updatePacket, false);
    }
}