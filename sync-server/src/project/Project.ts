import { SyncType } from './../sync/ISyncHandler';
import { IdbUpdatePacket, IdbUpdateResponsePacket } from './../network/packets/IdbUpdatePacket';
import { ObjectID } from 'mongodb';
import { IdbUpdate } from './../database/IdbUpdate';
import { BroadcastMessagePacket, BroadcastMessageType } from './../network/packets/BroadcastMessagePacket';
import { server, projectsManager, database, syncManager, publicFeed } from './../app';
import { BasePacket } from './../network/packets/BasePacket';
import { NetworkClient } from './../network/NetworkClient';
import { ProjectData } from './../database/ProjectData';
import { UpdateClientOperation } from './UpdateClientOperation';

export class Project {
    public activeClients: NetworkClient[] = [];
    public constructor(public data: ProjectData) { }

    public onClientJoined(client: NetworkClient, firstTime: boolean, localVersion: number) {
        // Join
        this.activeClients.push(client);
        client.activeProject = this;

        // Join Broadcast
        var broadcast = new BroadcastMessagePacket();
        broadcast.messageType = firstTime ? BroadcastMessageType.ClientFirstJoin : BroadcastMessageType.ClientJoin;
        broadcast.data = client.user.username;

        server.sendPackets(this.activeClients, broadcast);

        // First Time?
        if (firstTime) {
            this.data.users.push(client.user._id);
            database.projects.update(this.data)
                .then(result => console.log(result));

            publicFeed.postUserActivity(client.user, "joined project " + this.data.name);
        }

        // Log
        console.log("[Project] " + client.user.username + " joined " + this.data.name + (firstTime ? " (for the first time)" : ""));

        // Version
        client.updateOperation = new UpdateClientOperation(client);
        client.updateOperation.start(localVersion);
    }

    public onClientData(client: NetworkClient, packet: BasePacket): boolean {
        // Idb Update
        var idbUpdatePacket = packet as IdbUpdatePacket;
        if (idbUpdatePacket) {
            this.onIdbUpdatePacket(client, idbUpdatePacket);
            return true;
        }

        // Unhandled
        return false;
    }

    public onClientLeft(client: NetworkClient) {
        // Update Operation
        if (client.updateOperation) {
            client.updateOperation.stop();
            client.updateOperation = null;
        }

        // Active Project
        this.activeClients.splice(this.activeClients.indexOf(client));
        client.activeProject = null;

        // Join Broadcast
        var broadcast = new BroadcastMessagePacket();
        broadcast.messageType = BroadcastMessageType.ClientDisconnect;
        broadcast.data = client.user.username;

        server.sendPackets(this.activeClients, broadcast);
    }

    private onIdbUpdatePacket(client: NetworkClient, packet: IdbUpdatePacket) {
        console.log("[Project] " + client.name + " sent update (" + SyncType[packet.syncType] + ")");

        // Update Data
        var updateData = syncManager.decodePacket(packet);
        if (updateData == null) {
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

            // Feed
            var syncHandler = syncManager.syncHandlers[updateData.type];

            var updateText = syncHandler.updateToString(updateData);
            if (updateText != null) {
                publicFeed.postUserActivity(client.user, updateText);
            }

            // Disable old IdbUpdate entries which have been overridden
            var uniqueIdentifier = syncHandler.getUniqueIdentifier(updateData);
            if (uniqueIdentifier == null) {
                return; // unsupported, always sync
            }

            var queryParams = {
                projectId: this.data._id,
                type: updateData.type,
                version: { $lt: updateData.version },
                shouldSync: true
            };
            queryParams = Object.assign(queryParams, uniqueIdentifier);

            // Find
            database.idbUpdates.find(queryParams).then(updates => {
                updates.forEach(update => {
                    // Should no longer be synced
                    update.shouldSync = false;

                    // Update
                    database.idbUpdates.update(update);
                })
            })
        });
    }

    public applyUpdate(update: IdbUpdate): Promise<ObjectID> {
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

    public sendUpdate(update: IdbUpdate, client: NetworkClient) {
        if (!update.shouldSync) {
            return;
        }

        var updatePacket = syncManager.encodePacket(update);
        server.sendPacket(client, updatePacket, false);
    }

    private broadcastUpdate(update: IdbUpdate, exception: NetworkClient) {
        var targetClients = this.activeClients.concat();
        if (exception) {
            targetClients = targetClients.filter(client => client != exception);
        }

        var updatePacket = syncManager.encodePacket(update);
        server.sendPackets(targetClients, updatePacket, false);
    }
}