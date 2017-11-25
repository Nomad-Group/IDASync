import { SyncManager } from './sync/SyncManager';
import { ProjectsManager } from './project/ProjectsManager';
import { ProjectData } from './database/ProjectData';
import { Database } from './Database';
import { Server } from './server';

export var database:Database = new Database();
export var server:Server = null;

export var projectsManager:ProjectsManager = new ProjectsManager();
export var syncManager:SyncManager = new SyncManager();

database.initialize()
.then(() => {
    console.log("[Database] Connected!");

    server = new Server();
    server.startServer();
})
.catch(() => {
    console.log("Failed to connect to Database!");
})