import { ProjectData } from './database/ProjectData';
import { Database } from './Database';
import { Server } from './server';

export var database:Database = new Database();
export var server:Server = null;

database.initialize()
.then(() => {
    console.log("[Database] Connected!");

    server = new Server();
    server.startServer();
})
.catch(() => {
    console.log("Failed to connect to Database!");
})