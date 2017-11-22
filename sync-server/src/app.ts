import { ProjectData } from './database/ProjectData';
import { Database } from './Database';
import { Server } from './server';

let database = new Database();
database.initialize()
.then(() => {
    console.log("[Database] Connected!");

    let server = new Server();
    server.startServer();
})
.catch(() => {
    console.log("Failed to connect to Database!");
})