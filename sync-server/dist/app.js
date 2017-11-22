"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Database_1 = require("./Database");
const server_1 = require("./server");
let database = new Database_1.Database();
database.initialize()
    .then(() => {
    console.log("[Database] Connected!");
    let server = new server_1.Server();
    server.startServer();
})
    .catch(() => {
    console.log("Failed to connect to Database!");
});
//# sourceMappingURL=app.js.map