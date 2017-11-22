import { ProjectData } from './../database/ProjectData';
import { User } from './../database/User';
import { database, server, projectsManager } from './../app';
import { NetworkClient } from './../network/NetworkClient';
import { Handshake, HandshakeResponse } from './../network/packets/Handshake';

export class HandshakeHandler {
    private static getUser(hardware_id:string):Promise<User> {
        return new Promise<User>((resolve, reject) => {
            database.users.findByHardwareId(hardware_id)
                .then(user => {
                    // User
                    if(user != null) {
                        console.log("[Users] " + user.username + " connected");

                        resolve(user);
                        return;
                    }

                    // Setup
                    user = new User();
                    user.hardware_id = hardware_id;
                    user.username = "Unknown User (?)";

                    // Create
                    database.users.create(user)
                        .then(id => {
                            console.log("[Users] Virgin user connected: " + user.hardware_id);
                            resolve(user);
                        })
                        .catch(reason => reject(reason));
                })
                .catch(reject)
        });
    }

    private static getProject(binary_md5:string, name:string):Promise<ProjectData> {
        return new Promise<ProjectData>((resolve, reject) => {
            database.projects.findByMd5(binary_md5)
                .then(project => {
                    // Projects
                    if(project != null) {
                        resolve(project);
                        return;
                    }

                    // Setup
                    project = new ProjectData();
                    project.binary_md5 = binary_md5;
                    project.name = name;

                    // Create
                    database.projects.create(project)
                        .then(id => {
                            console.log("[Projects] Virgin idb detected: " + project.name);
                            resolve(project);
                        })
                        .catch(reason => reject(reason));
                })
                .catch(reject)
        });
    }

    public static handle(client:NetworkClient, packet:Handshake) {
        Promise.all([
            this.getUser(packet.guid),
            this.getProject(packet.binary_md5, packet.binary_name)
        ])
            .then((results) => {
                var response = new HandshakeResponse();

                // User 
                var user = results[0];
                response.username = user.username;
                client.name = user.username;

                // Project
                var project = results[1];
                response.project_name = project.name;

                // Network Client
                client.user = user;
                client.active_project = project;

                // Join Project as Active
                projectsManager.addActive(project, client);

                // Send
                server.sendPacket(client, response);
            })
    }
}