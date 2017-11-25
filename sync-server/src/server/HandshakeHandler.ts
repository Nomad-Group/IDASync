import { ProjectData } from './../database/ProjectData';
import { User } from './../database/User';
import { database, server, projectsManager } from './../app';
import { NetworkClient } from './../network/NetworkClient';
import { Handshake, HandshakeResponse } from './../network/packets/Handshake';

export class HandshakeHandler {
    private static getUser(hardware_id:string, name:string):Promise<any> {
        return new Promise<any>((resolve, reject) => {
            database.users.findByHardwareId(hardware_id)
                .then(user => {
                    // User
                    if(user != null) {
                        console.log("[Users] " + user.username + " connected");

                        resolve({ newlyCreated: false, user: user });
                        return;
                    }

                    // Setup
                    user = new User();
                    user.hardware_id = hardware_id;
                    user.username = name;

                    // Create
                    database.users.create(user)
                        .then(id => {
                            console.log("[Users] User connected for the first time: " + user.hardware_id);
                            resolve({ newlyCreated: false, user: user });
                        })
                        .catch(reason => reject(reason));
                })
                .catch(reject)
        });
    }

    private static getProject(binary_md5:string, name:string):Promise<any> {
        return new Promise<any>((resolve, reject) => {
            database.projects.findByMd5(binary_md5)
                .then(project => {
                    // Projects
                    if(project != null) {
                        resolve({ newlyCreated: false, project: project });
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
                            resolve({ newlyCreated: true, project: project });
                        })
                        .catch(reason => reject(reason));
                })
                .catch(reject)
        });
    }

    public static handle(client:NetworkClient, packet:Handshake) {
        Promise.all([
            this.getUser(packet.user_guid, packet.user_name),
            this.getProject(packet.binary_md5, packet.binary_name)
        ])
            .then((results) => {
                var response = new HandshakeResponse();

                // User 
                var user = <User> results[0].user;
                response.username = user.username;

                client.name = user.username;
                client.user = user;

                // Project
                var project = <ProjectData> results[1].project;
                response.project_name = project.name;

                // Send
                server.sendPacket(client, response);
                
                // Join Project as Active
                projectsManager.addActive(project, client, packet.binary_version);
            })
    }
}