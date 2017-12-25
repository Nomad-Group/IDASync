import { ProjectData } from './../database/ProjectData';
import { User } from './../database/User';
import { database, server, projectsManager, publicFeed } from './../app';
import { NetworkClient } from './../network/NetworkClient';
import { Handshake, HandshakeResponse } from './../network/packets/Handshake';

export class HandshakeHandler {
    private static getUser(hardware_id: string, name: string): Promise<any> {
        return new Promise<any>((resolve, reject) => {
            database.users.findByHardwareId(hardware_id)
                .then(user => {
                    // User
                    if (user != null) {
                        resolve({ newlyCreated: false, user: user });
                        return;
                    }

                    // Setup
                    user = new User();
                    user.hardwareId = hardware_id;
                    user.username = name;

                    // Create
                    database.users.create(user)
                        .then(id => {
                            console.log("[Users] Created user " + user.username + " (" + user.hardwareId + ")");
                            publicFeed.postUserActivity(user, "joined for the first time!");

                            resolve({ newlyCreated: false, user: user });
                        })
                        .catch(reason => reject(reason));
                })
                .catch(reject)
        });
    }

    private static getProject(binary_md5: string, name: string): Promise<any> {
        return new Promise<any>((resolve, reject) => {
            database.projects.findByMd5(binary_md5)
                .then(project => {
                    // Projects
                    if (project != null) {
                        resolve({ newlyCreated: false, project: project });
                        return;
                    }

                    // Setup
                    project = new ProjectData();
                    project.binaryMD5 = binary_md5;
                    project.name = name;

                    // Create
                    database.projects.create(project)
                        .then(id => {
                            console.log("[Projects] Virgin idb detected: " + project.name);
                            publicFeed.postActivity("Project **" + project.name + "** was created!");

                            resolve({ newlyCreated: true, project: project });
                        })
                        .catch(reason => reject(reason));
                })
                .catch(reject)
        });
    }

    public static handle(client: NetworkClient, packet: Handshake) {
        Promise.all([
            this.getUser(packet.userGuid, packet.userName),
            this.getProject(packet.binaryMD5, packet.binaryName)
        ])
            .then((results) => {
                var response = new HandshakeResponse();

                // User 
                var user = <User>results[0].user;
                response.username = user.username;

                client.name = user.username;
                client.user = user;

                // Project
                var project = <ProjectData>results[1].project;

                response.projectName = project.name;
                response.projectVersion = project.binaryVersion;

                // Send
                server.sendPacket(client, response);

                // Join Project as Active
                projectsManager.addActive(project, client, packet.binaryVersion);
            })
    }
}