import { User } from './../database/User';
import { database, server } from './../app';
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

    public static handle(client:NetworkClient, packet:Handshake) {
        this.getUser(packet.guid)
            .then(user => {
                var response = new HandshakeResponse();

                response.username = user.username;
                client.name = user.username;

                server.sendPacket(client, response);
            })
    }
}