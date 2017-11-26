import { Project } from './../project/Project';
import { User } from './../database/User';
import * as net from 'net';

export enum NetworkClientDisconnectReason {
    Disconnected,
    KickTimeout,
}

export class NetworkClient {
    public socket:net.Socket;
    public name:string;

    public user:User;
    public activeProject:Project;

    public lastHeartbeat:number = 0;
    public disconnectReason:NetworkClientDisconnectReason;
}