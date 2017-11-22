import { ProjectData } from './../database/ProjectData';
import { User } from './../database/User';
import * as net from 'net';

export class NetworkClient {
    public socket:net.Socket;
    public name:string;

    public user:User;
    public active_project:ProjectData;
}