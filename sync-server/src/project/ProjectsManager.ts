import { NetworkClient } from './../network/NetworkClient';
import { ProjectData } from './../database/ProjectData';
import { Project } from "./Project";

export class ProjectsManager {
    public active_projects:Project[] = [];

    public addActive(projectData:ProjectData, client:NetworkClient, localVersion:number) {
        // Project
        var project:Project = null;

        var index = this.active_projects.findIndex(prj => prj.data.binary_md5 == projectData.binary_md5);
        if(index < 0) {
            project = new Project(projectData);
            this.active_projects.push(project);
        } else {
            project = this.active_projects[index];
        }

        // Client
        client.active_project = project;

        // Client
        // TODO: check if one user is connected multiple times?
        var firstTimeJoin = projectData.users.findIndex(usr => usr.equals(client.user._id)) == -1;
        project.onClientJoined(client, firstTimeJoin, localVersion);
    }

    public removeActive(client:NetworkClient) {
        if(client.active_project == null || client.active_project == undefined) {
            return;
        }

        var index = this.active_projects.findIndex(prj => prj.data.binary_md5 == client.active_project.data.binary_md5);
        if(index < 0) {
            return;
        }

        var project = this.active_projects[index];
        project.onClientLeft(client);

        if(project.active_clients.length == 0) {
            this.active_projects.splice(index);
        }
    }
}