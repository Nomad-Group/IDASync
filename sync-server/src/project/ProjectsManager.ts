import { NetworkClient } from './../network/NetworkClient';
import { ProjectData } from './../database/ProjectData';
import { Project } from "./Project";

export class ProjectsManager {
    public active_projects:Project[] = [];

    public addActive(projectData:ProjectData, client:NetworkClient) {
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
        // TODO: check if one user is connected multiple times?
        project.onClientJoined(client);
    }

    public removeActive(client:NetworkClient) {
        if(client.active_project == null || client.active_project == undefined) {
            return;
        }

        var index = this.active_projects.findIndex(prj => prj.data.binary_md5 == client.active_project.binary_md5);
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