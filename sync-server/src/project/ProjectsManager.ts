import { NetworkClient } from './../network/NetworkClient';
import { ProjectData } from './../database/ProjectData';
import { Project } from "./Project";

export class ProjectsManager {
    public activeProjects: Project[] = [];

    public addActive(projectData: ProjectData, client: NetworkClient, localVersion: number) {
        // Project
        var project: Project = null;

        var index = this.activeProjects.findIndex(prj => prj.data.binaryMD5 == projectData.binaryMD5);
        if (index < 0) {
            project = new Project(projectData);
            this.activeProjects.push(project);
        } else {
            project = this.activeProjects[index];
        }

        // Client
        client.activeProject = project;

        // Client
        // TODO: check if one user is connected multiple times?
        var firstTimeJoin = projectData.users.findIndex(usr => usr.equals(client.user._id)) == -1;
        project.onClientJoined(client, firstTimeJoin, localVersion);
    }

    public removeActive(client: NetworkClient) {
        if (client.activeProject == null || client.activeProject == undefined) {
            return;
        }

        var index = this.activeProjects.findIndex(prj => prj.data.binaryMD5 == client.activeProject.data.binaryMD5);
        if (index < 0) {
            return;
        }

        var project = this.activeProjects[index];
        project.onClientLeft(client);

        if (project.activeClients.length == 0) {
            this.activeProjects.splice(index, 1);
        }
    }
}