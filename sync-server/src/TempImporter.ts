import { database } from "./app";
import * as LineByLineReader from 'line-by-line';
import { NameSyncUpdateData } from "./sync/handler/NameSyncHandler";
import { Project } from "./project/Project";
import { SyncType } from "./sync/ISyncHandler";
import { Long } from "mongodb";

export function TempImport(project: Project) {
    var reader = new LineByLineReader("import.txt");

    reader.on("line", (line: string) => {
        let split = line.split("~");

        let update: NameSyncUpdateData = new NameSyncUpdateData();
        update.type = SyncType.Name;
        update.name = split[1];
        update.ptr = Long.fromString(split[0], 16);
        update.local = false;

        project.applyUpdate(update);
    })
}