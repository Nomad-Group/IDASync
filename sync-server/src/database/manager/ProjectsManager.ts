import { ProjectData } from './../ProjectData';

import { BaseCollectionManager } from './BaseCollectionManager';
import { Collection } from 'mongodb';
import { Db } from 'mongodb';

export class ProjectsManager extends BaseCollectionManager {
    public constructor() {
        super();

        this.collectionName = "projects";
    }

    public findByMd5(md5_hash:string):Promise<ProjectData> {
        var query = { binary_md5: md5_hash };
        return this.collection.findOne(query);
    }
}