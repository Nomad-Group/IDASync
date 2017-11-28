import { ObjectID } from 'mongodb';

export class ProjectData {
    public _id: ObjectID;

    public name: string;
    public binaryMD5: string;
    public binaryVersion: number = 0;

    public users: ObjectID[] = [];
}