import { ObjectID } from 'mongodb';

export class ProjectData {
    public _id:ObjectID;
    
    public name:string;
    public binary_md5:string;
    public binary_version:number = 0;

    public users:ObjectID[] = [];
}