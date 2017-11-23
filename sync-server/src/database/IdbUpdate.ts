import { ObjectID } from 'mongodb';

export enum IdbUpdateType {
    Name = 0
}

export class IdbUpdate {
    public _id:ObjectID;

    public project_id:ObjectID;
    public user_id:ObjectID;

    public type:IdbUpdateType;
    public version:number;
}