import { discordBot } from "./app";
import { NetworkClient } from "./network/NetworkClient";
import { User } from "./database/User";


export class PublicFeed {
    public postActivity(text: string) {
        discordBot.sendMessage(text);
    }

    public postUserActivity(user: User, text: string) {
        //discordBot.sendMessage("**" + user.username + "** " + text);
    }

    public postServerError(error: Error, user: User = null) {
        discordBot.sendServerError(error, user);
    }
}