import { discordBot } from "./app";
import { NetworkClient } from "./network/NetworkClient";
import { User } from "./database/User";

const FEED_ENABLED: boolean = true;

export class PublicFeed {
    public postActivity(text: string) {
        if (!FEED_ENABLED) {
            return;
        }

        discordBot.sendMessage(text);
    }

    public postUserActivity(user: User, text: string) {
        if (!FEED_ENABLED) {
            return;
        }

        discordBot.sendMessage("**" + user.username + "** " + text);
    }

    public postServerError(error: Error, user: User = null) {
        if (!FEED_ENABLED) {
            return;
        }

        discordBot.sendServerError(error, user);
    }
}