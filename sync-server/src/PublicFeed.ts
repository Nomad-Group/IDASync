import { discordBot } from "./app";
import { NetworkClient } from "./network/NetworkClient";
import { User } from "./database/User";

const FEED_ENABLED: boolean = false;

export class PublicFeed {
	public postActivity(text: string) {
		if (!FEED_ENABLED) {
			return;
		}

		discordBot.sendMessage(text);
	}

	public postUserActivity(user: User, text: string, version?: number) {
		if (!FEED_ENABLED) {
			return;
		}

		let str = "**" + user.username + "** " + text;
		if (version) {
			str = `[${version}] ` + str;
		}

		discordBot.sendMessage(str);
	}

	public postServerError(error: Error, user: User = null) {
		if (!FEED_ENABLED) {
			return;
		}

		discordBot.sendServerError(error, user);
	}
}