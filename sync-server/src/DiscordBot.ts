import * as Discord from 'discord.js';
import { Collection, GuildChannel, TextChannel } from 'discord.js';

const client = new Discord.Client();
const token = 'Mzk0MTU5Mjg4Mjc0MjU1ODcy.DSAQ-w.lQ3VQCOg5TYGAOxpvJxMJcFP6SE';
const targetChannels = ["394808588079726616"]; // ida-log in Nomad Group

export class DiscordBot {
    public initialize() {
        client.on('ready', this.onReady.bind(this));
        client.on('message', this.onMessage.bind(this));

        client.login(token);
    }

    private onReady() {
        console.log("[DiscordBot] Ready!");
        //console.log(client.channels);
    }

    private onMessage(msg: Discord.Message) {
        //console.log("[DiscordBot] Got message: " + msg.content);
    }

    public sendMessage(text: string) {
        var channels = client.channels.filter(c => targetChannels.indexOf(c.id) > -1) as Collection<string, TextChannel>;
        channels.forEach(c => c.send(text))
    }
}