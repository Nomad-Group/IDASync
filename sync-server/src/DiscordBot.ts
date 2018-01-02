import * as Discord from 'discord.js';
import { Collection, GuildChannel, TextChannel } from 'discord.js';
import { User } from './database/User';
import { publicFeed, database } from './app';
import { ProjectData } from './database/ProjectData';

const client = new Discord.Client();
const token = 'Mzk0MTU5Mjg4Mjc0MjU1ODcy.DSAQ-w.lQ3VQCOg5TYGAOxpvJxMJcFP6SE';
const targetChannels = [
    "394808588079726616"   // ida-log in Nomad Group
    //"394796278476832768"    // internal in watchdogs2modding
];

export class DiscordBot {
    public initialize() {
        client.on('ready', this.onReady.bind(this));
        client.on('message', this.onMessage.bind(this));

        client.login(token);
    }

    private onReady() {
        console.log("[DiscordBot] Ready!");
    }

    private onMessage(msg: Discord.Message) {
        /*if (msg.content == "!stats") {
            this.postStats();
        }*/
    }

    public sendMessage(text: string | Discord.RichEmbed) {
        var channels = client.channels.filter(c => targetChannels.indexOf(c.id) > -1) as Collection<string, TextChannel>;
        channels.forEach(c => c.send(text))
    }

    public sendServerError(error: Error, user: User = null) {
        const embed = new Discord.RichEmbed();
        embed.setTitle("Server Error")
            .setColor([231, 76, 60])
            .setDescription("**" + error.message + "**\n ```" + error.stack + "```")
            .setTimestamp()

        if (user != null) {
            embed.addField("User", user.username);
        }

        this.sendMessage(embed);
    }

    public postStats() {
        let promises: any = [
            database.users.find(),
            database.projects.find(),
            database.idbUpdates.countForStats()
        ];

        Promise.all(promises)
            .then((results) => {
                this.postStatsEmbed(results[0] as User[], results[1] as ProjectData[], results[2]);
            })
    }

    private postStatsEmbed(users: User[], projects: ProjectData[], updates: any) {
        const embed = new Discord.RichEmbed();
        embed.setTitle("Server Stats")
            .setColor([46, 204, 113]);

        // Users
        let usersText: string = "";
        users.forEach(user => usersText += user.username + "\n");

        embed.addField("Users", usersText);

        // Projects
        projects.forEach(project => {
            embed.addField("Project: " + project.name,
                "**Updates:** " + project.binaryVersion + "\n" +
                "**Users:** " + project.users.length + "\n"
            );
        });

        embed.addField("Updates", JSON.stringify(updates));

        this.sendMessage(embed);
    }
}