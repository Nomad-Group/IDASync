import * as Discord from 'discord.js';
import { Collection, GuildChannel, TextChannel } from 'discord.js';
import { User } from './database/User';
import { publicFeed, database } from './app';
import { ProjectData } from './database/ProjectData';
import { SyncType } from './sync/ISyncHandler';

const client = new Discord.Client();
const token = 'Mzk0MTU5Mjg4Mjc0MjU1ODcy.DSAQ-w.lQ3VQCOg5TYGAOxpvJxMJcFP6SE';
const targetChannels = [
    "400025688062558210"   // ida-log in Nomad Group
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
        if (targetChannels.indexOf(msg.channel.id) < 0) {
            return;
        }

        if (msg.content == "!stats") {
            this.postStats(msg);
        }

        if (msg.content.startsWith("!disable-update ")) {
            let updateNumber = parseInt(msg.content.replace("!disable-update ", ""));
            if (updateNumber && updateNumber != NaN && updateNumber > 0) {
                database.idbUpdates.find({ version: updateNumber })
                    .then(updates => {
                        if (updates.length == 0) {
                            msg.reply("Did not find :/");
                            return;
                        }

                        if (updates.length > 1) {
                            msg.reply("Found multiple :/");
                            return;
                        }

                        let update = updates[0];
                        update.shouldSync = false;
                        database.idbUpdates.update(update)
                            .then(() => msg.reply("Ok"))
                            .catch(() => msg.reply("Error :/"))
                    })
            }
        }
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

    public postStats(msg: Discord.Message) {
        let promises: any = [
            database.users.find(),
            database.projects.find(),
            database.idbUpdates.countForStats()
        ];

        Promise.all(promises)
            .then((results) => {
                this.postStatsEmbed(msg, results[0] as User[], results[1] as ProjectData[], results[2]);
            })
            .catch((err) => {
                publicFeed.postServerError(err);
            })
    }

    private postStatsEmbed(msg: Discord.Message, users: User[], projects: ProjectData[], updates: any) {
        const embed = new Discord.RichEmbed();
        embed.setTitle(":regional_indicator_i: Server Stats")
            .setColor([46, 204, 113]);

        // Updates
        let content = "";
        updates.updates.forEach(info => {
            content += "**" + SyncType[info._id.type] + "**: " + info.count + "\n";
        })

        embed.setDescription(content);

        // Projects
        projects.forEach(project => {
            embed.addField(":regional_indicator_p: **" + project.name + "**",
                "**Updates:** " + project.binaryVersion + "\n" +
                "**Users:** " + project.users.length + "\n"
            );
        });

        users.forEach(user => {
            let infos = updates.userProjects.filter(info => info._id.userId.equals(user._id));

            let text = "";
            infos.forEach(info => {
                let project = projects.find(prj => prj._id.equals(info._id.projectId));
                text += "**" + info.count + "** updates in **" + project.name + "**\n";
            });

            if (text.length > 0) {
                embed.addField(":regional_indicator_u: **" + user.username + "**", text);
            }
        });

        // Author
        embed.setAuthor("IDA-Sync Stats", client.user.avatarURL);
        embed.setThumbnail(client.user.avatarURL);

        // Send
        msg.channel.send(embed);
    }
}