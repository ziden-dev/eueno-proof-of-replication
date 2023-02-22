const modules = {};
const executePath = require("path").join(__dirname, "msg/execute");
require("fs")
    .readdirSync(executePath)
    .forEach((file) => {
        let tmp = require(`./msg/execute/${file}`);
        for (var name in tmp) {
            modules[name] = tmp[name];
        }
    });
const instantiationPath = require("path").join(__dirname, "msg/instantiation");
require("fs")
    .readdirSync(instantiationPath)
    .forEach((file) => {
        let tmp = require(`./msg/instantiation/${file}`);
        for (var name in tmp) {
            modules[name] = tmp[name];
        }
    });

const queryPath = require("path").join(__dirname, "msg/query");
require("fs")
    .readdirSync(queryPath)
    .forEach((file) => {
        let tmp = require(`./msg/query/${file}`);
        for (var name in tmp) {
            modules[name] = tmp[name];
        }
    });

const migratePath = require("path").join(__dirname, "msg/migrate");
require("fs")
    .readdirSync(migratePath)
    .forEach((file) => {
        let tmp = require(`./msg/migrate/${file}`);
        for (var name in tmp) {
            modules[name] = tmp[name];
        }
    });
module.exports = modules;
