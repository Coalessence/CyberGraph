const neo4j = require("neo4j-driver");
require("dotenv").config();

console.log("process.env.NEO4J_URI ", process.env.NEO4J_URI)

let driver = neo4j.driver(
    process.env.NEO4J_URI,
    neo4j.auth.basic(process.env.NEO4J_USERNAME, process.env.NEO4J_PASSWORD),
    {
        maxConnectionPoolSize: 100,
        connectionTimeout: 30000, // 30 seconds
    }
);

module.exports = driver;
