//import process from 'node:process';
const process = require("node:process");
const driver = require("./connection");
const { session: neo4j_session } = require("neo4j-driver");

const firstQuery = async ({ jsonString }) => {
    const session = driver.session({
        defaultAccessMode: neo4j_session.READ,
        database: "neo4j",
    });

    let res;
    try {
        res = await session.executeRead((tx) => {
            return tx.run(
                `UNWIND apoc.convert.fromJsonList($values) AS query
                 OPTIONAL MATCH (metric:Metric)<-[:HAS_METRIC]-(cve:CVE)-[aff:AFFECTS]->(prd:Product)
                 WHERE toLower(prd.name)=toLower(query.technology) AND aff.versionStartIncluding <= query.version <= COALESCE(aff.versionEndExcluding, '99.9.9')
                 OPTIONAL MATCH (cve)-[:HAS_LINK_TO]->(ref:Patch)
                 RETURN prd.name AS technology, cve.id AS cve, cve.description AS description, metric.baseScore AS score, collect(DISTINCT ref.url) AS links
                 ORDER BY metric.baseScore DESC`,
                {
                    values: jsonString,
                }
            );
        });
    } catch (err) {
        console.error(
            `Some error occurred while performing the first query. Error: ${err}`
        );
    } finally {
        await session.close();
    }

    return res.records;
};

// Close Neo4j driver only if you shut down the backend
process.on("exit", async (code) => {
    await driver.close();
    console.log("Correctly closed Neo4j driver");
});

module.exports = {
    firstQuery,
};
