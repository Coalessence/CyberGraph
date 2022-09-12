const express = require("express");
const cors = require("cors");
const { firstQuery } = require("./graph/queries");

const main = async () => {
    const app = express();
    const port = process.env.PORT || 3001;

    app.use(cors());
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));

    app.route("/vulnerabilities").get(async (req, res) => {
        let reg = /^[0-9.]+$/;
        let are_valid_fields = true;
        if (req.query.technologies) {
            req.query.technologies.map((technology) => {
                const element = JSON.parse(technology);
                if (
                    !element["technology"] ||
                    !element["version"] ||
                    !reg.test(element["version"])
                ) {
                    are_valid_fields = false;
                }
            });
        } else {
            are_valid_fields = false;
        }

        if (are_valid_fields) {
            try {
                const query_response = await firstQuery({
                    jsonString: "[" + req.query.technologies.join(",") + "]",
                });
                res.send(query_response);
            } catch (err) {
                console.log(
                    `Some error occurred while performing the query. Error: ${err}`
                );
            }
        } else {
            res.send("1000");
        }
    });

    app.listen(port, () => {
        console.log(`Server running locally on port ${port}`);
    });
};

main().catch((err) => {
    console.log(err);
});
