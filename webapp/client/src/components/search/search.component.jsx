import axios from "axios";

import { Button, Form, Input, Typography, Row, Col, message } from "antd";
import { MinusCircleOutlined, PlusOutlined } from "@ant-design/icons";

import utils from "../../styles/utils.module.scss";
// import search from "./search.module.scss";

const Search = ({ setRes, setMean }) => {
    const { Text } = Typography;

    const onFinish = async (values) => {
        try {
            let res = await axios.get("http://localhost:3001/vulnerabilities", {
                params: {
                    technologies: values["technology_stack"],
                },
            });

            if (res.data === 1000) {
                // Some inputs are invalid
                message.error("Some inputs are incomplete and/or invalid!");
            } else {
                // [0]: "technology"
                // [1]: "probability"
                // [2]: "cve"
                // [3]: "description"
                // [4]: "score"
                // [5]: "links"
                let total_score = 0;
                let count = 0;
                let query_result = [];
                res.data.map((row, idx) => {
                    if (row._fields[2] || row._fields[3] || row._fields[4]) {
                        let elem = {
                            key: idx,
                            score: row._fields[4],
                            technology: row._fields[0],
                            probability: row._fields[1],
                            cveid: row._fields[2],
                            cvedescription: row._fields[3],
                            cvepatches: row._fields[5],
                        };
                        query_result.push(elem);
                    }
                    if (row._fields[4]) {
                        total_score += row._fields[4];
                        count += 1;
                    }

                    return true;
                });
                if (count) {
                    setMean((total_score / count).toFixed(2));
                } else {
                    setMean(0);
                }
                setRes(query_result);
            }
        } catch (error) {
            console.error(
                `Some error occurred while contacting the server for the query. Error: ${error}`
            );
        }
    };

    return (
        <>
            <Form name="query_form" autoComplete="off" onFinish={onFinish}>
                <Form.List name="technology_stack">
                    {(fields, { add, remove }, { errors }) => (
                        <>
                            {fields.map(({ key, name, ...restField }) => (
                                <Row
                                    key={key}
                                    justify="space-between"
                                    align="middle"
                                >
                                    <Col xs={14}>
                                        <Form.Item
                                            {...restField}
                                            name={[name, "technology"]}
                                            rules={[
                                                {
                                                    required: true,
                                                    message:
                                                        "Missing technology",
                                                },
                                            ]}
                                        >
                                            <Input
                                                placeholder="Technology"
                                                className={utils.round_corners}
                                                size="large"
                                                allowClear
                                            />
                                        </Form.Item>
                                    </Col>
                                    <Col xs={7}>
                                        <Form.Item
                                            {...restField}
                                            name={[name, "version"]}
                                            rules={[
                                                {
                                                    required: true,
                                                    message: "Missing version",
                                                },
                                                {
                                                    pattern: /^[0-9.]+$/,
                                                    message: "Only 0-9 and .",
                                                },
                                            ]}
                                        >
                                            <Input
                                                placeholder="Version"
                                                className={utils.round_corners}
                                                size="large"
                                                allowClear
                                            />
                                        </Form.Item>
                                    </Col>
                                    <Col xs={1}>
                                        <Form.Item>
                                            <Text type="danger">
                                                <MinusCircleOutlined
                                                    className={utils.big_icon}
                                                    onClick={() => remove(name)}
                                                />
                                            </Text>
                                        </Form.Item>
                                    </Col>
                                </Row>
                            ))}
                            <Form.Item>
                                <Button
                                    type="dashed"
                                    onClick={() => add()}
                                    icon={<PlusOutlined />}
                                    className={utils.round_corners}
                                    size="large"
                                    block
                                >
                                    Add technology
                                </Button>
                            </Form.Item>
                        </>
                    )}
                </Form.List>
                <Form.Item>
                    <Row>
                        <Col span={24}>
                            <Button
                                type="primary"
                                htmlType="submit"
                                size="large"
                                className={utils.round_corners}
                                block
                            >
                                Check for vulnerabilities
                            </Button>
                        </Col>
                    </Row>
                </Form.Item>
            </Form>
        </>
    );
};

export default Search;
