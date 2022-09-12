import { useState } from "react";
import { Row, Col, Typography, Empty } from "antd";
import { Jumbotron, Search, FirstQueryResult } from "../../components";

// import homepage from "./homepage.module.scss";
import utils from "../../styles/utils.module.scss";

const Homepage = () => {
    const [res, setRes] = useState(null);
    const [mean, setMean] = useState(0);

    const { Title } = Typography;

    return (
        <>
            <Row justify="center">
                <Col
                    xs={20}
                    md={16}
                    lg={10}
                    xl={8}
                    className={`${utils.mt_big} ${utils.text_center}`}
                >
                    <Jumbotron
                        title={"CyberGraph"}
                        subtitle={
                            "insert your technology stack and find out if there are any associated vulnerabilities and possible solutions"
                        }
                    />
                </Col>
            </Row>
            <Row justify="center">
                <Col xs={20} md={16} lg={10} xl={8} className={utils.mt_mid}>
                    <Search setRes={setRes} setMean={setMean} />
                </Col>
            </Row>
            {mean ? (
                <Row justify="center">
                    <Col
                        xs={20}
                        className={`${utils.mt_mid} ${utils.text_center}`}
                    >
                        <Title level={2}>
                            Overall vulnerability score: {mean}
                        </Title>
                    </Col>
                </Row>
            ) : null}
            {res && res.length ? (
                <Row justify="center">
                    <Col xs={20} className={utils.mt_mid}>
                        <FirstQueryResult data={res} />
                    </Col>
                </Row>
            ) : res && !res.length ? (
                <Row justify="center">
                    <Col xs={20} className={`${utils.mt_mid}`}>
                        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
                    </Col>
                </Row>
            ) : null}
        </>
    );
};

export default Homepage;
