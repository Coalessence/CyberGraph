import { useState } from "react";
import { Row, Col, Typography, Empty, Button, Card, Tooltip } from "antd";
import { Jumbotron, Search, SearchNew, FirstQueryResult, IpPrivate, IpPublic, Domain, Hash, SearchThreat, Threat_Actor } from "../../components";
import { LeftOutlined } from '@ant-design/icons';
import { SafetyCertificateOutlined, SearchOutlined, RadarChartOutlined } from '@ant-design/icons';

// import homepage from "./homepage.module.scss";
import utils from "../../styles/utils.module.scss";
const { Text } = Typography;





const Homepage = () => {
    const [res, setRes] = useState(null);
    const [mean, setMean] = useState(0);
    const [ippp, setIppp] = useState(null)
    const [ipp, setIpp] = useState(null)
    const [threat, setThreat] = useState(null)
    const [domain, setDomain] = useState(null)
    const [hash, setHash] = useState(null)
    const { Title } = Typography;
    const [showInterface, setShowInterface] = useState(null);
    const handleButtonClick = (interfaceName) => {
        setShowInterface(interfaceName);
    };

    const handleBackButtonClick = () => {
        setShowInterface(null);
        setRes(null);
        setMean(null);
        setIppp(null);
        setIpp(null);
        setDomain(null);
        setHash(null);
        setThreat(null);
    };

    const features = [
        {
          title: 'Vulnerability Assessment',
          icon: <SafetyCertificateOutlined style={{ fontSize: '48px', color: '#1890ff' }} />,
          description: 'Analyze and assess vulnerabilities in your systems.',
          link: '#vulnerability-assessment',
          onClick: () => handleButtonClick("InterfaceA")
        },
        {
          title: 'IoC Analysis',
          icon: <SearchOutlined style={{ fontSize: '48px', color: '#52c41a' }} />,
          description: 'Investigate Indicators of Compromise (IoCs) to detect threats.',
          link: '#ioc-analysis',
          onClick: () => handleButtonClick("InterfaceB")
        },
        {
          title: 'Threat Actor Search',
          icon: <RadarChartOutlined style={{ fontSize: '48px', color: '#fa8c16' }} />,
          description: 'Search and identify threat actors relevant to your environment.',
          link: '#threat-actor-search',
          onClick: () => handleButtonClick("InterfaceC")
        },
      ];
    return (
        <>
        {showInterface === null ? ( 
            <div style={{ padding: '50px', backgroundColor: '#f0f2f5' }}>
            <div style={{ textAlign: 'center', marginBottom: '40px' }}>
                <Title level={1} style={{ color: '#000' }}>CyberGraph</Title>
                <Text style={{ fontSize: '18px', color: '#595959' }}>
                    Empowering Cyber Defense: Analyzing Vulnerabilities and IOCs for Enhanced Security
                </Text>
            </div>
            <Row gutter={[24, 24]}>
            {features.map(feature => (
                <Tooltip title={`Enter the section`}>
                    <Col xs={24} sm={12} md={12} lg={8}>
                    <a href={feature.link} style={{ textDecoration: 'none' }}>
                        <Card
                        hoverable
                        style={{ textAlign: 'center', borderRadius: '8px', minHeight: '240px' }}
                        bodyStyle={{ padding: '30px' }}
                        onClick={feature.onClick}
                        >
                        {feature.icon}
                        <h3 style={{ marginTop: '20px', color: '#000' }}>{feature.title}</h3>
                        <p style={{ color: '#595959' }}>{feature.description}</p>
                        </Card>
                    </a>
                    </Col>
                </Tooltip>
            ))}
            </Row>
        </div>
        ) : showInterface === 'InterfaceA' ? (
            <div>
            <Row>
                    <Col xs={24} style={{padding:"25px"}}>
                        <Tooltip title={`Go back to the homepage`}>
                            <Button type="link" onClick={handleBackButtonClick} style={{ marginBottom: '20px', fontWeight: "bold" }}><LeftOutlined /> Go Back</Button>
                        </Tooltip>
                    </Col>
                </Row>
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
          </div>
        ) : showInterface === 'InterfaceB' ? (
            <div>
                <Row>
                <Col xs={24} style={{padding:"25px"}}>
                    <Tooltip title={`Go back to the homepage`}>
                            <Button type="link" onClick={handleBackButtonClick} style={{ marginBottom: '20px', fontWeight: "bold" }}><LeftOutlined /> Go Back</Button>
                        </Tooltip>
                    </Col>
                </Row>
                
                {ippp == null && ipp == null && domain == null && hash == null ? (
                <div>
                    <Row justify="center">
                        <Col
                            xs={20}
                            md={16}
                            lg={10}
                            xl={8}
                            className={`${utils.mt_big} ${utils.text_center}`}>
                            <Jumbotron
                                title={"CyberGraph"}
                                subtitle={
                                    "Investigate Indicators of Compromise (IoCs) to detect threats."
                                }
                            />
                        </Col>
                    </Row>
                    <Row justify="center">
                        <Col xs={20} md={16} lg={10} xl={8} className={utils.mt_mid}>
                            <SearchNew setIppp={setIppp} setIpp={setIpp} setDomain={setDomain} setHash={setHash}/>
                        </Col>
                    </Row>
                </div>
            ) : null}
            {ippp ? (
                <Row justify="center">
                    <Col
                        xs={24}
                        className={`${utils.mt_mid} ${utils.text_center}`}
                    >
                        <Title level={2}>
                            <IpPrivate data={ippp}/>
                        </Title>
                    </Col>
                </Row>
                
            ) : null}
            {ipp ? (
                <Row justify="center">
                    <Col xs={24} md={24}
                        className={`${utils.mt_mid} `}
                    >
                        <Title level={2}>
                            <IpPublic data={ipp}/>
                        </Title>
                    </Col>
                </Row>
                
            ) : null}
            {domain ? (
                <Row justify="center">
                    <Col xs={24} md={24}
                        className={`${utils.mt_mid} `}
                    >
                        <Title level={2}>
                            <Domain data={domain}/>
                        </Title>
                    </Col>
                </Row>
                
            ) : null}
            {hash ? (
                <Row justify="center">
                    <Col xs={24} md={24}
                        className={`${utils.mt_mid} `}
                    >
                        <Title level={2}>
                            <Hash data={hash}/>
                        </Title>
                    </Col>
                </Row>
            ) : null}
        </div>
        ) : showInterface === 'InterfaceC' ? (
            <div>
                <Row>
                    <Col xs={24} style={{padding:"25px"}}>
                    <Tooltip title={`Go back to the homepage`}>
                            <Button type="link" onClick={handleBackButtonClick} style={{ marginBottom: '20px', fontWeight: "bold" }}><LeftOutlined /> Go Back</Button>
                        </Tooltip>
                    </Col>
                </Row>
                {threat == null ? (
                    <div> 
                <Row justify="center">
                    <Col
                        xs={20}
                        md={16}
                        lg={10}
                        xl={8}
                        className={`${utils.mt_big} ${utils.text_center}`}>
                        <Jumbotron
                            title={"CyberGraph"}
                            subtitle={
                                "Search and identify threat actors relevant to your environment."
                            }
                        />
                    </Col>
                    <Col>
                            
                    </Col>
                </Row>
                <Row justify="center">
                    <Col xs={20} md={16} lg={10} xl={8} className={utils.mt_mid}>
                        <SearchThreat setThreat={setThreat}/>
                    </Col>
                </Row>
                </div>
                ) : null}
                {threat ? (
                <Row justify="center">
                    <Col
                        xs={24}
                        className={`${utils.mt_mid} ${utils.text_center}`}
                    >
                        <Title level={2}>
                            <Threat_Actor data={threat}/>
                        </Title>
                    </Col>
                </Row>
                
            ) : null}
            </div>
        ) : null}
        </>
    );
};

export default Homepage;
