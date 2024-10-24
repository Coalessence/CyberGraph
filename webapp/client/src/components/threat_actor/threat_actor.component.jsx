import {Tooltip, Row, Col, Collapse, Tag, List, Table } from "antd";

const { Panel } = Collapse;

const Threat_Actor = ({ data }) => {
    const pattern1 = /\(Citation:[^\)]*\)/g;
    const pattern2 = /\(https:\/\/attack\.mitre\.org\/[^\)]*\)/g;
    const pattern3 = /[\[\]]/g
    const cleanedString = data.description.replace(pattern1, '').replace(pattern2, '').replace(pattern3, '');
    const columns_techniques = [
        {
            title: "MITRE ID",
            dataIndex: "id",
            align:"center"
        },
        {
            title: "Name",
            dataIndex: "name",
            align:"center"
        },
        {
            title: "MITRE URL",
            dataIndex: "link",
            align:"center",
            render: (link) => <a href={link}>{link}</a>,
        },
    ];
    return (
        <>
        <div style={{paddingLeft:"15%", paddingRight:"15%"}}>
<Row style={{backgroundColor:"#595959", paddingTop: "25px", borderRadius: "10px"}}>
    <Col xs={24} md={24} style={{backgroundColor:"#595959"}}>
        <p style={{color:"white", marginLeft: "25px"}}>Summary</p>
    </Col>
    <Col xs={24} md={24} style={{backgroundColor: "#dedede", padding:"25px"}}>
        <Row>
            <Col xs={24} style={{ marginBottom: "-25px",textAlign:"left" }}>
                <h2>{data.name}</h2>
            </Col>
        </Row>
        <Row align="middle" style={{ marginBottom: "10px" }}>
                <Col>
                    {data.link && data.link !== "N/A" && (
                        <Tooltip title={`MITRE`}>
                            <Tag color="blue" style={{ marginRight: "5px" }}>
                                {data.link}
                            </Tag>
                        </Tooltip>
                        
                    )}
                </Col>
                <Col>
                    {data.aliases && data.aliases.length > 0 && (
                        <div>
                            {data.aliases.map((alias, index) => (
                                <Tooltip title={'Alias'}>
                                    <Tag color="gold" style={{ margin: "0 5px 5px 0" }}>
                                        {alias}
                                    </Tag>
                                </Tooltip>
                            ))}
                        </div>
                    )}
                </Col>
            </Row>
        <Row style={{ marginTop: "10px" }}>
            <Col xs={24} style={{textAlign:"left"}}>
                <div style={{ fontSize: "14px", color: "#555" }}>{cleanedString}</div>
            </Col>
        </Row>
    </Col>
</Row>
<Col xs={24} md={24}>
        <Collapse>
            <Panel header="Expand for more details">
                <Row>
                <Col xs={24}>
                        <List style={{ fontWeight: 'bold', textAlign: 'left' }}
                            dataSource={data.technique}
                            header="TECHNIQUES USED BY THE THREAT ACTOR"
                        />
                        <Table
                            columns={columns_techniques}
                            dataSource={data.technique}
                            pagination={{
                                position: ["bottomCenter"],
                                pageSize: 5,
                                pageSizeOptions: [5, 10, 15],
                                simple: true,
                            }}
                            scroll={{
                                y: 240,
                            }}
                            rowKey={record => record.value + Math.floor(Math.random() * (1000 - 1 + 1)) + 1}
                        />
                    </Col>
                    <Col xs={24} style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', paddingTop: "25px",}}>
                            <p>Information retrivied using <a href={"https://attack.mitre.org"}>MITRE ATT&CK</a></p>
                    </Col>
                </Row>
            </Panel>
        </Collapse>
</Col>
</div>
        </>
    );
};

export default Threat_Actor;
