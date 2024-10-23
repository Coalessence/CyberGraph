import { Tooltip, Tag, Collapse,Table,  List, Row, Col, Card, Typography } from "antd";

const { Panel } = Collapse;
const { Title, Link } = Typography;
const columns_vuln = [
    {
        title: "CVE ID",
        dataIndex: "id",
        align:"center"
    },
    {
        title: "Description",
        dataIndex: "description",
        align:"center",
        render: (descr) =>  descr != "N/A" ? descr.substring(0,200)+"...(visit the URL for more info)." : "N/A",
        tipText: "test"
    },
    {
        title: "URL",
        dataIndex: "url",
        align:"center",
        render: (url) => <a href={url}>{url}</a>,
    },
];
const columns_file = [
    {
        title: "FILE NAME",
        dataIndex: "value",
        align:"left"
    }
];

const CircleIndicator = ({ percentage }) => {
    const radius = 50;
    const strokeWidth = 10;
    const circumference = 2 * Math.PI * radius;
    const strokeDasharray = circumference;
    const strokeDashoffset = circumference - (percentage / 100) * circumference;
    return (
        <svg width="120" height="120" viewBox="0 0 120 120">
            <circle
                cx="60"
                cy="60"
                r={radius}
                stroke="#e6e6e6"
                strokeWidth={strokeWidth}
                fill="none"
            />
            <circle
                cx="60"
                cy="60"
                r={radius}
                stroke="#4CAF50"
                strokeWidth={strokeWidth}
                fill="none"
                strokeDasharray={strokeDasharray}
                strokeDashoffset={strokeDashoffset}
                transform="rotate(-90 60 60)"
            />
            <text x="50%" y="50%" alignmentBaseline="middle" textAnchor="middle" fontSize="20px" fill="#000">
                {percentage}%
            </text>
        </svg>
    );
};
const Hash = ({ data }) => {
    const percentage = Math.floor(data.score);
    const firstSubmissionnMilliseconds = Math.floor(data.first_submission * 1000);
    const first_new = new Date(Math.floor(firstSubmissionnMilliseconds));
    const isValidFirst = !isNaN(first_new.getTime());
    const formattedFirst = isValidFirst ? first_new.toISOString().split('T')[0] : 'Invalid Date';
    const tableData = data.file.map((item, index) => ({
        value: item
      }));
    return (
        <>
        <div style={{paddingLeft:"15%", paddingRight:"15%"}}>
        <Row style={{backgroundColor:"#595959", paddingTop: "25px", borderRadius: "10px" }}>
            <Col xs={24} md={24} style={{backgroundColor:"#595959"}}>
                <p style={{color:"white", marginLeft: "25px"}}>Summary</p>
            </Col>
            <Col xs={24} md={6} style={{backgroundColor: "#dedede", display: "flex", alignItems: "center", justifyContent: "center" }}>
                <CircleIndicator percentage={percentage} />
            </Col>
            <Col xs={24} md={18} style={{backgroundColor: "#dedede", padding:"25px"}}>
                <Row>
                    <Col xs={24} style={{ marginBottom: "-25px" }}>
                        <h3>{data.hash}</h3>
                    </Col>
                </Row>
                <Row align="middle" style={{ marginBottom: "10px" }}>
                        <Col>
                            {data.threat && data.threat !== "N/A" && (
                                <Tooltip title={`Threat found`}>
                                    <Tag color="red" style={{ marginRight: "5px" }}>
                                        {data.threat}
                                    </Tag>
                                </Tooltip>
                                
                            )}
                        </Col>
                        <Col>
                            {data.tags && data.tags.length > 0 && (
                                <div>
                                    {data.tags.map((cve, index) => (
                                        <Tooltip title={`CVE`}>
                                            <Tag color="orange" style={{ margin: "0 5px 5px 0" }}>
                                                {cve.id}
                                            </Tag>
                                        </Tooltip>
                                    ))}
                                </div>
                            )}
                        </Col>
                        <Col>
                            {data.extension && data.extension !== "N/A" && (
                                <Tooltip title={`Extension`}>
                                    <Tag color="purple" style={{ marginRight: "5px" }}>
                                        {data.extension}
                                    </Tag>
                                </Tooltip>
                                
                            )}
                        </Col>
                        <Col>
                            {data.magic && data.magic !== "N/A" && (
                                <Tooltip title={`Magic`}>
                                    <Tag color="purple" style={{ marginRight: "5px" }}>
                                        {data.magic}
                                    </Tag>
                                </Tooltip>
                                
                            )}
                        </Col>
                        <Col>
                            {data.type && data.type !== "N/A" && (
                                <Tooltip title={`Type`}>
                                    <Tag color="purple" style={{ marginRight: "5px" }}>
                                        {data.type}
                                    </Tag>
                                </Tooltip>
                                
                            )}
                        </Col>
                        <Col>
                            {data.type_description && data.type_description !== "N/A" && (
                                <Tooltip title={`type_description`}>
                                    <Tag color="purple" style={{ marginRight: "5px" }}>
                                        {data.type_description}
                                    </Tag>
                                </Tooltip>
                                
                            )}
                        </Col>
                </Row>
                <Row style={{ marginTop: "10px" }}>
                    <Col xs={12}>
                        <div style={{ fontSize: "14px", color: "#555" }}> First Submission: {formattedFirst}</div>
                    </Col>
                </Row>
            </Col>
    </Row>
    <Row>
    <Col xs={24} md={24}>
        <Collapse>
            <Panel header="Expand for more details">
                <Row>
                    <Col xs={24} md={24}>
                        <List style={{ fontWeight: 'bold', textAlign: 'left' }}
                            dataSource={tableData}
                            header="File names matching the hash"
                            />
                            <Table
                                columns={columns_file}
                                dataSource={tableData}
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
                    {data.tags && data.tags.length > 0 && (
                        <Col xs={24}>
                        <List
                            dataSource={data.tags}
                            header="Vulnerabilities exploited"
                        />
                        <Table
                            columns={columns_vuln}
                            dataSource={data.tags}
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
                    )}
                    <Card title="Threat Information" bordered={true}>
                        <Title level={4}>Threat: {data.threat}</Title>
                        
                        <Collapse accordion>
                        {data.tactics.map((tactic, index) => (
                            <Panel header={<Link href={tactic.link} target="_blank">{tactic.id} - {tactic.name}</Link>}>
                            <List
                                dataSource={tactic.techniques}
                                renderItem={(technique) => (
                                <List.Item>
                                    <Card title={<Link href={technique.link} target="_blank">{technique.id} - {technique.name}</Link>} bordered={true}>
                                    <Title level={5}>Threat Actors that use the technique:</Title>
                                    {technique.actors.map((actor, index) => (
                                        <Tag color="darkred">
                                        <a href={actor.link} target="_blank" rel="noopener noreferrer" style={{ color: '#fff' }}>
                                          {actor.id}
                                        </a>
                                      </Tag>
                                    ))}
                                    </Card>
                                </List.Item>
                                )}
                            />
                            </Panel>
                        ))}
                        </Collapse>
                    </Card>
                    <Col xs={24} style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', paddingTop: "25px",}}>
                            <p>Information retrivied using <a href={"https://attack.mitre.org"}>MITRE ATT&CK</a> and <a href={"https://www.virustotal.com"}>VirusTotal</a></p>
                    </Col>
                </Row>
            </Panel>
        </Collapse>
    </Col>
</Row>
</div>
        </>
    );
};

export default Hash;
