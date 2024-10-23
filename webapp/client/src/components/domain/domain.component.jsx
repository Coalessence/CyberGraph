import {List, Table, Tooltip, Row, Col, Collapse, Tag } from "antd";

const { Panel } = Collapse;

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

const Domain = ({ data }) => {
    const columns_dns = [
        {
            title: "DNS Record Key",
            dataIndex: "key",
            align:"center"
        },
        {
            title: "DNS Record Value",
            dataIndex: "value",
            align:"center"
        },
    ];
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
    return (
        <>
        <div style={{paddingLeft:"15%", paddingRight:"15%"}}>
<Row style={{backgroundColor:"#595959", paddingTop: "25px", borderRadius: "10px" }}>
    <Col xs={24} md={24} style={{backgroundColor:"#595959"}}>
        <p style={{color:"white", marginLeft: "25px"}}>Summary</p>
    </Col>
    <Col xs={24} md={6} style={{backgroundColor: "#dedede", display: "flex", alignItems: "center", justifyContent: "center" }}>
        <CircleIndicator percentage={data.reputation} />
    </Col>
    <Col xs={24} md={18} style={{backgroundColor: "#dedede", padding:"25px"}}>
        <Row>
            <Col xs={24} style={{ marginBottom: "-25px" }}>
                <h2>{data.domain}</h2>
            </Col>
        </Row>
        <Row align="middle" style={{ marginBottom: "10px" }}>
                <Col>
                    {data.organization && data.organization !== "N/A" && (
                        <Tooltip title={`Organization`}>
                            <Tag color="blue" style={{ marginRight: "5px" }}>
                                {data.organization}
                            </Tag>
                        </Tooltip>
                        
                    )}
                </Col>
                <Col>
                    {data.products && data.products.length > 0 && (
                        <div>
                            {data.products.map((product, index) => (
                                <Tooltip title={`Products used`}>
                                    <Tag color="gold" style={{ margin: "0 5px 5px 0" }}>
                                        {product}
                                    </Tag>
                                </Tooltip>
                            ))}
                        </div>
                    )}
                </Col>
                <Col>
                    {data.ports && data.ports.length > 0 && (
                        <div>
                            {data.ports.map((port, index) => (
                                <Tooltip title={`Open ports`}>
                                    <Tag color="#2F4F4F" style={{ margin: "0 5px 5px 0" }}>
                                        {port}
                                    </Tag>
                                </Tooltip>
                            ))}
                        </div>
                    )}
                </Col>
                <Col>
                            {data.vulnerabilities_other_format && data.vulnerabilities_other_format.length > 0 && (
                                <div>
                                    {data.vulnerabilities_other_format.map((cve, index) => (
                                        <Tooltip title={`CVE`}>
                                            <Tag color="orange" style={{ margin: "0 5px 5px 0" }}>
                                                {cve.id}
                                            </Tag>
                                        </Tooltip>
                                    ))}
                                </div>
                            )}
                </Col>
            </Row>
        <Row style={{ marginTop: "10px" }}>
            <Col xs={12}>
                <div style={{ fontSize: "14px", color: "#555" }}>IPv4: {data.ipv4}</div>
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
                        <List
                            split={false}
                            pagination={{
                                position: ["bottomCenter"],
                                pageSize: 10,
                                simple: true,
                            }}
                            dataSource={data.hostnames}
                            header="Hostnames"
                            renderItem={(item, index) => <List.Item>{index+1}) {item}</List.Item>}
                        />
                    </Col>
                    <Col xs={24}>
                        <List
                            dataSource={data.hostnames}
                            header="DNS Queries"
                        />
                        <Table
                            columns={columns_dns}
                            dataSource={data.dns_records_other_format}
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
                    {data.vulnerabilities_other_format && data.vulnerabilities_other_format.length > 0 && (
                    <Col xs={24}>
                    
                        <List
                        dataSource={data.vulnerabilities_other_format}
                        header="Vulnerabilities"
                        />
                        <Table
                            columns={columns_vuln}
                            dataSource={data.vulnerabilities_other_format}
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
                    <Col xs={24}>
                        <List
                            pagination={{
                                position: ["bottomCenter"],
                                pageSize: 10,
                                simple: true,
                            }}
                            dataSource={data.subdomains}
                            header="Subdomains"
                            renderItem={(item, index) => <List.Item>{index+1}) {item}</List.Item>}
                        />
                    </Col>
                    <Col xs={24} style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', paddingTop: "25px",}}>
                            <p>Information retrivied using <a href={"https://www.shodan.io"}>Shodan</a>, <a href={"https://www.virustotal.com"}>VirusTotal</a> and <a href={"https://securitytrails.com"}>SecurityTrails</a></p>
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

export default Domain;
