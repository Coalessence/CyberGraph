import { Tooltip, Tag, Collapse,Table,  List, Row, Col } from "antd";
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
const IpPublic = ({ data }) => {
    return (
        <>
        <div style={{paddingLeft:"15%", paddingRight:"15%"}}>
    <Row style={{backgroundColor:"#595959", paddingTop: "25px", borderRadius: "10px" }}>
        <Col xs={24} md={24} style={{backgroundColor:"#595959"}}>
            <p style={{color:"white", marginLeft: "25px"}}>Summary</p>
        </Col>
        <Col xs={24} md={6} style={{backgroundColor: "#dedede", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <CircleIndicator percentage={data.score} />
        </Col>
        <Col xs={24} md={18} style={{backgroundColor: "#dedede", padding:"25px"}}>
            <Row>
                <Col xs={24} style={{ marginBottom: "-25px" }}>
                    <h2>{data.ip}</h2>
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
                        {data.usage_type && data.usage_type !== "N/A" && (
                            <Tooltip title={`Organization`}>
                                <Tag color="blue" style={{ marginRight: "5px" }}>
                                    {data.usage_type}
                                </Tag>
                            </Tooltip>
                            
                        )}
                    </Col>
                    <Col>
                        {data.ASN && data.ASN !== "N/A" && (
                            <Tooltip title={`ASN`}>
                                <Tag color="orange" style={{ marginRight: "5px" }}>
                                    ASN: {data.ASN}
                                </Tag>
                            </Tooltip>
                            
                        )}
                    </Col>
                    <Col>
                        {data.ISP && data.ISP !== "N/A" && (
                            <Tooltip title={`ISP`}>
                                <Tag color="green" style={{ marginRight: "5px" }}>
                                    ISP: {data.ISP}
                                </Tag>
                            </Tooltip>
                            
                        )}
                    </Col>
                    <Col>
                        {data.country_city && data.country_city !== "N/A" && (
                            <Tooltip title={`City`}>
                                <Tag color="red" style={{ marginRight: "5px" }}>
                                    {data.country_city}
                                </Tag>
                            </Tooltip>
                            
                        )}
                    </Col>
                    <Col>
                        {data.country_name && data.country_name !== "N/A" && (
                            <Tooltip title={`Country`}>
                                <Tag color="red" style={{ marginRight: "5px" }}>
                                    {data.country_name}
                                </Tag>
                            </Tooltip>
                            
                        )}
                    </Col>
                    <Col>
                        {data.country_code && data.country_code !== "N/A" && (
                            <Tooltip title={`Country`}>
                                <Tag color="red" style={{ marginRight: "5px" }}>
                                    {data.country_code}
                                </Tag>
                            </Tooltip>
                            
                        )}
                    </Col>
                    <Col>
                        {data.products && data.products.length > 0 && (
                            <div>
                                {data.products.map((product, index) => (
                                    <Tooltip title={`Products used`}>
                                        <Tag color="gold" key={index} style={{ margin: "0 5px 5px 0" }}>
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
                                        <Tag color="#2F4F4F" key={index} style={{ margin: "0 5px 5px 0" }}>
                                            {port}
                                        </Tag>
                                    </Tooltip>
                                ))}
                            </div>
                        )}
                    </Col>
                </Row>
            <Row style={{ marginTop: "10px" }}>
                <Col xs={8}>
                    <div style={{ fontSize: "14px", color: "#555" }}> Number of reports: {data.number_of_reports}</div>
                </Col>
            </Row>
        </Col>
    </Row>
    <Row>
    <Col xs={24} md={24}>
        <Collapse>
            <Panel header="Expand for more details" key="1">
                <Row>
                    <Col xs={24} md={24}>
                        <List
                            split={false}
                            pagination={{
                                position: ["bottomCenter"],
                                pageSize: 10,
                                simple: true,
                            }}
                            dataSource={data.domains}
                            header="Domains matching the IP address: "
                            renderItem={(item, index) => <List.Item>{index+1}) {item}</List.Item>}
                        />
                    </Col>
                    <Col xs={24} style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', paddingTop: "25px",}}>
                        <p>Information retrivied using <a href={"https://www.shodan.io"}>Shodan</a> and <a href={"https://www.abuseipdb.com"}>AbuseIPDB</a></p>
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

export default IpPublic;
