import { Table, Tag, List } from "antd";

const FirstQueryResult = ({ data }) => {
    // [0]: "technology"
    // [1]: "cve"
    // [2]: "description"
    // [3]: "score"
    // [4]: "links"
    const columns = [
        {
            title: "Score",
            dataIndex: "score",
            key: "score",
            align: "center",
            render: (score) => {
                let color =
                    score >= 6 && score < 8
                        ? "#fda703"
                        : score >= 8
                        ? "#ff968a"
                        : "";
                let component = score;
                if (color) {
                    component = (
                        <Tag
                            color={color}
                            key={Math.floor(100000 + Math.random() * 900000)}
                        >
                            {score}
                        </Tag>
                    );
                }

                return component;
            },
        },
        {
            title: "Technology",
            dataIndex: "technology",
            key: "technology",
        },
        {
            title: "CVE Id",
            dataIndex: "cveid",
            key: "cveid",
        },
        {
            title: "CVE Description",
            dataIndex: "cvedescription",
            key: "cvedescription",
            width: 600,
        },
        {
            title: "CVE Patches",
            dataIndex: "cvepatches",
            key: "cvepatches",
            render: (links) => {
                return (
                    <List
                        size="small"
                        dataSource={links}
                        renderItem={(item) => (
                            <List.Item key={item}>
                                <a href={item} target="_blank" rel="noreferrer">
                                    {item}
                                </a>
                            </List.Item>
                        )}
                    />
                );
            },
        },
    ];
    return (
        <>
            <Table
                columns={columns}
                dataSource={data}
                pagination={{
                    position: ["bottomCenter"],
                    pageSize: 10,
                    simple: true,
                }}
                scroll={{ x: "max-content" }}
            />
        </>
    );
};

export default FirstQueryResult;
