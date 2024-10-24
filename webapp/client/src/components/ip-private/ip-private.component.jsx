import { Result } from "antd";

const IpPrivate = ({ data }) => {
    return (
        <>
            <Result
            title={data.ip}
            subTitle="The address you searched is a private IP address used inside an internal network system!"
            />
        </>
    );
};

export default IpPrivate;
