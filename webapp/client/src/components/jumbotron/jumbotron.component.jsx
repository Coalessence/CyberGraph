import { Typography } from "antd";

// import jumbotron from "./jumbotron.module.scss";

const Jumbotron = ({ title, subtitle }) => {
    const { Title, Paragraph } = Typography;

    return (
        <>
            <Title level={1}>{title}</Title>
            <Paragraph type="secondary">{subtitle}</Paragraph>
        </>
    );
};

export default Jumbotron;
