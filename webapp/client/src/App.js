import { Layout } from "antd";

import { Homepage } from "./pages";

import "./styles/app.css";
import utils from "./styles/utils.module.scss";

function App() {
    const { Content, Footer } = Layout;

    return (
        <Layout>
            <Content className="main-content">
                <Homepage />
            </Content>
            <Footer className={utils.text_center}>
                Made by{" "}
                <a
                    href="https://github.com/FabioDainese"
                    target="_blank"
                    rel="noreferrer"
                    aria-label={`GitHub page`}
                >
                    Fabio Dainese
                </a>{" "}
                - 2022
            </Footer>
        </Layout>
    );
}

export default App;
