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
                & {" "}
                <a
                    href="https://github.com/BrunoFrancesco97"
                    target="_blank"
                    rel="noreferrer"
                    aria-label={`GitHub page`}
                >
                     Francesco Bruno
                </a>{" "}
                - 2024
            </Footer>
        </Layout>
    );
}

export default App;
