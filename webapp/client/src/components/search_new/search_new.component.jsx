import axios from "axios";
import { Button, Form, Row, Col, Input, Spin, notification } from "antd";
import { useState } from "react";
import utils from "../../styles/utils.module.scss";

const SearchNew = ({ setIppp, setIpp, setDomain, setHash }) => {
    const [showSpinner, setSpinner] = useState(false)
    const [api, contextHolder] = notification.useNotification();
    const validateSearch = (_, value) => {
        const regex = /^[0-9a-zA-Z.]*$/;
        if (regex.test(value)) {
          return Promise.resolve();
        }
        return Promise.reject('Only numbers, alphabetic characters or special character "."');
      };
      const showError = (type) => {
        api[type]({
          message: 'Error!',
          description:
            'The IoC you want to analyze is invalid.',
        });
      };
      const onFinish = async (values) => {
        try {
            setIppp(null)
            setIpp(null)
            setDomain(null)
            setHash(null)
            setSpinner(true)
            let res = await axios.get("http://127.0.0.1:3002/ioc", {
                params: {
                    ioc: values["search"],
                },
            });
            if(res.status === 200){
                if(res.data != null && res.data.ip != null){
                    setSpinner(false)
                    if(res.data.is_public != null && res.data.is_public === "False"){
                        setIppp(res.data)
                        setIpp(null)
                        setDomain(null)
                        setHash(null)
                    }else{
                        if(res.data.is_public != null && res.data.is_public === "True"){
                            setIpp(res.data)
                            setIppp(null)
                            setDomain(null)
                            setHash(null)
                        }
                    }
                }else{
                    if(res.data != null && res.data.domain != null && res.data.domain != ""){
                        setSpinner(false)
                        setDomain(res.data)
                        setIpp(null)
                        setIppp(null)
                        setHash(null)
                    }else{
                        if(res.data != null && res.data.hash != null && res.data.hash != ""){
                            setSpinner(false)
                            setDomain(null)
                            setIpp(null)
                            setIppp(null)
                            setHash(res.data)
                        }
                    }
                }
            }
        } catch (error) {
            setSpinner(false)
            showError('error')
        }
      };
      const onFinishFailed = (errorInfo) => {
        setSpinner(false)
      };
    return (
        <>
        {contextHolder}
        {showSpinner === true ? (
            <Spin fullscreen tip="Loading" spinning={showSpinner} size="large" style={{position: 'absolute',
               left: '50%',
               top: '100%',
               transform: 'translate(-50%, -50%)'}}/>
        ) : (
            <Form 
            autoComplete="off"
            onFinish={onFinish}
            onFinishFailed={onFinishFailed}>
                <Form.Item
                name="search"
                rules={[{ required: true, message: 'Inserisci un valore di ricerca!' }, { validator: validateSearch }]}
                >
                <Input placeholder="IP Address/domain/MD5/SHA256..." />
                </Form.Item>
                <Form.Item>
                    <Row>
                        <Col span={24}>
                                <Button
                                    type="primary"
                                    htmlType="submit"
                                    size="large"
                                    className={utils.round_corners}
                                    block
                                >
                                    Analyze IoC
                                </Button>
                        </Col>
                    </Row>
                </Form.Item>
            </Form>
        )}  
        </>
    );
};

export default SearchNew;
