import axios from "axios";
import { Button, Form, Row, Col, Input, Spin, notification, Select, Radio } from "antd"; 
import { useState } from "react";


const { Option } = Select;

const countries = [
    "Afghanistan", "Albania", "Algeria", "Andorra", "Angola", "Antigua and Barbuda", "Argentina", "Armenia", 
    "Australia", "Austria", "Azerbaijan", "Bahamas", "Bahrain", "Bangladesh", "Barbados", "Belarus", "Belgium", 
    "Belize", "Benin", "Bhutan", "Bolivia", "Bosnia and Herzegovina", "Botswana", "Brazil", "Brunei", 
    "Bulgaria", "Burkina Faso", "Burundi", "Cabo Verde", "Cambodia", "Cameroon", "Canada", "Central African Republic", 
    "Chad", "Chile", "China", "Colombia", "Comoros", "Congo", "Costa Rica", "Croatia", "Cuba", "Cyprus", 
    "Czech Republic", "Denmark", "Djibouti", "Dominica", "Dominican Republic", "Ecuador", "Egypt", "El Salvador", 
    "Equatorial Guinea", "Eritrea", "Estonia", "Eswatini", "Ethiopia", "Fiji", "Finland", "France", "Gabon", 
    "Gambia", "Georgia", "Germany", "Ghana", "Greece", "Grenada", "Guatemala", "Guinea", "Guinea-Bissau", "Guyana", 
    "Haiti", "Honduras", "Hungary", "Iceland", "India", "Indonesia", "Iran", "Iraq", "Ireland", "Israel", 
    "Italy", "Jamaica", "Japan", "Jordan", "Kazakhstan", "Kenya", "Kiribati", "Kuwait", "Kyrgyzstan", 
    "Laos", "Latvia", "Lebanon", "Lesotho", "Liberia", "Libya", "Liechtenstein", "Lithuania", "Luxembourg", 
    "Madagascar", "Malawi", "Malaysia", "Maldives", "Mali", "Malta", "Marshall Islands", "Mauritania", "Mauritius", 
    "Mexico", "Micronesia", "Moldova", "Monaco", "Mongolia", "Montenegro", "Morocco", "Mozambique", "Myanmar", 
    "Namibia", "Nauru", "Nepal", "Netherlands", "New Zealand", "Nicaragua", "Niger", "Nigeria", "North Macedonia", 
    "Norway", "Oman", "Pakistan", "Palau", "Panama", "Papua New Guinea", "Paraguay", "Peru", "Philippines", 
    "Poland", "Portugal", "Qatar", "Romania", "Russia", "Rwanda", "Saint Kitts and Nevis", "Saint Lucia", 
    "Saint Vincent and the Grenadines", "Samoa", "San Marino", "Sao Tome and Principe", "Saudi Arabia", "Senegal", 
    "Serbia", "Seychelles", "Sierra Leone", "Singapore", "Slovakia", "Slovenia", "Solomon Islands", "Somalia", 
    "South Africa", "South Korea", "South Sudan", "Spain", "Sri Lanka", "Sudan", "Suriname", "Sweden", "Switzerland", 
    "Syria", "Taiwan", "Tajikistan", "Tanzania", "Thailand", "Timor-Leste", "Togo", "Tonga", "Trinidad and Tobago", 
    "Tunisia", "Turkey", "Turkmenistan", "Tuvalu", "Uganda", "Ukraine", "United Arab Emirates", "United Kingdom", 
    "United States", "Uruguay", "Uzbekistan", "Vanuatu", "Vatican City", "Venezuela", "Vietnam", "Yemen", 
    "Zambia", "Zimbabwe"
  ];

const SearchThreat = ({ setThreat }) => {
    const [form] = Form.useForm();
    const [showSpinner, setSpinner] = useState(false)
    const [api, contextHolder] = notification.useNotification();
    const [searchMode, setSearchMode] = useState('name');

    const validateSearch = (_, value) => {
        const regex = /^[a-zA-Z0-9 -]*$/;
        if (regex.test(value)) {
          return Promise.resolve();
        }
        return Promise.reject('Only numbers and alphabetic characters"');
      };

      const showError = (type) => {
        api[type]({
          message: 'Error!',
          description:
            'The Threat Actor you want to analyze is invalid.',
        });
      };

      const onFinish = async (values) => {
        try {
            setSpinner(true)
            if (searchMode === 'name' && values.searchText) {
                let res = await axios.get("http://127.0.0.1:3002/threat_actor", {
                params: {
                    name: values["searchText"],
                    type: 'name'
                },
                });
                if(res.status === 200){
                    if(res.data != null){
                        setSpinner(false)
                        setThreat(res.data)
                    }
                }
                // Esegui l'azione di ricerca con il testo inserito
              } else if (searchMode === 'country' && values.selectedCountry) {
                console.log('Selected Country:', values.selectedCountry);
                setSpinner(false)
                // Esegui l'azione di ricerca con il paese selezionato
              }
        } catch (error) {
            setSpinner(false)
            showError('error')
        }
      };
      const onFinishFailed = (errorInfo) => {
        setSpinner(false)
      };
      const handleModeChange = (e) => {
        setSearchMode(e.target.value);
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
            <div>
                <Form
                    form={form}
                    layout="vertical"
                    onFinish={onFinish}
                    onFinishFailed={onFinishFailed}
                >
                <Row ustify="center">
                    <Col xs={24} sm={24} md={24} lg={24}>
                        <Form.Item
                            name="searchMode"
                            label="Search Mode"
                        >
                        <Radio.Group onChange={handleModeChange} value={searchMode} defaultValue={"name"}>
                            <Radio value="name" >By Name</Radio>
                            <Radio value="country" disabled>By Country</Radio>
                        </Radio.Group>
                        </Form.Item>
                    </Col>
                </Row>
                {searchMode === 'name' && (
                    <Row justify="center">
                        <Col xs={24} sm={24} md={24} lg={24}>
                        <Form.Item
                            name="searchText"
                            label="Search by Name"
                            rules={[{ required: true, message: 'Please enter a search term' }, { validator: validateSearch }]}
                        >
                            <Input placeholder="Enter a known Threat Actor name" />
                        </Form.Item>
                        </Col>
                    </Row>
                )}
                {searchMode === 'country' && (
                    <Row justify="center">
                        <Col xs={24} sm={24} md={24} lg={24}>
                        <Form.Item
                            name="selectedCountry"
                            label="Search by Country"
                            rules={[{ required: true, message: 'Please select a country' }]}
                        >
                            <Select placeholder="Choose a country">
                            {countries.map((country) => (
                                <Option key={country} value={country}>
                                {country}
                                </Option>
                            ))}
                            </Select>
                        </Form.Item>
                        </Col>
                    </Row>
                )}
                <Row justify="center">
                <Col xs={24} sm={24} md={24} lg={24}>
                    <Form.Item>
                    <Button type="primary" htmlType="submit" style={{ width: '100%' }}>
                        Search
                    </Button>
                    </Form.Item>
                </Col>
                </Row>
            </Form>
            </div>
        )}  
        </>
    );
};

export default SearchThreat;
