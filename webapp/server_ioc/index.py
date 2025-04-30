from flask import Flask,redirect,request,url_for,Response,make_response,jsonify
from flask_cors import CORS
import re
import os
from dotenv import load_dotenv
from classes.domain import DOMAIN
from classes.ip import IP
from classes.hash import HASH
from handle_ioc import IoCGraph

load_dotenv()
neo4j_uri = os.getenv('NEO4J_URI')
neo4j_username = os.getenv('NEO4J_USERNAME')
neo4j_password = os.getenv('NEO4J_PASSWORD')

app = Flask(__name__)
CORS(app,origins=["http://localhost:3000"])
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

@app.route('/ioc', methods=['GET'])
def get_ioc():
    ioc = request.args.get('ioc')
    if ioc != None and ioc != "":
        ioc_clean= "".join(ioc.split())
        ip_pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        md5_pattern = r'^[a-fA-F0-9]{32}$'
        sha1_pattern = r'^[a-fA-F0-9]{40}$'
        sha256_pattern = r'^[a-fA-F0-9]{64}$'
        if re.match(ip_pattern, ioc_clean):
            cyberGraph = IoCGraph(neo4j_uri, neo4j_username, neo4j_password)
            res = cyberGraph.get_ip(ioc_clean)
            if res != None:
                cyberGraph.close()
                return res, 200
            else:
                ip_analyzed = IP(ioc_clean)
                if ip_analyzed.__dict__.get('is_public') != None:
                    cyberGraph.handle_ip(ip_analyzed.__dict__,False)
            cyberGraph.close()
            return ip_analyzed.__dict__, 200
        elif re.match(domain_pattern, ioc_clean):
            
            cyberGraph = IoCGraph(neo4j_uri, neo4j_username, neo4j_password)
            res = cyberGraph.get_domain(ioc_clean)
            if res != None:
                cyberGraph.close()                
                return res, 200
            else:
                domain_analyzed = DOMAIN(ioc_clean)
                if domain_analyzed.__dict__.get('domain') != None:
                    cyberGraph.handle_domain(domain_analyzed.__dict__,False)
            cyberGraph.close()
            print("\n \n "+str(domain_analyzed.__dict__)+"\n \n")
            return domain_analyzed.__dict__, 200
        elif re.match(md5_pattern, ioc_clean) or re.match(sha256_pattern, ioc_clean) or re.match(sha1_pattern, ioc_clean):
            cyberGraph = IoCGraph(neo4j_uri, neo4j_username, neo4j_password)
            res = cyberGraph.get_hash(ioc_clean)
            if res != None:
                cyberGraph.close()
                return res, 200
            else:
                hash_analyzed = HASH(ioc_clean)
                if hash_analyzed.__dict__.get('hash') != None:
                    cyberGraph.handle_hash(hash_analyzed.__dict__)
                res = cyberGraph.get_hash(ioc_clean)
            cyberGraph.close()
            return res, 200
        else:
            return Response(status=400)
    else:
        return Response(status=400)

@app.route('/threat_actor', methods=['GET'])
def get_threat_actor():
    threat_actor = request.args.get('name')
    if threat_actor != None and threat_actor != "":
        cyberGraph = IoCGraph(neo4j_uri, neo4j_username, neo4j_password)
        res = cyberGraph.get_threat_actor(threat_actor)
        if res != None:
            cyberGraph.close()
            return res, 200
        else:
            return {'found':False}, 200
    else:
        return Response(status=400)
    
@app.route('/vulnerability', methods=['GET'])
def get_vulnerability():
    vulnerability = request.args.get('cveId')
    if vulnerability != None and vulnerability != "":
        cyberGraph = IoCGraph(neo4j_uri, neo4j_username, neo4j_password)
        res = cyberGraph.get_vulnerability(vulnerability)
        if res != None:
            cyberGraph.close()
            return res, 200
        else:
            return {'found':False}, 200
    else:
        return Response(status=400)
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3002, debug=True)