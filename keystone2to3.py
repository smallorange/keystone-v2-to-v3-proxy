from flask import Flask, request, Response
from flask import jsonify
import requests
import json
#import urllib3

app = Flask(__name__)


@app.route('/v2.0/tokens', methods=['POST'])
def identity_tokens():
    header = request.headers
    jsonbody = request.get_json()
    print(header)
    print(jsonbody)
    v3body = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": jsonbody['auth']['passwordCredentials']['username'],
                        "domain": {
                            "name": "Default"
                        },
                        "password": jsonbody['auth']['passwordCredentials']['password'],
                    }
                }
            },
            "scope": {
                "project": {
                    "domain": {
                        "name": "default"
                    },
                    "id": jsonbody['auth']['tenantId']
                }
            }
        }
    }
    if request.method == 'POST':

        r = requests.post(url='http://10.203.1.12:5001/v3/auth/tokens', json=v3body)
        v3resp = r.json()
        print(r.status_code)
        roles = []
        role_ids = []
        for i in v3resp.get('token').get('roles'):
            roles.append({'name': i.get('name')})
            role_ids.append(i.get('id'))
        endpointList = []
        for cat in v3resp.get('token').get('catalog'):
            item = {
                "endpoints": [],
                "endpoints_links": [],
                "type": None,
                "name": None
            }
            item['type'] = cat.get('type')
            item['name'] = cat.get('name')
            tmpitem = dict()
            for i in cat.get('endpoints'):
                tmpitem['region'] = i.get('region_id')
                if i.get('interface') == 'public':
                    tmpitem['publicURL'] = i.get('url')
                elif i.get('interface') == 'admin':
                    tmpitem['adminURL'] = i.get('url')
                elif i.get('interface') == 'internal':
                    tmpitem['internalURL'] = i.get('url')
            tmpitem['id'] = '7088995'
            item['endpoints'].append(tmpitem)
            endpointList.append(item)
            del(tmpitem)
        print(endpointList)
        v2response = {
            "access": {
                "token": {
                    "issued_at": v3resp.get('token').get('issued_at'),
                    "expires": v3resp.get('token').get('expires_at'),
                    "id": r.headers.get('X-Subject-Token'),
                    "tenant": {
                        "description": None,
                        "enabled": True,
                        "id": v3resp['token']['project']['id'],
                        "name": "admin"
                    }
                },
                "serviceCatalog": endpointList,
                "user": {
                    "username": v3resp['token']['user']['name'],
                    "roles_links": [],
                    "id": v3resp['token']['user']['id'],
                    "roles": roles,
                    "name": v3resp['token']['user']['id']
                },
                "metadata": {
                    "is_admin": 0,
                    "roles": role_ids,
                }
            }
        }
        response = app.response_class(
            response=json.dumps(v2response),
            status=r.status_code,
            mimetype='application/json'
        )
        response.headers['X-Auth-Token'] = r.headers.get('X-Subject-Token')
        for i in r.headers.items():
            (key, value) = i
            if key != 'Content-Length' and key != 'Keep-Alive'and key != 'Connection':
                print("key: {} value: {}".format(key, value))
                response.headers[key] = value
    return response


def dup_header(dst, src):
    for i in src.items():
            (key, value) = i
            if key != 'Content-Length' and key != 'Keep-Alive'and key != 'Connection':
                print("key: {} value: {}".format(key, value))
                dst[key] = value


@app.route('/', defaults={'path': ''}, methods=['POST', 'GET', 'PUT', 'DELETE', 'PATCH', 'HEAD'])
@app.route('/<path:path>',  methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'])
def catch_all(path):
    if request.method == 'POST':
        body = request.get_json()
        sendHeader = dict()
        dup_header(sendHeader, request.headers)
        url = 'http://10.203.1.12:5001{}'.format(request.path)
        r = requests.post(url=url, headers=sendHeader, json=body)
        header = dict()
        dup_header(header, r.headers)
        response = app.response_class(
            response=json.dumps(r.json()),
            status=r.status_code,
            mimetype='application/json'
        )
        response.headers = header
        del(sendHeader)
        del(header)
    elif request.method == 'GET':
        sendHeader = dict()
        dup_header(sendHeader, request.headers)
        url = 'http://10.203.1.12:5001{}'.format(request.path)
        r = requests.get(url=url, headers=sendHeader)
        header = dict()
        dup_header(header, r.headers)
        response = app.response_class(
            response=json.dumps(r.json()),
            status=r.status_code,
            mimetype='application/json'
        )
        response.headers = header
        del(sendHeader)
        del(header)
    elif request.method == 'HEAD' or request.method == 'DELETE':
        sendHeader = dict()
        dup_header(sendHeader, request.headers)
        url = 'http://10.203.1.12:5001{}'.format(request.path)
        if request.method == 'HEAD':
            r = requests.head(url=url, headers=sendHeader)
        else:
            r = requests.delete(url=url, headers=sendHeader)
        header = dict()
        dup_header(header, r.headers)
        response = app.response_class(status=r.status_code)
        response.headers = header
        del(sendHeader)
        del(header)
    elif request.method == 'PUT':
        pass
    return response


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
