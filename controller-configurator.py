from ssl import SSLCertVerificationError
import requests
import urllib3
import time
import json
from getpass import getpass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

####### neet to change it #######
CONTROLLER_FQDN="https://nginxcontroller.westeurope.cloudapp.azure.com"

def main_procedure():
    session = auth_controller()
    app_name = input("\nEnter the new APP name, and press Enter: ")
    gw_name = f"{app_name}-gw"
    instance_group = input("\nChoose the instance group, and press Enter: \n1: Test \n2: Prod \n")
    match instance_group:
        case "1":
            instance_group = "david-test"
            environment = "test"
            print("You choosed TEST\n")
        case "2":
            instance_group = "david-test"
            environment = "prod"
            print("You choosed PROD\n")
    cert_choosen = get_cert(CONTROLLER_FQDN,session,environment)
    hostname = input("\nEnter the APP URL (GW hostname) , and press Enter: ")
    backed_url = input("\nEnter the backend URL, and press Enter: ")
    create_gw(session,hostname,gw_name,instance_group,environment,cert_choosen)
    time.sleep(5)
    create_app(session,app_name,environment)
    time.sleep(5)
    create_comp(session,app_name,gw_name,environment,backed_url)
    print("\nDONE!!!")

### Login to Controller                                 
def auth_controller():
    user = input("Enter username: ")
    passd = getpass("Enter password: ")

    endpoint = f"{CONTROLLER_FQDN}/api/v1/platform/login"
    payload = {
        "credentials": {
            "type": "BASIC",
            "username": user,
            "password": passd
        }
    }
    payload=json.dumps(payload)
    headers = { 'content-type': "application/json" }
    session = requests.session()
    response = session.post(endpoint, data=payload, headers=headers, verify=False)
    if (200 <= response.status_code <= 210):
        print("login successful")
    else:
        print("Try to login again.....")
        quit()
    return session

### create new GW
def create_gw(session,hostname,gw_name,instance_group,environment,cert_choosen):

    ### payload to submit
    payload = {
      "metadata": {
        "name": gw_name,
        "tags": []
      },
      "desiredState": {
        "ingress": {
          "uris": {
            hostname: {}
          },
          "placement": {
            "instanceGroupRefs": [
              {
                "ref": "/infrastructure/instance-groups/"f"{instance_group}"
              }
            ]
          },
          "tls": {
            "certRef": {
              "ref": cert_choosen
            },
            "preferServerCipher": "DISABLED"
          }
        },
        "configSnippets": {
          "httpSnippet": {
            "directives": [
              {
                "directive": "log_format",
                "args": [
                  "syslog-adasha",
                  "\"@timestamp\"=\"$time_iso8601\",",
                  "\"@source\"=\"$server_addr\",",
                  "\"hostname\"=\"$hostname\",",
                  "\"ip\"=\"$http_x_forwarded_for\",",
                  "\"client\"=\"$remote_addr\",",
                  "\"request_method\"=\"$request_method\",",
                  "\"scheme\"=\"$scheme\",",
                  "\"domain\"=\"$server_name\",",
                  "\"referer\"=\"$http_referer\",",
                  "\"request\"=\"$request_uri\",",
                  "\"args\"=\"$args\",",
                  "\"size\"=$body_bytes_sent,",
                  "\"status\"= $status,",
                  "\"responsetime\"=$request_time,",
                  "\"upstreamtime\"=\"$upstream_response_time\",",
                  "\"upstreamaddr\"=\"$upstream_addr\",",
                  "\"http_user_agent\"=\"$http_user_agent\",",
                  "\"https\"=\"$https\""
                ]
              }
            ]
          }
        }
      }
    }
    headers = { 'content-type': "application/json" }
    endpoint = f"{CONTROLLER_FQDN}/api/v1/services/environments/{environment}/gateways"
    payload=json.dumps(payload)
    response = session.post(endpoint, data=payload, headers=headers, verify=False)
    if (200 <= response.status_code <= 210):
        print("OK - GW created")
    else:
        print("bad GW config")
        exit()


### create new App
def create_app(session,app_name,environment):
    payload = {
    "metadata": {
        "name": app_name,
        "tags": []
    },
    "desiredState": {}
        }
    headers = { 'content-type': "application/json" }
    endpoint = f"{CONTROLLER_FQDN}/api/v1/services/environments/{environment}/apps"
    payload=json.dumps(payload)
    response = session.post(endpoint, data=payload, headers=headers, verify=False)
    if (200 <= response.status_code <= 210):
        print("OK - APP created")
    else:
        print("bad APP config") 
        exit()   

### create new Component
def create_comp(session,app_name,gw_name,environment,backed_url):
    payload = {
  "metadata": {
    "name": f"{app_name}-component",
    "tags": []
  },
  "desiredState": {
    "ingress": {
      "gatewayRefs": [
        {
          "ref": "/services/environments/"f"{environment}/gateways/{gw_name}"
        }
      ],
      "uris": {
        "/": {}
      }
    },
    "backend": {
      "ntlmAuthentication": "DISABLED",
      "preserveHostHeader": "DISABLED",
      "workloadGroups": {
        f"{app_name}-wl": {
          "loadBalancingMethod": {
            "type": "ROUND_ROBIN"
          },
          "uris": {
            backed_url: {
              "isBackup": False,
              "isDown": False,
              "isDrain": False
            }
          },
          "useServerPort": "DISABLED"
        }
      }
    },
    "logging": {
      "errorLog": "DISABLED",
      "accessLog": {
        "state": "DISABLED"
      }
    },
    "configSnippets": {
      "uriSnippets": [
        {
          "directives": [
            {
              "directive": "#",
              "args": [
                " Send WAF logs to Grafana"
              ]
            },
            {
              "directive": "access_log",
              "args": [
                "syslog:server=172.17.0.1:515",
                "syslog-adasha"
              ]
            }
          ]
        }
      ]
    },
    "security": {
      "strategyRef": {
        "ref": "/security/strategies/default-xff-strategy"
      },
      "waf": {
        "isEnabled": True
      }
    }
  }
}

    headers = { 'content-type': "application/json" }
    endpoint = f"{CONTROLLER_FQDN}/api/v1/services/environments/{environment}/apps/{app_name}/components"
    payload=json.dumps(payload)
    response = session.post(endpoint, data=payload, headers=headers, verify=False)
    if (200 <= response.status_code <= 210):
        print("OK - Component created")
    else:
        print("bad Component config")
        exit()

def get_cert(CONTROLLER_FQDN,session,environment):
    headers = { 'content-type': "application/json" }
    endpoint = f"{CONTROLLER_FQDN}/api/v1/services/environments/{environment}/certs"
    response = session.get(endpoint,  headers=headers, verify=False).json()
    json_data = response['items']
    item = len(json_data)
    certs = []
    cert_link = []
    while item !=0:
      json_data = response['items'][item-1]['currentStatus']['certMetadata'][0]
      json_data2 = response['items'][item-1]['metadata']['links']
      for key, value in json_data.items():
          if key == 'commonName':
            certs.append(value)
      for key, value in json_data2.items():
          if key == 'rel':
            cert_link.append(value)
      item = item -1

    print("Choose the CERT from the list, and press Enter: ")
    x = 0
    for y in certs:
      x = x + 1
      print(x,":",y)
    cert_choosen = input()
    #cert_choosen = input("Choose the CERT from the list, and press Enter:")
    cert_choosen = int(cert_choosen)-1
    cert_position = cert_link[int(cert_choosen)]
    cert_position = cert_position.replace("/api/v1","")
    return(cert_position)

main_procedure()
