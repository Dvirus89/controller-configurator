from ssl import SSLCertVerificationError
import requests
import urllib3
import time
import json
from getpass import getpass
import PySimpleGUI as sg

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

####### neet to change it #######
CONTROLLER_FQDN="https://nginxcontroller.westeurope.cloudapp.azure.com"

def main_procedure():
  session = auth_controller()
  app_name = get_app_name()
  gw_name = f"{app_name}-gw"
  instance_group = get_instance_group()
  if instance_group == '1':
    ####### neet to change it #######
    instance_group = "david-test"
    environment = "test"
  elif instance_group == '2':
    ####### neet to change it #######
    instance_group = "david-test"
    environment = "prod"
  cert_choosen = get_cert(CONTROLLER_FQDN,session,environment)
  hostname,backed_url = hostname_backed_url()
  create_gw(session,hostname,gw_name,instance_group,environment,cert_choosen)
  time.sleep(5)
  create_app(session,app_name,environment)
  time.sleep(5)
  create_comp(session,app_name,gw_name,environment,backed_url)
  progress_bar('4', '4', 'DONE!!!')
  time.sleep(3)

def progress_bar(x,y,status_update):
  font = ("Arial", 14)
  sg.theme('GreenMono')  # please make your windows colorful
  column_to_be_centered = [[sg.Text('Configuring', key='status',font=font)],
                          [sg.ProgressBar(1, orientation='h', size=(40, 30), key='progress')],]
  layout = [[sg.VPush()],
            [sg.Push(), sg.Column(column_to_be_centered,element_justification='c'), sg.Push()],
            [sg.VPush()]]
  window = sg.Window('Controller Configurator', layout).Finalize()
  progress_bar = window['progress']
  status = window['status']
  if x == '0' and y == '0': ### BAD config
    print("BAD")
    status.update(status_update)
    progress_bar.update(visible=False)
  else:  ### GOOD config
    status.update(status_update)
    progress_bar.update(x, y)

def get_app_name():
  font = ("Arial", 14)
  font2 = ("Arial", 12)
  sg.theme('GreenMono')  # please make your windows colorful
  layout = [[sg.Text('Enter the new APP name, and press Enter:',font=font)],
            [sg.Text('', size=(0, 0), font=font), sg.InputText(key='app_name', font=font2)],
            [sg.Submit(font=font2), sg.Exit(font=font2)]]
  window = sg.Window('Controller Configurator', layout, finalize=True)
  event, values = window.read()
  app_name = values['app_name']
  window.Close()
  return app_name

def get_instance_group():
  font = ("Arial", 14)
  sg.theme('GreenMono')  # please make your windows colorful
  layout = [[sg.Text('Choose the instance group, and press Enter:', font=font)],
            [sg.Text('1: Test', font=font)],
            [sg.Text('2: Prod', font=font)],
            [sg.Text('', size=(0, 1), font=font), sg.InputText(key='instance_group', font=font)],
            [sg.Submit(), sg.Exit()]]
  window = sg.Window('Controller Configurator', layout, finalize=True)
  event, values = window.read()
  instance_group = values['instance_group']
  window.Close()
  return instance_group

def hostname_backed_url():
  font = ("Arial", 14)
  font2 = ("Arial", 12)
  sg.theme('GreenMono')  # please make your windows colorful
  layout = [[sg.Text('Enter the APP URL (GW hostname) , and press Enter:', font=font)],
            [sg.Text('', size=(0, 0), font=font), sg.InputText(key='hostname', font=font2)],
            [sg.Text('Enter the backend URL, and press Enter:', font=font)],
            [sg.Text('', size=(0, 0), font=font), sg.InputText(key='backed_url', font=font2)],
            [sg.Submit(), sg.Exit()]]
  window = sg.Window('Controller Configurator', layout, finalize=True)
  event, values = window.read()
  hostname = values['hostname']
  backed_url = values['backed_url']
  window.close()
  return hostname,backed_url

### Login to Controller                                 
def auth_controller():
    font1 = ("Arial", 14)
    font2 = ("Arial", 12)
    hex_color_code = ''
    sg.theme('GreenMono')  # please make your windows colorful
    layout1 = [[sg.pin(sg.Text('Enter your user and password:',font=font1))],
          [sg.Text('User:', size=(10),font=font2), sg.InputText(key='user',font=font2)],
          [sg.Text('Password: ', size=(10),font=font2), sg.InputText('', key='passd', password_char='*', font=font2)],
          [sg.StatusBar('', size=10, expand_x=True, key='Status',font=font2, background_color='light gray')],
          [sg.Submit(font=font2), sg.Exit(font=font2)]]
    window = sg.Window('Controller Configurator', layout1, finalize=True, enable_close_attempted_event=True)
    window['Status'].my_bg = sg.theme_text_element_background_color()
    status = window['Status']
    event, values = window.read()
    user = values['user']
    passd = values['passd']
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
        status.update("login successful")
        window['Status'].update(background_color='green')
        window.refresh()
        time.sleep(1)
        window.close()
    else:
        status.update("Try to login again.....")
        window['Status'].update(background_color='red')
        window.refresh()
        time.sleep(3)
        window.close()
        exit()

    return session

### create new GW
def create_gw(session,hostname,gw_name,instance_group,environment,cert_choosen):
    #print("hostname",hostname)
    #print("gw_name",gw_name)
    #print("instance_group",instance_group)
    #print("environment",environment)
    #print("cert_choosen",cert_choosen)
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
      status_update = "OK - GW created"
      progress_bar(1, 4,status_update)
      time.sleep(5)
    else:
      status_update = "bad GW config"
      progress_bar('0', '0', status_update)
      time.sleep(5)
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
    status_update = 'OK - APP created'
    progress_bar(2, 4,status_update)
    time.sleep(5)
  else:
    status_update = "bad APP config"
    progress_bar('0', '0', status_update)
    time.sleep(5)
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
      status_update = 'OK - Component created'
      progress_bar(3, 4, status_update)
      time.sleep(5)
    else:
      status_update = 'bad Component config'
      progress_bar('0', '0', status_update)
      time.sleep(5)
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
  font = ("Arial", 14)
  font2 = ("Arial", 12)
  sg.theme('GreenMono')  # please make your windows colorful
  layout = [[sg.Text('Choose the CERT from the list, and press Enter:', font=font)],
            [sg.Combo(certs, enable_events=True, key='CERT', font=font)]]
  window = sg.Window('Controller Configurator', layout)
  event, values = window.Read()
  cert_choosen = values['CERT']
  window.Close()
  cert_position = certs.index(cert_choosen)
  cert_position = cert_link[int(cert_position)]
  cert_position = cert_position.replace("/api/v1","")
  return cert_position

main_procedure()
