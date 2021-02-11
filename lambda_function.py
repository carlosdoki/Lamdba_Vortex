import json
import boto3
import botocore
import logging
import array as arr
from random import randint
from resources import *
from restClient import FMCRestClient


def setup_logging(debug_disabled):
    """
    Purpose:    Sets up logging behavior for the Autoscale Manager
    Parameters: User input to disable debug logs
    Returns:    logger object
    Raises:
    """
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.INFO)
    logger = logging.getLogger()
    for h in logger.handlers:
        logger.removeHandler(h)
    h = logging.StreamHandler(sys.stdout)
    log_format = '%(levelname)s [%(asctime)s] (%(funcName)s)# %(message)s'
    h.setFormatter(logging.Formatter(log_format))
    logger.addHandler(h)
    logger.setLevel(logging.DEBUG)
    if debug_disabled:
        logging.disable(logging.DEBUG)
    return logger


def ipRange(start_ip, end_ip):
    # print("\n Inside iprange() def ")
    start = list(map(int, start_ip.split(".")))
    end = list(map(int, end_ip.split(".")))
    temp = start
    ip_range = []
    ip_range.append(start_ip)
    while temp != end:
        start[3] += 1
        for i in (3, 2, 1):
            if temp[i] == 256:
                temp[i] = 0
                temp[i-1] += 1
        ip_range.append(".".join(map(str, temp)))
    return ip_range


def ipRangeByCount(start_ip, total_ip):
    # print("\n Inside iprange() def ")
    start = list(map(int, start_ip.split(".")))
    temp = start
    ip_range = []
    ip_range.append(start_ip)
    i = 0
    while i < total_ip:
        ip_range.append(".".join(map(str, temp)))
        start[3] += 1
        for j in (3, 2, 1):
            if temp[j] == 256:
                temp[j] = 0
                temp[j-1] += 1
        i += 1
    return ip_range


def create(self, resource):
    # print("create called")
    url_path = resource.get_api_path()
    post_data = resource.json(pretty=False)
    json_resp = self.post(url_path, post_data)
    resource.json_load(json_resp)
    return resource


def deleteNWobjects(nwObjName):
    print("delete NW oBJ")
    try:
        rest_client = FMCRestClient('https://100.26.48.221', 'api', '<senha>')
        url_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/hosts?filter=nameOrValue%3A" + nwObjName
        json_resp = rest_client.get(url_path)
        _id = json_resp['items'][0]['id']
        url_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/hosts/" + _id
        json_resp = rest_client.delete(url_path)
    except Exception as e:
        print("Exception:\n")
        print(e.__class__)


def createNWobjects(nwObjCount, nwObjName, first_nwObjvalue, last_nwObjvalue=None):
    print("create NW oBJ")
    nwObj_dict = {}
    iprange = []
    rest_client = FMCRestClient('https://100.26.48.221', 'api', '<senha>')

    if last_nwObjvalue:
        iprange = ipRange(first_nwObjvalue, last_nwObjvalue)
    else:
        iprange = ipRangeByCount(first_nwObjvalue, nwObjCount)
    for i in range(1, nwObjCount+1):
        key = nwObjName
        ip_index = i % len(iprange)
        print("ipRange[i]", iprange[ip_index])
        value = str(iprange[ip_index])
        if rest_client:
            try:
                rest_client.create(Host(key, value))
            except Exception as e:
                if(str(e) == "name-exists"):
                    print("\nObject already Exists in FMC\n")


def modifyNWGroup(ip, _group):
    try:
        rest_client = FMCRestClient('https://100.26.48.221', 'api', '<senha>')
        url_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups?filter=nameOrValue%3A" + _group
        json_resp = rest_client.get(url_path)
        _idGroup = json_resp['items'][0]['id']

        url_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups/" + _idGroup
        json_resp = rest_client.get(url_path)
        _objects = ""
        for key in json_resp['objects']:
            if _objects != "":
                _objects = _objects + ","
            _objects = _objects + \
                "{ \"type\": \"" + key['type'] + "\", \"id\": \"" + \
                key['id'] + "\", \"name\": \"" + key['name'] + "\"}"

        url_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/hosts?filter=nameOrValue%3A" + ip
        json_resp = rest_client.get(url_path)
        _id = json_resp['items'][0]['id']
        _name = json_resp['items'][0]['name']
        url_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups/" + _idGroup
        _objects = _objects + \
            ", { \"type\": \"Host\", \"id\": \"" + \
            _id + "\", \"name\": \"" + _name + "\"}"
        post_data = {"objects": [
            _objects
        ],
            "type": "NetworkGroup",
            "id": _idGroup,
            "name": _group
        }
        _teste = str(post_data).replace("'", "\"").replace(
            "True", "true").replace("\"{", "{").replace("}\"", "}")
        json_resp = rest_client.put(url_path, _teste)
    except Exception as e:
        print("Exception:\n")
        print(e.__class__)


def deleteNWGroup(_inst, _group):
    try:
        rest_client = FMCRestClient('https://100.26.48.221', 'api', '<senha>')
        url_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups?filter=nameOrValue%3A" + _group
        json_resp = rest_client.get(url_path)
        _idGroup = json_resp['items'][0]['id']

        url_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/networkgroups/" + _idGroup
        json_resp = rest_client.get(url_path)
        _objects = ""
        for key in json_resp['objects']:
            if _inst not in key['name']:
                if _objects != "":
                    _objects = _objects + ","

                _objects = _objects + \
                    "{ \"type\": \"" + key['type'] + "\", \"id\": \"" + \
                    key['id'] + "\", \"name\": \"" + key['name'] + "\"}"

        post_data = {"objects": [
            _objects
        ],
            "type": "NetworkGroup",
            "id": _idGroup,
            "name": _group
        }
        _teste = str(post_data).replace("'", "\"").replace(
            "True", "true").replace("\"{", "{").replace("}\"", "}")
        json_resp = rest_client.put(url_path, _teste)
    except Exception as e:
        print("Exception:\n")
        print(e.__class__)


def start_deployment():
    """
    Purpose:    Deploys policy changes on device
    Parameters: Device name
    Returns:    Task Id
    Raises:
    """
    print("Start Deployment")
    try:
        rest_client = FMCRestClient('https://100.26.48.221', 'api', '<senha>')

        url_path = "/api/fmc_platform/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/audit/auditrecords"
        json_resp = rest_client.get(url_path)

        _version = json_resp['items'][0]['time']*1000

        url_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deployabledevices"
        json_resp = rest_client.get(url_path)
        _name = ""

        for key in json_resp['items']:
            if _name != "":
                _name = _name + ", \"" + key['name'] + "\""
            else:
                _name = "\"" + key['name'] + "\""

        url_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/devices/devicerecords?offset=0&limit=10000"
        json_resp = rest_client.get(url_path)

        a = []
        # if 'items' in json_resp.json():
        for key in json_resp['items']:
            print('******************')
            print(key)
            if key['name'] in _name:
                a.append(key['id'])

        url_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/deployment/deploymentrequests"
        post_data = {
            "type": "DeploymentRequest",
            "version": str(_version),
            "forceDeploy": True,
            "ignoreWarning": True,
            "deviceList": a
        }

        _teste = str(post_data).replace("'", "\"").replace("True", "true")
        json_resp = rest_client.post(url_path, _teste)
        print(json_resp)
        # if 'type' in json_resp.json():
        #     if json_resp.json()['type'] == 'DeploymentRequest':
        #         return json_resp.json()['metadata']['task']['id']
        # return ''
    except Exception as e:
        print("Exception:\n")
        print(e.__class__)


def get_instance_name(fid):
    # When given an instance ID as str e.g. 'i-1234567', return the instance 'Name' from the name tag.
    ec2 = boto3.resource('ec2')
    ec2instance = ec2.Instance(fid)
    print(ec2instance)
    instancename = ''
    groupName = ''
    for tags in ec2instance.tags:
        if tags["Key"] == 'FMC_Object_Name':
            instancename = tags["Value"]
        if tags["Key"] == 'FMC_Group':
            groupName = tags["Value"]
    return instancename, groupName


def get_instance_ip(fid):
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances(InstanceIds=[fid])
    ip = ""
    for x in response["Reservations"]:
        ip = x["Instances"][0]['PrivateIpAddress']
    return ip


def lambda_handler(event, context):
    d1 = json.dumps(event)
    data = json.loads(d1)
# if __name__ == "__main__":
#     # logger = setup_logging(utl.e_var['DebugDisable'])

#     event = """
# { "version": "0",
#   "id": "618bf007-5f4c-2a68-79b1-e48c5c04c857",
#   "detail-type": "EC2 Instance State-change Notification",
#   "source": "aws.ec2",
#   "account": "379464126793",
#   "time": "2021-02-09T10:50:26Z",
#   "region": "us-east-1",
#   "resources": [
#     "arn:aws:ec2:us-east-1:379464126793:instance/"
#     ],
#   "detail":
#     {"instance-id": "",
#      "state": "shutting"
#     }
# }
# """
#     data = json.loads(event)
    _inst, _group = get_instance_name(data['detail']['instance-id'])
    if _inst != '':
        ip = get_instance_ip(data['detail']['instance-id'])

        if (data['detail']['state'] == "pending"):
            try:
                ec2_elb_client = boto3.client('elbv2')
                ec2_elb_client.register_targets(
                    TargetGroupArn='<loadBalanceInterno_ARN_Group',
                    Targets=[
                        {
                            'Id': ip,
                            'Port': 80
                        },
                    ],
                )
                createNWobjects(1, _inst, ip)
                modifyNWGroup(ip, _group)
            except botocore.exceptions.ClientError as e:
                print("Error registering the target: {}".format(
                    e.response['Error']))
            except Exception as e:
                print(e.__class__)

        else:
            try:
                ec2_elb_client = boto3.client('elbv2')
                ec2_elb_client.deregister_targets(
                    TargetGroupArn='<loadBalanceInterno_ARN_Group',
                    Targets=[
                        {
                            'Id': ip,
                            'Port': 80
                        },
                    ],
                )
                deleteNWGroup(_inst, _group)
                deleteNWobjects(ip)
            except Exception as e:
                print(e.__class__)

        start_deployment()
