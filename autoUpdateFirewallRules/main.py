import datetime
import requests
import hashlib, hmac, json, time

class config:
    ApiDomain = "lighthouse.tencentcloudapi.com"
    secretId = ""
    secretKey = ""

    # 需要更新的轻量实例ID
    InstanceId = []

    IPListURL = ""

    sleepTime = 86400

    pushMsgOpen = 0
    workWxWebHook =  ""

def LoadingConfig():
    """
    加载配置文件
    """
    f = open("config.json", "r",encoding="utf-8")
    configStr = f.read()
    f.close()
    try:
        configJson = json.loads(configStr)
    except Exception as e:
        logShow("配置文件格式错误，请检查config.json","ERROR")
        exit()
    config.ApiDomain = configJson["ApiDomain"]
    config.secretId = configJson["secretId"]
    config.secretKey = configJson["secretKey"]
    config.InstanceId = configJson["InstanceId"]
    config.IPListURL = configJson["IPListURL"]
    config.sleepTime = configJson["sleepTime"]
    config.pushMsgOpen = configJson["pushMsgOpen"]
    config.workWxWebHook = configJson["workWxWebHook"]
    logShow("配置文件加载成功")

def qcloud_v3_post(SecretId,SecretKey,Service,bodyArray,headersArray):
    HTTPRequestMethod = "POST"
    CanonicalURI = "/"
    CanonicalQueryString = ""
    # 按 ASCII 升序进行排序
    headersArray = dict(sorted(headersArray.items(), key=lambda x: x[0]))
    sortHeadersArray = headersArray
    
    SignedHeaders = ""
    CanonicalHeaders = ""
    
    # 拼接键
    for key in list(sortHeadersArray.keys()):
        SignedHeaders += key.lower() + ";"
    if SignedHeaders[-1] == ";":
        SignedHeaders = SignedHeaders[:-1]
    
    # 拼接键
    for key in list(sortHeadersArray.keys()):
        CanonicalHeaders += key.lower() + ":" + sortHeadersArray[key].lower() + "\n"
    
    # 如果遇到报错，把`ensure_ascii=False`删除
    # HashedRequestPayload = hashlib.sha256(bytes(json.dumps(bodyArray),encoding="utf-8")).hexdigest()
    HashedRequestPayload = hashlib.sha256(bytes(json.dumps(bodyArray,ensure_ascii=False),encoding="utf-8")).hexdigest()

    CanonicalRequest = HTTPRequestMethod + "\n" + CanonicalURI + "\n" + CanonicalQueryString + "\n" + CanonicalHeaders + "\n" + SignedHeaders + "\n" + HashedRequestPayload
    
    # ------
    
    # 时间戳
    RequestTimestamp = str(int(time.time()))
    # 获取年月日
    formattedDate = time.strftime("%Y-%m-%d", time.gmtime(int(RequestTimestamp)))
    Algorithm = "TC3-HMAC-SHA256"
    CredentialScope = formattedDate + "/" + Service + "/tc3_request"
    HashedCanonicalRequest = hashlib.sha256(bytes(CanonicalRequest,encoding="utf-8")).hexdigest()
    
    # ------
    
    StringToSign = Algorithm + "\n" + RequestTimestamp + "\n" + CredentialScope + "\n" + HashedCanonicalRequest
    
    _SecretDate = hmac.new(key=bytes("TC3" + SecretKey,encoding="utf-8"),digestmod="sha256")
    _SecretDate.update(bytes(formattedDate,encoding="utf-8"))
    SecretDate = _SecretDate.digest()
    _SecretService = hmac.new(key=SecretDate,digestmod="sha256")
    _SecretService.update(bytes(Service,encoding="utf-8"))
    SecretService = _SecretService.digest()
    _SecretSigning = hmac.new(key=SecretService,digestmod="sha256")
    _SecretSigning.update(bytes("tc3_request",encoding="utf-8"))
    SecretSigning = _SecretSigning.digest()

    _Signature = hmac.new(key=SecretSigning,digestmod="sha256")
    _Signature.update(bytes(StringToSign,encoding="utf-8"))
    Signature = _Signature.hexdigest()
    
    
    Authorization = Algorithm + ' ' + 'Credential=' + SecretId + '/' + CredentialScope + ', ' + 'SignedHeaders=' + SignedHeaders + ', ' + 'Signature=' + Signature
    
    headersArray["X-TC-Timestamp"] = RequestTimestamp
    headersArray["Authorization"] = Authorization
    
    return headersArray

def DescribeRegions():
    """
    获取地域列表
    """
    service = "lighthouse"
    headersPending = {
        'Host': config.ApiDomain,
        'Content-Type': 'application/json',
        'X-TC-Action': 'DescribeRegions',
        'X-TC-Version': '2020-03-24'
    }
    payload = {
    }

    headersSend = qcloud_v3_post(config.secretId,config.secretKey,service,payload,headersPending)
    RegionSetList = []

    r = requests.post("https://"+config.ApiDomain,headers=headersSend,json=payload)
    if r.status_code == 200:
        if "Error" not in r.json()["Response"]:
            for RegionSet in r.json()["Response"]["RegionSet"]:
                RegionSetList.append(RegionSet["Region"])
            logShow("获取地域列表成功：{}".format(RegionSetList))
            return {"code":0,"data": RegionSetList}
        else:
            logShow("获取地域列表失败，错误信息：{}".format(r.json()["Response"]["Error"]),"ERROR")
            return {"code":-1,"data": None}
    else:
        logShow("API状态码非200：{}".format(r.status_code),"ERROR")
        return {"code":-1,"data": None}

def DescribeAllRegionInstance(RegionSetList:list):
    """
    获取所有地域的实例列表
    :param RegionSetList: 地域列表
    :return: {"code":0,"data": InstanceList}
    """
    service = "lighthouse"
    InstanceList = {}
    for Region in RegionSetList:
        headersPending = {
            'Host': config.ApiDomain,
            'Content-Type': 'application/json',
            'X-TC-Action': 'DescribeInstances',
            'X-TC-Version': '2020-03-24',
            'X-TC-Region': Region,
        }
        payload = {
        }

        headersSend = qcloud_v3_post(config.secretId,config.secretKey,service,payload,headersPending)

        r = requests.post("https://"+config.ApiDomain,headers=headersSend,json=payload)
        if r.status_code == 200:
            if "Error" not in r.json()["Response"]:
                logShow("获取 {} 实例列表成功，共有 {} 个实例".format(Region,r.json()["Response"]["TotalCount"]))
                if r.json()["Response"]["InstanceSet"] != []:
                    if Region not in InstanceList:
                        InstanceList[Region] = {}
                    for InstanceInfo in r.json()["Response"]["InstanceSet"]:
                        Instance = {
                            "Region": Region,
                            "Zone": InstanceInfo['Zone'],
                            "CPU": InstanceInfo['CPU'],
                            "Memory": InstanceInfo['Memory'],
                            "InstanceName": InstanceInfo['InstanceName'],
                            "PrivateAddresses": InstanceInfo['PrivateAddresses'],
                            "PublicAddresses": InstanceInfo['PublicAddresses'],
                            "onlyIPv4": True
                        }
                        for PublicAddressesOne in Instance["PublicAddresses"]:
                            if ":" in PublicAddressesOne:
                                Instance["onlyIPv4"] = False
                        InstanceList[Region][InstanceInfo['InstanceId']] = Instance
            else:
                logShow("获取实例列表失败，错误信息：{}".format(r.json()["Response"]["Error"]),"ERROR")
                return {"code":-1,"data": None}
        else:
            logShow("API状态码非200：{}".format(r.status_code),"ERROR")
            return {"code":-1,"data": None}
        time.sleep(0.5)
    logShow("成功获取 {} 个地域中的 {} 个实例".format(len(InstanceList),sum([len(InstanceList[Region]) for Region in InstanceList])))

    return {"code":0,"data": InstanceList}

def CreateFirewallRules(InstanceId:str,FirewallRules:list,Region:str):
    """
    创建防火墙规则

    Args:
        InstanceId (str): 实例ID, 示例:lhins-aglzynfg
        FirewallRules (list): 防火墙规则列表, 示例: 
            [
                {
                    "Protocol": "TCP",
                    "Port": "ALL",
                    "CidrBlock": "0.0.0.0/0",
                    "Action": "ACCEPT",
                    "FirewallRuleDescription":"Automation-Firewall"
                }
            ]
        Region (str): 地域, 示例: ap-beijing

    Returns:
        None

    """
    if FirewallRules == []:
        return {"code":0,"data":None}
    service = "lighthouse"
    headersPending = {
        'Host': config.ApiDomain,
        'Content-Type': 'application/json',
        'X-TC-Action': 'CreateFirewallRules',
        'X-TC-Version': '2020-03-24',
        'X-TC-Region': Region,
    }
    payload = {
        "InstanceId":"",
        "FirewallRules":[]
    }
    payload["InstanceId"] = InstanceId
    payload["FirewallRules"] = FirewallRules

    headersSend = qcloud_v3_post(config.secretId,config.secretKey,service,payload,headersPending)

    r = requests.post("https://"+config.ApiDomain,headers=headersSend,json=payload)
    if r.status_code == 200:
        if "Error" not in r.json()["Response"]:
            logShow("规则添加成功")
            return {"code":0,"data":None}
        else:
            logShow("规则添加失败，错误信息：{}".format(r.json()["Response"]["Error"]),"ERROR")
            return {"code":-1,"data":None}
    else:
        logShow("API状态码非200：{}".format(r.status_code),"ERROR")
        return {"code":-1,"data":None}

def DescribeFirewallRules(InstanceId:str,Region:str):
    """
    查询防火墙规则

    Args:
        InstanceId (str): 实例ID, 示例:lhins-aglzynfg
        Region (str): 地域, 示例: ap-beijing
    Returns:
        None

    """
    service = "lighthouse"
    headersPending = {
        'Host': config.ApiDomain,
        'Content-Type': 'application/json',
        'X-TC-Action': 'DescribeFirewallRules',
        'X-TC-Version': '2020-03-24',
        'X-TC-Region': Region,
    }
    payload = {
        "InstanceId":"",
        "Limit":100
    }
    payload["InstanceId"] = InstanceId

    headersSend = qcloud_v3_post(config.secretId,config.secretKey,service,payload,headersPending)

    r = requests.post("https://"+config.ApiDomain,headers=headersSend,json=payload)
    if r.status_code == 200:
        if "Error" not in r.json()["Response"]:
            logShow("获取防火墙列表成功")
            return {"code":0,"data":r.json()["Response"]["FirewallRuleSet"]}
        else:
            logShow("获取防火墙列表失败，错误信息：{}".format(r.json()["Response"]["Error"]),"ERROR")
            return {"code":-1,"data":None}
    else:
        logShow("API状态码非200：{}".format(r.status_code),"ERROR")
        return {"code":-1,"data":None}

def DeleteFirewallRules(InstanceId:str,FirewallRules:list,Region:str):
    """
    删除防火墙规则
    Args:
        InstanceId (str): 实例ID, 示例:lhins-aglzynfg
        FirewallRules (list): 防火墙规则列表, 示例: 
            [
                {
                    "Protocol": "TCP",
                    "Port": "ALL",
                    "CidrBlock": "0.0.0.0/0",
                    "Action": "ACCEPT",
                    "FirewallRuleDescription":"Automation-Firewall"
                }
            ]
        Region (str): 地域, 示例: ap-beijing
    Returns:
        None
    """
    if FirewallRules == []:
        return {"code":0,"data":None}
    service = "lighthouse"
    headersPending = {
        'Host': config.ApiDomain,
        'Content-Type': 'application/json',
        'X-TC-Action': 'DeleteFirewallRules',
        'X-TC-Version': '2020-03-24',
        'X-TC-Region': Region,
    }
    payload = {
        "InstanceId":"",
        "FirewallRules":[]
    }
    payload["InstanceId"] = InstanceId
    payload["FirewallRules"] = FirewallRules

    headersSend = qcloud_v3_post(config.secretId,config.secretKey,service,payload,headersPending)

    r = requests.post("https://"+config.ApiDomain,headers=headersSend,json=payload)
    if r.status_code == 200:
        if "Error" not in r.json()["Response"]:
            logShow("规则删除成功")
            return {"code":0,"data":None}
        else:
            logShow("规则删除失败，错误信息：{}".format(r.json()["Response"]["Error"]),"ERROR")
    else:
        logShow("API状态码非200：{}".format(r.status_code),"ERROR")

def GetIpList():
    """
    获取白名单IP列表
    """
    v4v6ip = {
        "ipv4":[],
        "ipv6":[]
    }
    r = requests.get(url=config.IPListURL)
    if r.status_code == 200:
        ipList = r.text.split("\n")
        ipList = list(filter(None, ipList))
        for ip in ipList:
            if ":" not in ip:
                v4v6ip["ipv4"].append(ip)
            else:
                v4v6ip["ipv6"].append(ip)
    logShow("获取IP列表成功，IPv4共 {} 个，IPv6共 {} 个".format(len(v4v6ip["ipv4"]), len(v4v6ip["ipv6"])))
    return {"code":0,"data":v4v6ip}

def CheckAddAndDelFirewallRules(nowFirewallRulesList:list,targetFirewallRulesList:list):
    """
    提取需要添加的防火墙规则和需要删除的防火墙规则
    删除防火墙规则只会删除备注为"Automation-Firewall"的规则
    """
    addFirewallRules = []
    delFirewallRules = []
    nowAutomationFirewall = {}
    nowFirewallRules = {}
    targetFirewallRules = {}

    # 格式化防火墙规则
    nowFirewallRulesList_2 = []
    for FirewallRules in nowFirewallRulesList:
        FirewallRules.pop("AppType")
        if FirewallRules.get("Ipv6CidrBlock") == "":
            FirewallRules.pop("Ipv6CidrBlock")
        else:
            FirewallRules.pop("CidrBlock")
        nowFirewallRulesList_2.append(FirewallRules)

    for FirewallRules in nowFirewallRulesList_2:
        nowFirewallRules["{},{},{}".format(FirewallRules["Protocol"],FirewallRules["Port"],FirewallRules["CidrBlock"] if "CidrBlock" in FirewallRules else FirewallRules["Ipv6CidrBlock"])] = FirewallRules
        if FirewallRules["FirewallRuleDescription"] == "Automation-Firewall":
            nowAutomationFirewall["{},{},{}".format(FirewallRules["Protocol"],FirewallRules["Port"],FirewallRules["CidrBlock"] if "CidrBlock" in FirewallRules else FirewallRules["Ipv6CidrBlock"])] = FirewallRules
    for FirewallRules in targetFirewallRulesList:
        targetFirewallRules["{},{},{}".format(FirewallRules["Protocol"],FirewallRules["Port"],FirewallRules["CidrBlock"] if "CidrBlock" in FirewallRules else FirewallRules["Ipv6CidrBlock"])] = FirewallRules
    
    # 提出需要删除的防火墙规则
    for FirewallRules in nowAutomationFirewall:
        if FirewallRules not in targetFirewallRules.keys():
            delFirewallRules.append(nowAutomationFirewall[FirewallRules])
    
    # 提出需要添加的防火墙规则
    for FirewallRules in targetFirewallRules:
        if FirewallRules not in nowFirewallRules.keys():
            addFirewallRules.append(targetFirewallRules[FirewallRules])
    
    return {"code":0,"data":{"addFirewallRules":addFirewallRules,"delFirewallRules":delFirewallRules}}

def IpListToFirewallRules(IpList:list):
    """
    将IP列表转换为防火墙规则
    """
    FirewallRules = []
    for ip in IpList:
        if ":" not in ip:
            FirewallRules.append({
                "Protocol": "ALL",
                "Port": "ALL",
                "CidrBlock": ip,
                "Action": "ACCEPT",
                "FirewallRuleDescription":"Automation-Firewall"
            })
        else:
            FirewallRules.append({
                "Protocol": "ALL",
                "Port": "ALL",
                "Ipv6CidrBlock": ip,
                "Action": "ACCEPT",
                "FirewallRuleDescription":"Automation-Firewall"
            })
    return {"code":0,"data":FirewallRules}

def pushMsg(title:str,content:str):
    """
    推送消息
    """
    if config.pushMsgOpen == 1:
        r = requests.post(config.workWxWebHook,json={
                "msgtype": "text",
                "text": {
                    "content": "{}\n{}".format(title,content)
                }
            })
        if r.status_code == 200:
            logShow("推送消息成功")
            return {"code":0,"data":None}
        else:
            logShow("推送消息失败，错误信息：{}".format(r.json()),"ERROR")
            return {"code":-1,"data":None}
    else:
        return {"code":0,"data":None}

def logShow(log:str,level:str="INFO"):
    print('[{}][{}] {}'.format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),level,log))

def run():
    msg = ""
    LoadingConfig()
    IpList = GetIpList()["data"]
    AllRegionsList = DescribeRegions()
    AllRegionInstance = DescribeAllRegionInstance(RegionSetList=AllRegionsList["data"])
    # AllRegionInstance = DescribeAllRegionInstance(['ap-beijing'])
    msg += "本轮需处理 {} 个实例，只打印报错信息\n".format(sum([len(AllRegionInstance["data"][Region]) for Region in AllRegionInstance["data"]]))
    for InstanceId in config.InstanceId:
        InstanceInfo = {}
        for RegionInstance in AllRegionInstance["data"]:
            if InstanceId in AllRegionInstance["data"][RegionInstance]:
                InstanceInfo = AllRegionInstance["data"][RegionInstance][InstanceId]
        if InstanceInfo == {}:
            logShow("{} 实例不存在".format(InstanceId),"ERROR")
            msg += "{} 实例不存在\n".format(InstanceId)
            continue
        logShow("当前实例所在地域：{}".format(InstanceInfo["Region"]))
        logShow("当前实例 {}具有 IPv6".format("不" if InstanceInfo["onlyIPv4"] else ""))
        logShow("开始处理 {} 实例防火墙规则".format(InstanceId))
        nowFirewallRules = DescribeFirewallRules(InstanceId=InstanceId,Region=InstanceInfo["Region"])["data"]
        logShow("现有 {} 条防火墙规则".format(len(nowFirewallRules)))
        if InstanceInfo["onlyIPv4"]:
            targetFirewallRules = IpListToFirewallRules(IpList["ipv4"])["data"]
        else:
            targetFirewallRules = IpListToFirewallRules(IpList["ipv4"]+IpList["ipv6"])["data"]
        logShow("有 {} 条目标防火墙规则".format(len(targetFirewallRules)))
        operationFirewallRules = CheckAddAndDelFirewallRules(nowFirewallRulesList=nowFirewallRules,targetFirewallRulesList=targetFirewallRules)
        logShow("需要添加 {} 条防火墙规则，删除 {} 条防火墙规则".format(len(operationFirewallRules["data"]["addFirewallRules"]), len(operationFirewallRules["data"]["delFirewallRules"])))
        res = DeleteFirewallRules(InstanceId=InstanceId,FirewallRules=operationFirewallRules["data"]["delFirewallRules"],Region=InstanceInfo["Region"])
        msg  += "实例 {} 删除规则报错\n".format(InstanceId) if res["code"] == -1 else ""
        quota = 100-len(nowFirewallRules)+len(operationFirewallRules["data"]["delFirewallRules"])
        if len(operationFirewallRules["data"]["addFirewallRules"]) > quota:
            logShow("可用防火墙规则配额为 {}，当前需要添加的规则数已超出轻量配额(100条)，将为你添加前 {} 条规则".format(quota,quota),"WARNING")
            msg += "{} 超出规则配额\n".format(InstanceId)
        res = CreateFirewallRules(InstanceId=InstanceId,FirewallRules=operationFirewallRules["data"]["addFirewallRules"][:quota],Region=InstanceInfo["Region"])
        msg  += "实例 {} 删除规则报错\n".format(InstanceId) if res["code"] == -1 else ""
        logShow("实例 {} 操作完成".format(InstanceId))

    msg += "全部处理完成"
    logShow("全部处理完成")
    return {"code":0,"data":{"msg":msg}}
    

if __name__ == "__main__":
    pushMsg("白名单更新启动","开始更新")
    while True:
        try:
            msg = run()["data"]["msg"]
            pushMsg("白名单更新完成",msg+"\n下一次将在 {} 秒后执行".format(config.sleepTime))
            # print(msg)
        except Exception as e:
            logShow("主循环报错 {}".format(e),"ERROR")
        time.sleep(config.sleepTime)