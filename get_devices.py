import requests
from lxml import etree
import json
import hashlib
import os
import hmac
import crypto.Random as Random
import urllib3
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings()

gl_cookies = {}
gl_cookie = ""
gl_cookies_path = "cookies"
gl_csrf_param = ""
gl_csrf_token = ""
gl_count = 0

firstNonce = ""
finalNonce = ""
salt = ""


def update_information(html):
    global gl_cookies
    global gl_csrf_param
    global gl_csrf_token

    gl_cookies = html.cookies
    url_tree = etree.HTML(html.text)
    gl_csrf_param = url_tree.xpath("//meta[@name='csrf_param']/@content")[0]
    gl_csrf_token = url_tree.xpath("//meta[@name='csrf_token']/@content")[0]


def salt_password(password, salt, iter_times):
    return hashlib.pbkdf2_hmac("sha256", password, salt, iter_times)


def main_login(sess, router, username, passwd):
    global gl_cookie
    global gl_cookies
    global gl_csrf_param
    global gl_csrf_token

    result = sess.get(f"https://{router}/html/index.html")
    update_information(result)

    request_header = {
        "Connection": "keep-alive",
        "Cache-Control": "max-age=0",
        "Origin": f"https://{router}",
        "Content-Type": "application/json;charset=UTF-8",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "_ResponseFormat": "JSON",
        "Referer": f"https://{router}/html/index.html",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }

    first_nonce_str = Random.get_random_bytes(32).hex()
    first_nonce = bytes(first_nonce_str, encoding="utf-8")

    login_post_data = {
        "csrf": {"csrf_param": gl_csrf_param, "csrf_token": gl_csrf_token},
        "data": {"username": username, "firstnonce": first_nonce_str},
    }

    url_router_login = f"https://{router}/api/system/user_login_nonce"
    device_login = sess.post(
        url_router_login,
        headers=request_header,
        data=json.dumps(login_post_data, ensure_ascii=True),
        cookies=gl_cookies,
    )

    login_response = json.loads(device_login.text)
    if not login_response["err"] == 0:
        print("first post failed")

    gl_csrf_param = login_response["csrf_param"]
    gl_csrf_token = login_response["csrf_token"]
    salt = bytes.fromhex(login_response["salt"])
    final_nonce = login_response["servernonce"]
    auth_msg = first_nonce_str + "," + final_nonce + "," + final_nonce
    iterations_rece = int(login_response["iterations"])

    passwd = passwd.encode()

    saltPassword = salt_password(passwd, salt, iterations_rece)
    mac = hmac.new(b"Client Key", saltPassword, hashlib.sha256)
    client_key = mac.digest()
    store_key = hashlib.sha256(client_key).digest()
    mac = hmac.new(bytes(auth_msg, encoding="utf-8"), store_key, hashlib.sha256)
    client_signature = mac.digest()
    client_key = bytearray(client_key)
    for i in range(len(client_key)):
        client_key[i] = client_key[i] ^ client_signature[i]
    client_proof = bytes(client_key)

    login_post_data = {
        "csrf": {"csrf_param": gl_csrf_param, "csrf_token": gl_csrf_token},
        "data": {"finalnonce": final_nonce, "clientproof": client_proof.hex()},
    }

    url_router_login = f"https://{router}/api/system/user_login_proof"
    device_login = sess.post(
        url_router_login,
        headers=request_header,
        data=json.dumps(login_post_data),
    )
    login_response = json.loads(device_login.text)
    if not login_response["err"] == 0:
        print("login failed")
    return


if __name__ == "__main__":
    session = requests.Session()
    session.verify = False

    router = os.getenv("ROUTER")
    passwd = os.getenv("PASSWORD")
    username = "admin"
    main_login(session, router, username, passwd)

    result = session.get(f"https://{router}/api/system/HostInfo")
    false = False
    true = True
    result = eval(result.text)
    for device in result:
        if device["Active"]:
            print(device["MACAddress"])
