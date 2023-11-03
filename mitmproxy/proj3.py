import requests

sid = '917503904'
headers = {
    'Student-Id': sid,
}
certificate_path = 'C:\\Users\\Jacob\\.mitmproxy\\mitmproxy-ca-cert.pem'

r = requests.get('https://kartik-labeling-cvpr-0ed3099180c2.herokuapp.com/ecs152a_ass1', headers=headers, verify=certificate_path)
print("Status Code:", r.status_code)
print(r.headers)