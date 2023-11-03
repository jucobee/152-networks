import requests

# URL to the API or resource you want to access
url = 'https://example.com/api/resource'

# Send the request with certificate verification disabled
response = requests.get(url, verify=False)

if response.status_code == 200:
    print('Request was successful')
    # Process the response here
else:
    print(f'Request failed with status code: {response.status_code}')