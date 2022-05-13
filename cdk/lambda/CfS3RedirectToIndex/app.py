import re

def handler(event, context):
    # Extract the request from the CloudFront event that is sent to Lambda@Edge
    request = event['Records'][0]['cf']['request']

    olduri = request['uri']

    if olduri.endswith('index.html'):
        return request

    if not olduri.endswith('/'):
        olduri = f"{olduri}/"

    request['uri'] = f"{olduri}index.html"

    print(f"Old URI: {olduri}\n New URI: {request['uri']}")

    return request


