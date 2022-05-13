from app import handler


event1 = {
  "Records": [
    {
      "cf": {
        "config": {
          "distributionId": "EXAMPLE"
        },
        "request": {
          "headers": {
            "host": [
              {
                "key": "Host",
                "value": "some-hostname.org"
              }
            ],
            "user-name": [
              {
                "key": "User-Name",
                "value": "CloudFront"
              }
            ]
          },
          "clientIp": "2001:cdba::3257:9652",
          "uri": "/test",
          "method": "GET"
        },
        "response": {
          "status": "200",
          "statusDescription": "OK",
          "headers": {
            "x-cache": [
              {
                "key": "X-Cache",
                "value": "Hello from Cloudfront"
              }
            ]
          }
        }
      }
    }
  ]
}

def test_handler():
    resp = handler(event1, None)
    print()
    print(resp)

