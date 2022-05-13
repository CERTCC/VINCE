from app import handler


event1 = {
    "Records": [
        {
            "cf": {
                "config": {
                    "distributionId": "EXAMPLE"
                },
                "request": {
                    "uri": "/",
                    "method": "GET",
                    "clientIp": "2001:cdba::3257:9652",
                    "headers": {
                        "user-agent": [
                            {
                                "key": "User-Agent",
                                "value": "Test Agent"
                            }
                        ],
                        "host": [
                            {
                                "key": "Host",
                                "value": "d123.cf.net"
                            }
                        ],
                        "cookie": [
                            {
                                "key": "Cookie",
                                "value": "SomeCookie=1; AnotherOne=A; X-Experiment-Name=B"
                            }
                        ]
                    }
                }
            }
        }
    ]
}

event2 = {
    "Records": [
        {
            "cf": {
                "config": {
                    "distributionId": "EXAMPLE"
                },
                "request": {
                    "uri": "/vuls/",
                    "method": "GET",
                    "clientIp": "2001:cdba::3257:9652",
                    "headers": {
                        "user-agent": [
                            {
                                "key": "User-Agent",
                                "value": "Test Agent"
                            }
                        ],
                        "host": [
                            {
                                "key": "Host",
                                "value": "d123.cf.net"
                            }
                        ],
                        "cookie": [
                            {
                                "key": "Cookie",
                                "value": "SomeCookie=1; AnotherOne=A; X-Experiment-Name=B"
                            }
                        ]
                    }
                }
            }
        }
    ]
}

event3 = {
    "Records": [
        {
            "cf": {
                "config": {
                    "distributionId": "EXAMPLE"
                },
                "request": {
                    "uri": "/vuls/meow",
                    "method": "GET",
                    "clientIp": "2001:cdba::3257:9652",
                    "headers": {
                        "user-agent": [
                            {
                                "key": "User-Agent",
                                "value": "Test Agent"
                            }
                        ],
                        "host": [
                            {
                                "key": "Host",
                                "value": "d123.cf.net"
                            }
                        ],
                        "cookie": [
                            {
                                "key": "Cookie",
                                "value": "SomeCookie=1; AnotherOne=A; X-Experiment-Name=B"
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
    assert resp['uri'] == '/index.html'

    resp = handler(event2, None)
    assert resp['uri'] == '/vuls/index.html'

    resp = handler(event3, None)
    assert resp['uri'] == '/vuls/meow/index.html'
