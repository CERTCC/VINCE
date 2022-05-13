def handler(event, context):
    # Extract the request from the CloudFront event that is sent to Lambda@Edge
    response = event['Records'][0]['cf']['response']
    # host = event['Records'][0]['cf']['request']['headers']['host'][0]['value']
    headers = response['headers']

    #
    # NOTE: If you make a change to this lambda, you must go into AWS console,
    # find it in us-east-1, and then select to "publish a new version." AFTER
    # that is done, redeploy the stacks or cloudfront to pick up the lambda@edge
    # changes and get cloudfront to point at the new function version. [JDW]
    #

    # :update:
    # "kb.fqdn" and "vince.fqdn" should be changed to the cloudfront domain
    # names used for kb and vince.

    # make pycharm not hard wrap this
    # @formatter:off
    security_policy = f"script-src 'self' kb.fqdn vince.fqdn https://www.googletagmanager.com https://www.google-analytics.com https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; style-src 'self' kb.fqdn vince.fqdn https://fonts.googleapis.com https://use.fontawesome.com 'unsafe-inline'; object-src 'none'"
    # @formatter:on

    headers['strict-transport-security'] = [{
        'key': 'Strict-Transport-Security',
        'value': "max-age=5184000"
    }]

    headers['content-security-policy'] = [{
        'key': 'Content-Security-Policy',
        'value': security_policy
    }]

    headers['x-content-security-policy'] = [{
        'key': 'X-Content-Security-Policy',
        'value': security_policy
    }]

    headers['x-content-type-options'] = [{
        'key': 'X-Content-Type-Options',
        'value': "nosniff"
    }]

    headers['x-frame-options'] = [{
        'key': 'X-Frame-Options',
        'value': "SAMEORIGIN"
    }]

    headers['expect-ct'] = [{
        'key': 'Expect-CT',
        'value': "max-age=0"
    }]

    headers['cache-control'] = [{
        'key': 'Cache-control',
        'value': "no-store"
    }]

    headers['pragma'] = [{
        'key': 'Pragma',
        'value': "no-cache"
    }]

    headers['x-xss-protection'] = [{
        'key': 'X-XSS-Protection',
        'value': "1; mode=block"
    }]

    headers['referrer-policy'] = [{
        'key': 'Referrer-Policy',
        'value': "no-referrer-when-downgrade"
    }]

    return response
