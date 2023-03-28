from django.conf import settings

def get_cognito_pool_url():
    return f"{get_cognito_url()}/{settings.COGNITO_USER_POOL_ID}"


# adjusted as localstack is currently setting the hostname for cognito as just "localhost"
def get_cognito_url():
    if settings.LOCALSTACK:
        base_url = settings.BASE_URL
        return f"http://{base_url}"
    else:
        base_url = "amazonaws.com"
        return f"https://cognito-idp.{settings.COGNITO_REGION}.{base_url}"
