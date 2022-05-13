from aws_cdk import core

from lib.public_bucket import LimitedPublicBucket


class TestStack(core.Stack):
    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        #LimitedPublicBucket(self, 'test-104', bucket_name='test-104.#.org', website_index_document='index.html')
        #LimitedPublicBucket(self, 'test-105', bucket_name='test-105.#.org', website_index_document='index.html')
        #LimitedPublicBucket(self, 'test-106', bucket_name='test-106.#.org', website_index_document='index.html')
