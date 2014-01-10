# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import hmac
import hashlib
import base64

from urllib import quote

#from webob.exc import HTTPForbidden, HTTPNotFound, HTTPUnauthorized
#from webob import Request, Response
from swift.common.swob import Response, Request
from swift.common.swob import HTTPBadRequest, HTTPForbidden, HTTPNotFound, HTTPUnauthorized

from swift.common.utils import cache_from_env, get_logger, split_path, get_remote_client
from swift.common.middleware.acl import clean_acl, parse_acl, referrer_allowed
from time import time
from datetime import datetime

class MultiAuth(object):
    """
    A swift auth middleware designed to be pluggable with existing auth systems.

    ------
    SETUP:
    ------
    File: proxy-server.conf
    Add 'mauth' (and 'cache') to your pipeline:

        [pipeline:main]
        pipeline = catch_errors cache mauth proxy-server

    Optional S3 Integration - To add support for s3 calls, change the above to:

        [pipeline:main]
        pipeline = catch_errors cache swift3 mauth proxy-server

        [filter:swift3]
        use = egg:swift#swift3

    Add account auto creation to the proxy-server.

        [app:proxy-server]
        account_autocreate = true


    Add a filter for 'mauth':

        [filter:mauth]
        use = egg:mauth#mauth
        swift_storage_url = http://127.0.0.1:8080
        #cache_timeout = 86400
        #allowed_sync_hosts = 127.0.0.1#,127.0.0.2,127.0.0.3
        mauth_extension = CSAuth
        # -- add extension specific config here -- #
        cs_api_url = http://127.0.0.1:8081/client/api
        cs_admin_apikey = <admin user's apikey>
        cs_admin_secretkey = <admin user's secretkey>


    ------
    USAGE:
    ------

    Curl:
    -----
    Request for authentication
    curl -v -H "X-Auth-User: $username" -H "X-Auth-Key: $apikey" http://127.0.0.1:8080/v1.0
    returns: $auth_token and $swift_storage_url

    Request container list
    curl -v -X GET -H "X-Auth-Token: $auth_token" $swift_storage_url


    Swift CLI:
    ----------
    Request status
    swift -v -A http://127.0.0.1:8080/v1.0 -U $username -K $apikey stat


    S3 API:
    -------
    Requires the optional step in SETUP
    (example uses the python boto lib)

    from boto.s3.connection import S3Connection, OrdinaryCallingFormat

    conn = S3Connection(aws_access_key_id=$apikey,
                        aws_secret_access_key=$secretkey,
                        host='127.0.0.1',
                        port=8080,
                        is_secure=False,
                        calling_format=OrdinaryCallingFormat())
    bucket = conn.create_bucket('sample_bucket')
    

    :param app: The next WSGI app in the pipeline
    :param conf: The dict of configuration values
    """
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='mauth')
        self.reseller_prefix = conf.get('reseller_prefix', '').strip()
        self.cache_timeout = int(conf.get('cache_timeout', 86400))
        self.storage_url = conf.get('swift_storage_url').strip()
        self.allowed_sync_hosts = [h.strip()
            for h in conf.get('allowed_sync_hosts', '127.0.0.1').split(',')
            if h.strip()]
            
    def get_s3_identity(self):
        pass # interface
        
    def get_identity(self):
        pass # interface
        
    def validate_token(self):
        pass # interface

    def __call__(self, env, start_response):
        self.logger.debug('In mauth middleware')
        identity = None # the identity we are trying to populate
 
        # Handle s3 connections first because s3 has a unique format/use for the 'HTTP_X_AUTH_TOKEN'.
        s3 = env.get('HTTP_AUTHORIZATION', None)
        if s3 and s3.startswith('AWS'):
            s3_apikey, s3_signature = s3.split(' ')[1].rsplit(':', 1)[:]
            if s3_apikey and s3_signature:
                # check if we have cached data to validate this request instead of hitting cloudstack.
                memcache_client = cache_from_env(env)
                memcache_result = memcache_client.get('mauth_s3_apikey/%s' % s3_apikey)
                valid_cache = False
                data = None
                if memcache_result and self.cache_timeout > 0:
                    expires, data = memcache_result
                    if expires > time():
                        valid_cache = True
                if valid_cache:
                    self.logger.debug('Validating the S3 request via the cached identity')
                    s3_token = base64.urlsafe_b64decode(env.get('HTTP_X_AUTH_TOKEN', '')).encode("utf-8")
                    if s3_signature == base64.b64encode(hmac.new(data.get('secret', ''), s3_token, hashlib.sha1).digest()):
                        self.logger.debug('Using cached S3 identity')
                        identity = data.get('identity', None)
                        
                        # The swift3 middleware sets env['PATH_INFO'] to '/v1/<aws_secret_key>', we need to map it to the cloudstack account.
                        if self.reseller_prefix != '':
                            env['PATH_INFO'] = env['PATH_INFO'].replace(s3_apikey, '%s_%s' % (self.reseller_prefix, identity.get('account', '')))
                        else:
                            env['PATH_INFO'] = env['PATH_INFO'].replace(s3_apikey, '%s' % (identity.get('account', '')))
                else: # hit cloudstack and populate memcached if valid request
                    identity, secret_key = self.get_s3_identity(env, start_response, s3_apikey, s3_signature);
                    
                    if identity:
                        if self.reseller_prefix != '':
                            account_url = '%s/v1/%s_%s' % (self.storage_url, self.reseller_prefix, quote(identity.get('account', '')))
                        else:
                            account_url = '%s/v1/%s' % (self.storage_url, quote(identity.get('account', '')))
                        identity['account_url'] = account_url
                        
                        # The swift3 middleware sets env['PATH_INFO'] to '/v1/<aws_secret_key>', we need to map it to the cloudstack account.
                        if self.reseller_prefix != '':
                            env['PATH_INFO'] = env['PATH_INFO'].replace(s3_apikey, '%s_%s' % (self.reseller_prefix, identity.get('account', '')))
                        else:
                            env['PATH_INFO'] = env['PATH_INFO'].replace(s3_apikey, '%s' % (identity.get('account', '')))  
                        memcache_client = cache_from_env(env)
                        if memcache_client:
                            memcache_client.set('mauth_s3_apikey/%s' % s3_apikey, (identity['expires'], dict({'secret':secret_key, 'identity':identity})), time=int(env.get('HTTP_X_AUTH_TTL', self.cache_timeout)))
                            memcache_client.set('mauth_token/%s' % token, (identity['expires'], identity), time=int(env.get('HTTP_X_AUTH_TTL', self.cache_timeout)))
                    else:
                        self.logger.debug('No identity for this request')
                        env['swift.authorize'] = self.denied_response
                        return self.app(env, start_response)
            else:
                self.logger.debug('Invalid credential format')
                env['swift.authorize'] = self.denied_response
                return self.app(env, start_response)
        
        # If it is not an S3 call, handle the request for authenication, otherwise, use the token.
        req = Request(env)
        if not s3:
            try:
                auth_url_piece, rest_of_url = split_path(req.path_info, minsegs=1, maxsegs=2, rest_with_last=True)
            except ValueError:
                return HTTPNotFound(request=req)

            # Check if the request is for authentication (to get a token).
            if auth_url_piece in ('auth', 'v1.0'): # valid auth urls
                auth_user = env.get('HTTP_X_AUTH_USER', None)
                auth_key = env.get('HTTP_X_AUTH_KEY', None)
                if auth_user and auth_key:
                    # check if we have this user and key cached.
                    memcache_client = cache_from_env(env)
                    memcache_result = memcache_client.get('mauth_creds/%s/%s' % (auth_user, auth_key))
                    valid_cache = False
                    data = None
                    if memcache_result and self.cache_timeout > 0 and env.get('HTTP_X_AUTH_TTL', 1) > 0:
                        expires, data = memcache_result
                        if expires > time():
                            valid_cache = True
                    if valid_cache:
                        self.logger.debug('Using cached identity via creds')
                        identity = data
                        self.logger.debug("Using identity: %r" % (identity))
                        req.response = Response(request=req,
                                                headers={'x-auth-token':identity.get('token', None), 
                                                         'x-storage-token':identity.get('token', None),
                                                         'x-storage-url':identity.get('account_url', None)})
                        return req.response(env, start_response)
                    else: # hit cloudstack for the details.
                        identity = self.get_identity(env, start_response, auth_user, auth_key)
                        
                        if identity:
                            if self.reseller_prefix != '':
                                account_url = '%s/v1/%s_%s' % (self.storage_url, self.reseller_prefix, quote(identity.get('account', '')))
                            else:
                                account_url = '%s/v1/%s' % (self.storage_url, quote(identity.get('account', '')))
                            identity['account_url'] = account_url
                                
                            # add to memcache so it can be referenced later
                            memcache_client = cache_from_env(env)
                            if memcache_client:
                                memcache_client.set('mauth_creds/%s/%s' % (auth_user, auth_key), (identity['expires'], identity), time=int(env.get('HTTP_X_AUTH_TTL', self.cache_timeout)))
                                memcache_client.set('mauth_token/%s' % identity.get('token', ''), (identity['expires'], identity), time=int(env.get('HTTP_X_AUTH_TTL', self.cache_timeout)))
                            req.response = Response(request=req,
                                                    headers={'x-auth-token':identity.get('token', None), 
                                                             'x-storage-token':identity.get('token', None),
                                                             'x-storage-url':identity.get('account_url', None)})
                            return req.response(env, start_response)
                        else:
                            self.logger.debug('No identity for these credentials')
                            env['swift.authorize'] = self.denied_response
                            return self.app(env, start_response)
                else:
                    self.logger.debug('Credentials missing')
                    env['swift.authorize'] = self.denied_response
                    return self.app(env, start_response)
            else:
                token = env.get('HTTP_X_AUTH_TOKEN', env.get('HTTP_X_STORAGE_TOKEN'))
        
        if not identity and not env.get('HTTP_X_AUTH_TOKEN', env.get('HTTP_X_STORAGE_TOKEN', None)):
            # this is an anonymous request.  pass it through for authorize to verify.
            self.logger.debug('Passing through anonymous request')
            env['swift.authorize'] = self.authorize
            env['swift.clean_acl'] = clean_acl
            return self.app(env, start_response)

        # setup a memcache client for the following.
        memcache_client = cache_from_env(env)
        
        if not identity:
            memcache_result = memcache_client.get('mauth_token/%s' % token)
            if memcache_result and self.cache_timeout > 0:
                expires, _identity = memcache_result
                if expires > time():
                    self.logger.debug('Using cached identity via token')
                    identity = _identity

        if not identity:
            self.logger.debug("No cached identity, validate token via the extension.")
            identity = self.validate_token(token)
            if identity and memcache_client:
                if self.reseller_prefix != '':
                    account_url = '%s/v1/%s_%s' % (self.storage_url, self.reseller_prefix, quote(identity.get('account', '')))
                else:
                    account_url = '%s/v1/%s' % (self.storage_url, quote(identity.get('account', '')))
                identity['account_url'] = account_url
                
                memcache_client.set('mauth_token/%s' % identity.get('token', None), (identity['expires'], identity), time=int(env.get('HTTP_X_AUTH_TTL', self.cache_timeout)))
            else:  # if we didn't get identity it means there was an error.
                self.logger.debug('No identity for this token');
                env['swift.authorize'] = self.denied_response
                return self.app(env, start_response)

        if not identity:
            env['swift.authorize'] = self.denied_response
            return self.app(env, start_response)

        self.logger.debug("Using identity: %r" % (identity))
        env['mauth.identity'] = identity
        env['REMOTE_USER'] = ':'.join(identity['roles'])
        env['swift.authorize'] = self.authorize
        env['swift.clean_acl'] = clean_acl
        return self.app(env, start_response)
        

    def authorize(self, req):
        env = req.environ
        identity = env.get('mauth.identity', {})

        try:
            version, _account, container, obj = split_path(req.path, minsegs=1, maxsegs=4, rest_with_last=True)
        except ValueError:
            return HTTPNotFound(request=req)

        if not _account or not _account.startswith(self.reseller_prefix):
            return self.denied_response(req)

        # Remove the reseller_prefix from the account.
        if self.reseller_prefix != '':
            account = _account[len(self.reseller_prefix)+1:]
        else:
            account = _account
        
        user_roles = identity.get('roles', [])

        # If this user is part of this account, give access.
        if account == identity.get('account'):
            req.environ['swift_owner'] = True
            return None

        # Allow container sync
        if (req.environ.get('swift_sync_key') and req.environ['swift_sync_key'] == req.headers.get('x-container-sync-key', None) and
           'x-timestamp' in req.headers and (req.remote_addr in self.allowed_sync_hosts or get_remote_client(req) in self.allowed_sync_hosts)):
            self.logger.debug('Allowing container-sync')
            return None

        # Check if Referrer allow it
        referrers, groups = parse_acl(getattr(req, 'acl', None))
        if referrer_allowed(req.referer, referrers):
            if obj or '.rlistings' in groups:
                self.logger.debug('Authorizing via ACL')
                return None
            return self.denied_response(req)

        # Check if we have the group in the user_roles and allow if we do
        for role in user_roles:
            if role in groups:
                self.logger.debug('User has role %s, allowing via ACL' % (role))
                return None

        # This user is not authorized, deny request.
        return self.denied_response(req)

    def denied_response(self, req):
        """
        Returns a standard WSGI response callable with the status of 403 or 401
        depending on whether the REMOTE_USER is set or not.
        """
        if req.remote_user:
            return HTTPForbidden(request=req)
        else:
            return HTTPUnauthorized(request=req)



def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)
    extension = conf.get('mauth_extension').strip()
    
    mod = __import__('mauth.extensions.'+extension, fromlist=[extension])
    extension_cls = getattr(mod, extension)

    def auth_filter(app):
        return extension_cls(app, conf)
    return auth_filter
