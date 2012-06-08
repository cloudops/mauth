import hmac
import hashlib
import base64
import json

from urllib import quote
from urllib2 import urlopen, HTTPError, URLError

from swift.common.utils import get_logger
from time import time

from mauth.middleware import MultiAuth

class CSAuth(MultiAuth):
    """
    Manage the 'identity' to be used by swift.
    
    The identity is of the form:
    identity = dict({
        'username':<username>,
        'account':<account>,
        'token':<token>,
        'roles':[<account>, ...],
        'expires':<expires>
    })
    Note: <variables> are just placeholders for the values you would use.
    
    :param app: The next WSGI app in the pipeline
    :param conf: The dict of configuration values
    """
    def __init__(self, app, conf):
        super(CSAuth, self).__init__(app, conf)
        self.logger = get_logger(conf, log_route='cs_auth')
        self.cs_roles = ('cs_user_role', 'cs_global_admin_role', 'cs_domain_admin_role') # ORDER IS IMPORTANT: mapping to cs accounttype.
        self.cs_api_url = conf.get('cs_api_url').strip()
        self.cs_admin_apikey = conf.get('cs_admin_apikey').strip()
        self.cs_admin_secretkey = conf.get('cs_admin_secretkey').strip()
        self.cs_api = CSAPI(host=self.cs_api_url, api_key=self.cs_admin_apikey, secret_key=self.cs_admin_secretkey)
        
    # Given an s3_apikey and an 3s_signature validate the request and return the (identity, secret_key).
    # 'secret_key' is used to decode the signature.
    # If anything goes wrong, return a 'denied_response'.
    def get_s3_identity(self, env, start_response, s3_apikey, s3_signature):
        identity = None
        user_list = self.cs_api.request(dict({'command':'listUsers'}))
        if user_list:
            for user in user_list['user']:
                if user['state'] == 'enabled' and 'apikey' in user and user['apikey'] == s3_apikey:
                    # At this point we have found a matching user.  Authenticate them.
                    s3_token = base64.urlsafe_b64decode(env.get('HTTP_X_AUTH_TOKEN', '')).encode("utf-8")
                    if s3_signature == base64.b64encode(hmac.new(user['secretkey'], s3_token, hashlib.sha1).digest()):
                        expires = time() + self.cache_timeout
                        token = hashlib.sha224('%s%s' % (user['secretkey'], user['apikey'])).hexdigest()
                                                
                        self.logger.debug('Creating S3 identity')
                        identity = dict({
                            'username':user['username'],
                            'account':user['account'],
                            'token':token,
                            'roles':[self.cs_roles[user['accounttype']], user['account']],
                            'expires':expires
                        })
                        return (identity, user['secretkey'])
                    else:
                        self.logger.debug('S3 credentials are not valid')
                        env['swift.authorize'] = self.denied_response
                        return self.app(env, start_response)
        else:
            self.logger.debug('Errors: %s' % self.cs_api.errors)
            env['swift.authorize'] = self.denied_response
            return self.app(env, start_response)
        return (None, None) # should never get here, but make sure that identity is None if it does.
        
    
    # Given an auth_user and auth_key validate the request and return the identity.
    # If anything goes wrong, return a 'denied_response'.
    def get_identity(self, env, start_response, auth_user, auth_key):
        identity = None
        user_list = self.cs_api.request(dict({'command':'listUsers', 'username':auth_user}))
        if user_list:
            for user in user_list['user']:
                if user['state'] == 'enabled' and 'apikey' in user and user['apikey'] == auth_key:
                    token = hashlib.sha224('%s%s' % (user['secretkey'], user['apikey'])).hexdigest()
                    if env.get('HTTP_X_AUTH_TTL', None):
                        expires = time() + int(env.get('HTTP_X_AUTH_TTL'))
                    else:
                        expires = time() + self.cache_timeout

                    identity = dict({
                        'username':user['username'],
                        'account':user['account'],
                        'token':token,
                        'roles':[self.cs_roles[user['accounttype']], user['account']],
                        'expires':expires
                    })
                    self.logger.debug('Created identity: %s' % identity)
                    return identity
            # if we get here the user was not valid, so fail...
            self.logger.debug('Not a valid user and key pair')
            env['swift.authorize'] = self.denied_response
            return self.app(env, start_response)
        else:
            self.logger.debug('Errors: %s' % self.cs_api.errors)
            env['swift.authorize'] = self.denied_response
            return self.app(env, start_response)
        return None # return an identity of None if its gets here...
    

    # Given a token claim, validate the request and return the identity.
    def validate_token(self, token_claim):
        """
        Will take a token and validate it in cloudstack.
        """
        identity = None
        user_list = self.cs_api.request(dict({'command':'listUsers'}))
        if user_list:
            for user in user_list['user']:
                if user['state'] == 'enabled' and 'secretkey' in user and hashlib.sha224('%s%s' % (user['secretkey'], user['apikey'])).hexdigest() == token_claim:
                    expires = time() + self.cache_timeout
                    identity = dict({
                        'username':user['username'],
                        'account':user['account'],
                        'token':token_claim,
                        'roles':[self.cs_roles[user['accounttype']], user['account']],
                        'expires':expires
                    })
                    self.logger.debug('Using identity from cloudstack via token')
                    return identity
        else:
            self.logger.debug('Errors: %s' % self.cs_api.errors)
        return None # if it gets here return None.
        
        

class CSAPI(object):
    """
    Login and run queries against the Cloudstack API.
    Example Usage: 
    cs_api = CSAPI(api_key='api_key', secret_key='secret_key'))
    accounts = cs_api.request(dict({'command':'listAccounts'}))
    if accounts:
        # do stuff with the result
    else:
        # print cs_api.errors
    
    """
    
    def __init__(self, host=None, api_key=None, secret_key=None):        
        self.host = host
        self.api_key = api_key
        self.secret_key = secret_key
        self.errors = []
        
    def request(self, params):
        """Builds a query from params and return a json object of the result or None"""
        if self.api_key and self.secret_key:
            # add the default and dynamic params
            params['response'] = 'json'
            params['apiKey'] = self.api_key

            # build the query string
            query_string = "&".join(map(lambda (k,v):k+"="+quote(str(v)), params.items()))
            
            # build signature
            signature = quote(base64.b64encode(hmac.new(self.secret_key, "&".join(sorted(map(lambda (k,v):k.lower()+"="+quote(str(v)).lower(), params.items()))), hashlib.sha1).digest()))

            # final query string...
            url = self.host+"?"+query_string+"&signature="+signature
            
            output = None
            try:
                output = json.loads(urlopen(url).read())[params['command'].lower()+'response']
            except HTTPError, e:
                self.errors.append("HTTPError: "+str(e.code))
            except URLError, e:
                self.errors.append("URLError: "+str(e.reason))
               
            return output
        else:
            self.errors.append("missing api_key and secret_key in the constructor")
            return None
            
            
