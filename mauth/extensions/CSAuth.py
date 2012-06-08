class CSAuth(MultiAuth):
    """
    :param app: The next WSGI app in the pipeline
    :param conf: The dict of configuration values
    """
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='cs_auth')
        self.cs_roles = ('cs_user_role', 'cs_global_admin_role', 'cs_domain_admin_role') # ORDER IS IMPORTANT: mapping to cs accounttype.
        self.cs_api_url = conf.get('cs_api_url').strip()
        self.cs_admin_apikey = conf.get('cs_admin_apikey').strip()
        self.cs_admin_secretkey = conf.get('cs_admin_secretkey').strip()
        self.cs_api = CSAPI(host=self.cs_api_url, api_key=self.cs_admin_apikey, secret_key=self.cs_admin_secretkey)
        
            
    def get_s3_identity(self):
        user_list = self.cs_api.request(dict({'command':'listUsers'}))
        if user_list:
            for user in user_list['user']:
                if user['state'] == 'enabled' and 'apikey' in user and user['apikey'] == s3_apikey:
                    # At this point we have found a matching user.  Authenticate them.
                    s3_token = base64.urlsafe_b64decode(env.get('HTTP_X_AUTH_TOKEN', '')).encode("utf-8")
                    if s3_signature == base64.b64encode(hmac.new(user['secretkey'], s3_token, hashlib.sha1).digest()):
                        expires = time() + self.cache_timeout
                        timeout = self.cache_timeout
                        token = hashlib.sha224('%s%s' % (user['secretkey'], user['apikey'])).hexdigest()
                        if self.reseller_prefix != '':
                            account_url = '%s/v1/%s_%s' % (self.storage_url, self.reseller_prefix, quote(user['account']))
                        else:
                            account_url = '%s/v1/%s' % (self.storage_url, quote(user['account']))
                        identity = dict({
                            'username':user['username'],
                            'account':user['account'],
                            'token':token,
                            'account_url':account_url,
                            'roles':[self.cs_roles[user['accounttype']], user['account']],
                            'expires':expires
                        })
                        self.logger.debug('Creating S3 identity')
                        # The swift3 middleware sets env['PATH_INFO'] to '/v1/<aws_secret_key>', we need to map it to the cloudstack account.
                        if self.reseller_prefix != '':
                            env['PATH_INFO'] = env['PATH_INFO'].replace(s3_apikey, '%s_%s' % (self.reseller_prefix, user['account']))
                        else:
                            env['PATH_INFO'] = env['PATH_INFO'].replace(s3_apikey, '%s' % (user['account']))        
                        memcache_client = cache_from_env(env)
                        if memcache_client:
                            memcache_client.set('mauth_s3_apikey/%s' % s3_apikey, (expires, dict({'secret':user['secretkey'], 'identity':identity})), timeout=timeout)
                            memcache_client.set('mauth_token/%s' % token, (expires, identity), timeout=timeout)
                    else:
                        self.logger.debug('S3 credentials are not valid')
                        env['swift.authorize'] = self.denied_response
                        return self.app(env, start_response)
        else:
            self.logger.debug('Errors: %s' % self.cs_api.errors)
            env['swift.authorize'] = self.denied_response
            return self.app(env, start_response)
    
    
    def get_identity(self):
        user_list = self.cs_api.request(dict({'command':'listUsers', 'username':auth_user}))
        if user_list:
            for user in user_list['user']:
                if user['state'] == 'enabled' and 'apikey' in user and user['apikey'] == auth_key:
                    token = hashlib.sha224('%s%s' % (user['secretkey'], user['apikey'])).hexdigest()
                    if env.get('HTTP_X_AUTH_TTL', None):
                        expires = time() + int(env.get('HTTP_X_AUTH_TTL'))
                        timeout = int(env.get('HTTP_X_AUTH_TTL'))
                    else:
                        expires = time() + self.cache_timeout
                        timeout = self.cache_timeout
                    if self.reseller_prefix != '':
                        account_url = '%s/v1/%s_%s' % (self.storage_url, self.reseller_prefix, quote(user['account']))
                    else:
                        account_url = '%s/v1/%s' % (self.storage_url, quote(user['account']))
                    identity = dict({
                        'username':user['username'],
                        'account':user['account'],
                        'token':token,
                        'account_url':account_url,
                        'roles':[self.cs_roles[user['accounttype']], user['account']],
                        'expires':expires
                    })
                    self.logger.debug('Created identity: %s' % identity)
                    # add to memcache so it can be referenced later
                    memcache_client = cache_from_env(env)
                    if memcache_client:
                        memcache_client.set('mauth_creds/%s/%s' % (auth_user, auth_key), (expires, identity), timeout=timeout)
                        memcache_client.set('mauth_token/%s' % token, (expires, identity), timeout=timeout)
                    req.response = Response(request=req,
                                            headers={'x-auth-token':token, 
                                                     'x-storage-token':token,
                                                     'x-storage-url':account_url})
                    return req.response(env, start_response)
    
            # if we get here the user was not valid, so fail...
            self.logger.debug('Not a valid user and key pair')
            env['swift.authorize'] = self.denied_response
            return self.app(env, start_response)
        else:
            self.logger.debug('Errors: %s' % self.cs_api.errors)
            env['swift.authorize'] = self.denied_response
            return self.app(env, start_response)
            
            
    def validate_token(self, token_claim):
        """
        Will take a token and validate it in cloudstack.
        """
        identity = None
        user_list = self.cs_api.request(dict({'command':'listUsers'}))
        if user_list:
            for user in user_list['user']:
                if user['state'] == 'enabled' and 'secretkey' in user and hashlib.sha224('%s%s' % (user['secretkey'], user['apikey'])).hexdigest() == token_claim:
                    if self.reseller_prefix != '':
                        account_url = '%s/v1/%s_%s' % (self.storage_url, self.reseller_prefix, quote(user['account']))
                    else:
                        account_url = '%s/v1/%s' % (self.storage_url, quote(user['account']))
                    expires = time() + self.cache_timeout
                    identity = dict({
                        'username':user['username'],
                        'account':user['account'],
                        'token':token_claim,
                        'account_url':account_url,
                        'roles':[self.cs_roles[user['accounttype']], user['account']],
                        'expires':expires
                    })
                    self.logger.debug('Using identity from cloudstack via token')
                    return identity
        else:
            self.logger.debug('Errors: %s' % self.cs_api.errors)

        return identity
        
        

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
            
            