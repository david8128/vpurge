#!/usr/bin/env python
#
# Tool to send cache ban and purge requests to varnish layer.

import sys,os,os.path,re,httplib,optparse

hdb_require_version = '1.6.1'
try:
  import pkg_resources
  try:
    if sum(1 for x in sys.argv if x.startswith('--devel')) == 0:
      pkg_resources.require('hdb >= %s' % (hdb_require_version,))
    import hdb
  except pkg_resources.ResolutionError:
    print >>sys.stderr, 'hdblib not installed or too old (need %s or better)' % (hdb_require_version)
    sys.exit(1)
except ImportError:
  try:
    import hdb
    if hdb.get_version() < hdb_require_version:
      print >>sys.stderr, 'hdblib too old (need %s or better)' % (hdb_require_version)
      sys.exit(1)
  except ImportError:
    print >>sys.stderr, 'required library, hdblib, not found'
    sys.exit(1)

del hdb_require_version

from hdb import NodeTree

urls = (os.environ.get('HDB_SERVER'),os.environ.get('LDAPHOST'),
        'ldap://hdb.prod.nandomedia.com','ldap://hdbw.prod.nandomedia.com')

OPTIONS = None
PROG = os.path.basename(sys.argv[0])
__version__ = '1.1.0'

if sys.version_info[1] < 6:
  from urlparse import urlsplit as _urlsplit, urlparse as _urlparse
  from urlparse import urlunparse
  class urlsplit(object):
    def __init__(self,url):
      self._url = url
      info = _urlsplit(url)
      if info[0] in ('http','https'):
        # bug in python's urlparse.urlsplit prior to 2.6
        self.netloc = info[1]
        self.path = info[2]
      else:
        pathinfo = info[2].lstrip('/').rstrip('/').split('/',1)
        self.netloc = pathinfo[0]
        if len(pathinfo) > 1:
          self.path = pathinfo[1]
        else:
          self.path = ''
      self.scheme = info[0]
      self.query = info[3]
      self.fragment = info[4]
  class urlparse(tuple):
    def __new__(cls,*args):
      args = _urlparse(*args)
      return super(urlparse,cls).__new__(cls,args)

    def __init__(self,*args):
      super(urlparse,self).__init__(*args)
      self.netloc = self[1]

else:
  from urlparse import urlparse,urlunparse,urlsplit

class Http(object):
  method = 'HEAD'
  _url_re = re.compile(r'''[a-z]+://''',re.IGNORECASE)

  def __init__(self,url,**opts):
    method = opts.pop('method',None)
    timeout = opts.pop('timeout',None)
    self.url = self.canonical_url(url)
    self._parsed_url = urlparse(self.url)
    if method:
        self.method = method
    self.timeout = timeout
    self._connection = None
    self._options = opts
    super(Http,self).__init__()

  @property
  def connection(self):
    if self._connection is None:
      kwargs = dict()
      host = self._parsed_url.netloc
      port = None
      if ':' in host:
        host,port = host.rsplit(':',1)
        if port:
          port = int(port)
      if port:
        kwargs['port'] = port
      if sys.version_info[1] > 5:
        if self.timeout:
          kwargs['timeout'] = self.timeout
      elif 'timeout' in kwargs:
        del kwargs['timeout']
      self._connection = httplib.HTTPConnection(host,**kwargs)
      if OPTIONS and OPTIONS.verbose > 1:
        self._connection.set_debuglevel(OPTIONS.verbose)
    return self._connection

  def close(self):
    if hasattr(self._connection,'close'):
      self._connection.close()
    self._connection = None

  def _request(self,url=None,method=None,headers=None,split_host=True,mode=None,
                                                      accept_encoding=None):
    '''Returns (resp object, content) tuple.
    '''
    pr_kwargs = dict()
    if OPTIONS and OPTIONS.verbose:
      prefix = getattr(OPTIONS,'prefix','')
    else:
      prefix = ''
    if url is None:
      url = self.url
    if split_host and self._url_re.match(url):
      pr_kwargs['skip_host'] = True
      url = self.canonical_url(url)
      parsed_url = urlsplit(url)
      if headers is None:
        headers = dict()
      if ':' in parsed_url.netloc:
        headers['Host'] = parsed_url.netloc.rsplit(':',1)[0]
      else:
        headers['Host'] = parsed_url.netloc
      if parsed_url.scheme == 'https':
        headers['X-MI-SSL'] = 'true'
      if parsed_url.path:
        url = parsed_url.path
      else:
        url = '/'
      if parsed_url.query:
        url += '?' + parsed_url.query
    if accept_encoding is not None:
      if headers is None:
        headers = dict()
      pr_kwargs['skip_accept_encoding'] = True
      if accept_encoding:
        headers['Accept-Encoding'] = accept_encoding
    if mode is not None:
      mode = mode.upper()
      if mode == 'QUERY':
        method = mode
      elif self._options.get('hard'):
        if self._options.get('varnish4'):
          headers['Purge'] = 'hard'
        else:
          headers['Purge-Method'] = mode
      else:
        method = mode
    if method is None:
      method = self.method
    if OPTIONS and OPTIONS.auth:
      if isinstance(OPTIONS.auth,basestring):
        headers['Authorization'] = 'basic ' + OPTIONS.auth
      else:
        headers['Authorization'] = 'basic bGV0bWVpbjpub3c='
    conn = self.connection
    conn.connect()
    output_trace = (OPTIONS and (OPTIONS.verbose > 1 or (OPTIONS.verbose and method != 'QUERY')))
    if output_trace:
      print prefix+'> %s %s HTTP/1.1' % (method,url)
    conn.putrequest(method,url,**pr_kwargs)
    if headers:
      for k,v in sorted(headers.items()):
        if output_trace:
          print prefix+'> %s: %s' % (k,v)
        conn.putheader(k,v)
    conn.endheaders()
    resp = conn.getresponse()
    resp.begin()
    body = resp.read()
    resp.close()
    self.close()
    return resp,body

  def request(self,*args,**kwargs):
    try:
      return self._request(*args,**kwargs)
    except:
      ei = sys.exc_info()
      try:
        self.close()
      except:
        self._connection = None
      raise ei[0],ei[1],ei[2]

  @classmethod
  def canonical_url(cls,url):
    if not cls._url_re.match(url):
      return urlunparse(urlparse('http://' + url))
    return urlunparse(urlparse(url))

def uniq_preserve_order(seq):
  seen = set()
  for i in seq:
    if i and i not in seen:
      seen.add(i)
      yield i

def extract_ldap_error(e):
  '''ldap exceptions are horrible; there seems to be little consitency regarding the attributes
  of various LDAPError subclasses.
  '''
  try:
    msg = e.message.get('info')
    if msg is None:
      msg = e.message.get('desc')
    if msg is None:
      msg = str(e[1])
  except (KeyError,AttributeError,IndexError):
    msg = str(e)
  return msg

class OptionParser(optparse.OptionParser,object):
  env_r = re.compile(r'''(prod|test|dev(?:el)?|qa[123]?|edge|alpha|beta|tlc|production)$''',
                     re.IGNORECASE)
  tool_mode_r = re.compile(r'''\s*(?:(PURGE|REFRESH|QUERY|BAN)|([PRQB]))$''')
  modes = {'P':'PURGE','R':'REFRESH','Q':'QUERY','B':'BAN'}

  def inc_varnish_tool_option(self,optob,opt,value,*args,**kwargs):
    v = getattr(self.values,optob.dest,0) + (value or 1)
    optob.take_action('store',optob.dest,opt,v,self.values,self)

  def display_varnish_tool_version(self,optob,opt,value,*args,**kwargs):
    global __version__
    print '%s %s' % (self.prog,__version__)
    sys.exit(0)

  def set_auth_credentials(self,optob,opt,value,*args,**kwargs):
    import base64
    m = re.match(r'.+:.+$',value)
    if not m:
      raise optparse.OptionValueError, 'invalid username:password combination (%r)' % value
    creds = ''.join(base64.encodestring(value).strip().splitlines())
    optob.take_action('store',optob.dest,opt,creds,self.values,self)

  def set_varnish_tool_mode(self,optob,opt,value,*args,**kwargs):
    m = self.tool_mode_r.match(value.upper())
    if not m:
      raise optparse.OptionValueError, 'invalid mode %r (choose from \'purge\', \'query\', or \'ban\')' % value.upper()
    if m.group(1):
      value = m.group(1)
    else:
      value = m.group(2)
    optob.take_action('store',optob.dest,opt,self.modes[value[0]],self.values,self)

  def set_varnish_tool_environment(self,optob,opt,value,*args,**kwargs):
    if value:
      m = self.env_r.match(value.lower())
      if not m:
        raise optparse.OptionValueError, 'invalid environment %r' % value
      value = m.group(1)
      if value == 'prod':
        value = 'production'
      elif value in ('test','qa'):
        value = 'qa1'
      elif value in ('devel','dev'):
        value = 'alpha'
    optob.take_action('store',optob.dest,opt,value,self.values,self)

  def __init__(self,**kwargs):
    global PROG
    kwargs.setdefault('prog',PROG)
    kwargs.setdefault('usage','Usage: %prog [options] <url> [<url> ...]')
    kwargs.setdefault('description','Utility to issue HTTP BAN, PURGE, or QUERY requests to one or more '+
                                   'varnish servers in a (probably escenic) environment. Varnish servers are '+
                                   'selected by querying the hdb.')
    super(OptionParser,self).__init__(**kwargs)

    self.disable_interspersed_args()
    self.add_option('-M','--mode',action='callback',type='string',
                    default=optparse.NO_DEFAULT,dest='mode',callback=self.set_varnish_tool_mode,
                    help='''Select %s option mode ('purge', 'ban', or 'query' -
                                               default is query)''' % (self.prog,))
    group = self.add_option_group('Purge Mode (-MP or --mode=purge)',
               description='''This is the default mode if %s is run as 'vpurge'.
Issues a "soft purge" as opposed to a hard purge or ban. Soft purges are more
resource intensive on the varnish server compared to bans but less so than hard
purges.  They cause an immediate expire of content ttls while leaving the
actual content in place so that it can still be delivered via grace mode --
comparable to bans which are queued up for the varnish ban thread and hard
purges which forcefully and completely remove content from a varnish server so
that itis unavailable in any and all circumstances. Soft purges are a good
compromise between bans and traditional hard purges in terms of routine
use.''' % self.prog)
    group.add_option('-a','--authentication',action='store_true',dest='auth',default=None,
                      help='Send an authenticated purge (random user:pass without --credentials) [note: NOT required]')
    group.add_option('-c','--credentials',action='callback',dest='auth',
                      callback=self.set_auth_credentials,type='string',
                      help='Supply authentication credentials in the format user:pass')
    group.add_option('-H','--hard',action='store_true',dest='hard',default=False,
                      help='Send a "hard" purge which irrevocably purges content')

    if 0:
      group = self.add_option_group('Refresh Mode (-MR or --mode=refresh)',
                  description='Issues a request to purge and immediately reload a cached object. '+
                              'There will be a short interval between purging and refresh completion '+
                              'when the object will not be available for incoming requests.')

    group = self.add_option_group('Query Mode (-MQ or --mode=query)',
                description='Issue a query to each varnish server in an environment (or other '+
                            'hdb query). The results of the query will report the cache state '+
                            'for the requested url, including Time-To-Live and Age. This is the '+
                            'default mode when running as "vquery" (or "vq" perhaps). Combine with '+
                            '-v/--verbose to return more information about the cached object.')

    group = self.add_option_group('Ban Mode (-MB or --mode=ban)',
              description='''In Ban mode, A request is sent to each varnish
server in an environment or network which adds a url to the server's "ban
lurker thread list". This activates a special background thread which will
quietly purge the requested url from the cache while causing as little
operational interference as possible. Thus, this is the least invasive method
of purging desired content. Unless a varnish server is extremely overloaded
this ban will take effect much more rapidly than is humanly noticeable.''')

    group = self.add_option_group('Generic Options')

    group.add_option('-3','--varinsh3',action='store_false',dest='varnish4', default=True,
                    help='Disable varnish4 mode')
    group.add_option('-v','--verbose',action='callback',dest='verbose',default=0,
                      callback=self.inc_varnish_tool_option,
                      help='Increase verbosity, can be used multiple times')
    group.add_option('--devel',action='callback',dest='verbose',default=0,
                      callback=self.inc_varnish_tool_option, help=self.SUPPRESS_HELP)

    group.add_option('-V','--version',action='callback',callback=self.display_varnish_tool_version,
                      help='Display version information')
    group.add_option('-e','--env','--environment',action='callback',callback=self.set_varnish_tool_environment,
                      dest='env',default='',type='string',
                      help='Send requests to all varnish servers in an environment')
    group.add_option('-q','--query',action='store',dest='query',
                      default='',type='string',
                      help='Specify HDB query to use to select varnish hosts')
    group.add_option('--disabled',action='store_true',default=False,
                      help='Included hosts marked as disabled or decommissioned in the hdb')

    group.add_option('-p','--port',action='store',type='int',default=8888,
                      help='Set varnish port to connect to (default is 8888)')
    group.add_option('-i','--ignore-missing',action='store_true',default=False,
                      help='Ignore 404 errors when purging or banning.')

  @classmethod
  def update_constants(kls,iterable):
    optparse.OptionParser.__dict__.update(dict(iterable))

def get_hdb_query(opts=OPTIONS):
  query = list()
  if not opts or (not opts.env and not opts.query):
    env = os.environ.get('ENVIRONMENT')
  elif opts and opts.env:
    env = opts.env

  if not opts or not opts.query:
    if not env:
      print >>sys.stderr, 'Configuration error, cannot detect environment.'
      sys.exit(10)

    if opts.varnish4:
      query.append('[class=varnish4::escenic+class=varnish41::escenic+class=varnish6::escenic].env='+env)
    else:
      query.append('class=varnish.env='+env)
  elif opts.query:
    query.append(opts.query)

  if opts and not opts.disabled:
    query.insert(0,'[')
    query.append(']')
    query.append('-DISABLED')
  return ''.join(query)

def main(args):
  import warnings, socket
  from hdb.ldapex.exceptions import SERVER_DOWN,LDAPError

  global OPTIONS
  OptionParser.update_constants((k,v) for k,v in optparse.__dict__.iteritems()
                                                              if k.isupper())
  option_parser = OptionParser()
  opts,args = option_parser.parse_args(args)

  if not opts.mode:
    m = re.search(r'^(v4?)(arnish4?-)?(purge|refresh|ban|query)',PROG,re.IGNORECASE)
    if m:
      if m.group(1) == 'v4' or m.group(2) == 'arnish4-':
        opts.varnish4 = True
      opts.mode = m.group(3).upper()
  if not args:
    option_parser.print_help(sys.stderr)
    sys.exit(1)
  if not opts.mode:
    opts.mode = 'QUERY'
  OPTIONS = opts

  query = get_hdb_query(opts)
  tree = None

  if opts.verbose > 1:
    print 'HDB query:',query

  for url in uniq_preserve_order(urls):
    try:
      if opts.verbose > 1:
        print 'Trying hdb server:',urlsplit(url).netloc
      tree = NodeTree(url)
      break
    except SERVER_DOWN:
      pass
    except LDAPError, e:
      warnings.warn('%s: %s' % (url,extract_ldap_error(e)))

  if tree is None:
    print >>sys.stderr,'Cannot contact HDB server.'
    sys.exit(20)

  if query:
    tree.search(filter=hdb.parse_query(query))
  else:
    tree.search()

  hosts = list()
  for dn in tree:
    hosts.append(dn.as_fqdn())

  hosts.sort()
  conns = dict()
  flags = dict()
  for host in hosts:
    conns[host] = Http('http://%s:%d/' % (host,opts.port), method='PURGE',timeout=5.0,hard=opts.hard,varnish4=opts.varnish4)

  exit_code = 0
  ccre = re.compile(r'\s+|\s*[;,]\s*')
  numeric_r = re.compile('\s*(\d+(?:\.\d+)?)\s*')
  requests = dict()
  info = dict()
  for a in args:
    requests.clear()
    for host in sorted(conns.keys()):
      if opts.verbose > 1 or (opts.mode != 'QUERY' and opts.verbose):
        prefix = '[%s] ' % (host.split('.')[0],)
      elif len(conns) > 1:
        prefix = host.split('.')[0]+':'
      else:
        prefix = ''
      request = requests.setdefault(host,dict(prefix=prefix))
      OPTIONS.prefix = prefix
      try:
        c = conns[host]
        request['resp'],request['data'] = c.request(url=a,mode=opts.mode,accept_encoding=False)
        request['headers'] = dict(request['resp'].getheaders())
      except socket.error, e:
        request['resp'] = request['data'] = request['headers'] = None
        request['error'] = e

    for host,request in sorted(requests.items()):
      if 'prefix' in request:
        OPTIONS.prefix = prefix = request['prefix']
      if 'error' not in request:
        resp = request['resp']
        data = request['data']
        headers = request['headers']
        if resp.status != 200 and (resp.status != 404 or not opts.ignore_missing):
          exit_code += 1
        verbose = opts.verbose
        if opts.mode == 'QUERY' and resp.status != 200 and verbose == 1:
          if sum(1 for r in requests.values() if r['resp'].status == 200) == 0:
            verbose += 1
        if resp.status == 200 and (not verbose or opts.mode == 'QUERY'):
          if opts.mode == 'QUERY':
            code = 0
            cc = headers.get('mi-query-origin-cache-control','').strip()
            qresp = headers.get('mi-query-response','??').split(' ',1)
            if verbose:
              lines = data.splitlines()
              nlines = len(lines)
              for i,line in enumerate(lines):
                if cc and i == nlines-1 and line.startswith('----'):
                  print prefix+'CacheCtl:',', '.join([v for v in ccre.split(cc) if v])
                print prefix+line
              if len(qresp) > 0 and qresp[0].strip().isdigit():
                code = int(qresp[0].strip())
            else:
              info.clear()
              info['Age'] = headers.get('mi-query-age','??')
              info['TTL'] = headers.get('mi-query-ttl','??')
              info['Hits'] = headers.get('mi-query-hits','??')
              if len(qresp) > 1:
                info['Code'] = code = int(qresp[0].strip())
                info['Response'] = qresp[-1].strip()
              elif qresp[0].strip().isdigit():
                info['Code'] = code = int(qresp[0].strip())
                info['Response'] = ''
              else:
                info['Code'] = '???'
                info['Response'] = ' '.join(qresp)
              info['Length'] = headers.get('mi-query-content-length','N/A').split(' ',1)[0]
              info['Status'] = headers.get('mi-varnish-status','??')
              info['Grace'] = headers.get('mi-query-grace','??')
              info['CC'] = cc
              info['URL'] = a
              if info['Length'].isdigit():
                info['Length'] += 'b'
              m = numeric_r.match(info['Grace'])
              if m:
                info['Grace'] = '%ds' % int(round(float(m.group(1)),0))
              m = numeric_r.match(info['TTL'])
              if m:
                info['TTL'] = '%0.1fs' % round(float(m.group(1)),1)
              if info['Status'] == '??':
                info['Status'] = info['Response']
              m = numeric_r.match(info['Age'])
              if m:
                info['Age'] = '%ds' % int(round(float(m.group(1)),0))

              print prefix+'Status:%(Code)s Age:%(Age)s/TTL:%(TTL)s/Grace:%(Grace)s Hits:%(Hits)s Length:%(Length)s [%(Status)s]' % info

            if code and code >= 300 and code < 400 and 'location' in headers:
              print prefix+' \----> Redirect Location:',headers['location'].strip()
          else:
            print prefix+'%d %s' % (resp.status,resp.reason)
        elif resp.status != 200 and (resp.status != 404 or not opts.ignore_missing):
          if verbose:
            print prefix+'< %d %s' % (resp.status,resp.reason)
          elif opts.mode != 'QUERY':
            print prefix+'%d %s' % (resp.status,resp.reason)
          else:
            print prefix+'Status:%d [%s]' % (resp.status,resp.reason)
        elif resp.status == 404 and opts.mode == 'QUERY' and opts.ignore_missing is not True and not verbose:
          print prefix+'Status:%d [%s]' % (resp.status,resp.reason)
        if resp.status not in (200,404) or verbose:
          if verbose or (resp.status != 404 or not opts.ignore_missing):
            if verbose > 1 or opts.mode != 'QUERY':
              for k,v in sorted(headers.items()):
                print prefix+'< %s: %s' % (k,v)
      else:
        print >>sys.stderr, prefix+'%s: %s' % (a,request['error'])
        exit_code += 1
  sys.exit(exit_code)

if __name__ == '__main__':
  try:
    main(sys.argv[1:])
  except KeyboardInterrupt:
    print >>sys.stderr,"\nInterrupt"
    sys.exit(100)

#
