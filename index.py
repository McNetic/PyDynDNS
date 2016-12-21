#!/usr/bin/python

import web
import re
import base64
from passlib.hash import sha256_crypt

import dnsutil

try:
  import config
  web.config.debug = config.debug
except:
  config = None
  web.config.debug = True

urls = (
  '/nic/update', 'ddns',
)
app = web.application(urls, globals())

class ddns:

  def isValidFQDN(self, hostname):
    if len(hostname) > 255:
      return False
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    parts = hostname.split(".")
    return 2 < len(parts) and all(allowed.match(x) for x in parts)

  def requestAuthorization(self):
    web.header('WWW-Authenticate','Basic realm="SpeedX DDNS Service API"')
    web.header('X-UpdateCode', 'A')
    web.ctx.status = '401 Unauthorized'
    return 'badauth'

  def notAuthorized(self):
    web.header('X-UpdateCode', 'X')
    web.ctx.status = '403 Forbidden'
    return 'badauth'

  def isAuthorized(self, auth):
    auth = re.sub('^Basic ', '', auth)
    self.username,password = base64.decodestring(auth).split(':')
    if self.username in config.users.keys() and sha256_crypt.verify(password, config.users[self.username]['password']):
      return True
    else:
      return False

  def configMissing(self):
    web.header('X-UpdateCode', 'X')
    return '911'

  def noValidHostname(self):
    web.header('X-UpdateCode', 'X')
    return 'notfqdn'

  def hostnameNotAllowed(self):
    web.header('Accept-Ranges', 'none')
    web.header('Transfer-Encoding', 'chunked')
    web.header('X-User-Status', 'free')
    return 'nohost'

  def updateNic(self, fqdn, rdtype='A', ipaddr=None):
    web.header('Accept-Ranges:', 'none')
    if not ipaddr:
      ipaddr = web.ctx.env.get('REMOTE_ADDR')
    parts = fqdn.split('.')
    hostname = parts[0];
    nsinfo = config.domains['.'.join(parts[1:])]
    try:
      dnsutil.update_ns(name=hostname, nsinfo=nsinfo,rdtype=rdtype, ipaddr=ipaddr, action='upd')
    except dnsutil.DnsUpdateError:
      return 'dnserr'
    return 'good ' + ipaddr

  def tryUpdateNic(self):
    input = web.input()
    if not 'hostname' in input:
      return self.noValidHostname()

    hosts = input['hostname'].split(',')
    result = []
    if 'myip' in input:
      myip = input['myip'].encode('ascii', 'replace')
    else:
      myip = None

    for hostname in hosts:
      if not self.isValidFQDN(hostname):
        result.append(self.noValidHostname())
      elif not hostname in config.users[self.username]['hosts']:
        result.append(self.hostnameNotAllowed())
      else:
        result.append(self.updateNic(hostname.encode('ascii', 'replace'), 'A', myip))
    return '\n'.join(result)

  def GET(self):
    auth = web.ctx.env.get('HTTP_AUTHORIZATION')
    web.header('Content-Type', 'text/plain')
    if not config:
      return self.configMissing()
    if not auth:
      return self.requestAuthorization()
    elif not self.isAuthorized(auth):
      return self.notAuthorized()
    else:
      return self.tryUpdateNic()

if __name__ == "__main__":
  try:    
    app.run()
  except:
    pass

