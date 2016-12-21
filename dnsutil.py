import os
import web
try:
  from socket import ConnectionRefusedError
  SocketError = None
except ImportError:
  from socket import error as SocketError
  ConnectionRefusedError = None

import dns.exception
import dns.query
import dns.rcode
import dns.tsig
import dns.tsigkeyring
import dns.update

# time to wait for dns name updating [s]
UPDATE_TIMEOUT = float(os.environ.get('DNS_UPDATE_TIMEOUT', '20.0'))

class DnsUpdateError(ValueError):
  """
  raised if DNS update return code is not NOERROR
  """

def update_ns(name, nsinfo, rdtype='A', ipaddr=None, origin=None, action='upd', ttl=60):
  """
  update the master server

  :param name: the domain name to update (str)
  :param nsinfo: the nsinfo record (tuple)
  :param rdtype: the record type (default: 'A') (str)
  :param ipaddr: ip address (v4 or v6), if needed (str)
  :param origin: the origin zone to update (default; autodetect) (str)
  :param action: 'add', 'del' or 'upd'
  :param ttl: time to live for the added/updated resource, default 60s (int)
  :return: dns response
  :raises: DnsUpdateError, Timeout
  """
  assert action in ['add', 'del', 'upd', ]
  (origin, nameserver, keyname, key, algo) = nsinfo
  upd = dns.update.Update(origin,
                          keyring=dns.tsigkeyring.from_text({keyname: key}),
                          keyalgorithm=getattr(dns.tsig, algo))
  if action == 'add':
    assert ipaddr is not None
    upd.add(name, ttl, rdtype, ipaddr)
  elif action == 'del':
    upd.delete(name, rdtype)
  elif action == 'upd':
    assert ipaddr is not None
    upd.replace(name, ttl, rdtype, ipaddr)
  web.debug("performing %s for name %s and origin %s with rdtype %s and ipaddr %s" % (
               action, name, origin, rdtype, ipaddr))
  try:
    response = dns.query.tcp(upd, nameserver, timeout=UPDATE_TIMEOUT)
    rcode = response.rcode()
    if rcode != dns.rcode.NOERROR:
      rcode_text = dns.rcode.to_text(rcode)
      web.debug("DNS error [%s] performing %s for name %s and origin %s with rdtype %s and ipaddr %s" % (
                     rcode_text, action, name, origin, rdtype, ipaddr))
      raise DnsUpdateError(rcode_text)
    return response
  except SocketError as (errno, msg):
    web.debug("socket error [%s] (%s) connecting to nameserver %s" % (errno, msg, nameserver))
    raise DnsUpdateError("DNSServerSocketTimeout")
  except ConnectionRefusedError:
    web.debug("socket error [11] (connection refused) connecting to nameserver %s" % (nameserver))
    raise DnsUpdateError("DNSServerSocketTimeout")
  except dns.exception.Timeout:
    web.debug("timeout when performing %s for name %s and origin %s with rdtype %s and ipaddr %s" % (
                   action, name, origin, rdtype, ipaddr))
    #set_ns_availability(domain, False)
    raise
  except dns.tsig.PeerBadSignature:
    logger.error("PeerBadSignature - shared secret mismatch? zone: %s" % (origin, ))
    #set_ns_availability(domain, False)
    raise DnsUpdateError("PeerBadSignature")

