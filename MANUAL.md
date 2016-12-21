PyDynDNS Manual
===============

This is a short manual to using PyDynDNS.

Introduction
------------
There are already other free dynamic dns implementations, but most have
relatively complex requirements and/or implement custom update protocols.

PyDynDNS implements a minimal subset of the DynDNS Remote Access Update API
(https://help.dyn.com/remote-access-api/) with minimal requirements (no 
django or other heavy frameworks required), so you can set up your own 
DynDNS service to allow updates from almost all devices with builtin dyndns
support (most allow for custom DynDNS server name).

Prerequisites (web service)
---------------------------
* python with modules web and dns
* web server with python and url rewriting support (e.g. apache with 
mod_python and mod_rewrite)

Prerequisites (infrastructure)
------------------------------
* have your own dns (sub-)domain
* have your own name server(s) for said domain or have the name server
configured to support dynamic updates as defined in RFC 2136


Step-by-Step Manual
-------------------
* make sure your dns server supports dynamic updates as defined in RFC 2136
with TSIG authentication as defined in RFC 3007 (for bind servers, there are
many howtos out there, for example https://wiki.debian.org/DDNS)
* edit config.py.example 
* rename config.py.example to config.py
* use existing .htaccess for apache, or configure your web server accordingly

