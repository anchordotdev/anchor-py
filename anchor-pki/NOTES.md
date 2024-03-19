# Spike Plan

## gunicorn

- wsgi
- uses built in `import ssl`
- strongly recommended to put it behind nginx
- the conf has a ca_certs, keyfile, certfile
- set a ssl_context() method in the `gunicorn.conf.py` file
    - returns a `ssl.SSLContext` object
- https://docs.gunicorn.org/en/latest/settings.html#ssl-context
- Just need to set `conf.certfile` to the the path of a valid file on the file
    system which will cause `conf.is_ssl` to return true
    which will in turn cause the ssl context to be called
- for gunicorn - all sockets are ssl or all are not, if `is_ssl` returns true
  then all listening sockets are ssl across the board

## waitress

- wsgi
- no ssl support

## werkzeug

- wsgi
- not for use in production

## daphne

 - uses twisteds endpoint description strings, which requires a .pem file

## uWSGI

- not a python project
- wsgi
    - https://uwsgi-docs.readthedocs.io/en/latest/SNI.html

## uvicorn

- asgi
    - [https://www.uvicorn.org/](https://www.uvicorn.org/)
        - loop.create_server
    - loop - asyncio.get_runing_loop
    - loop.create_server - use libssl and SSLContext.sni_callback
    -
- would need to expliclity set `config.ssl` on the Config object created, which
  means not runnig the main() function at all or being able to use the
  commandline

### hypercorn

- asgi
- can config programatically
- requires overriding the `create_ssl_context` method in the existing `Config`
    object and then probably doing the same as gunicorn

commandline -- 
 -c CONFIG, --config CONFIG
                        Location of a TOML config file, or when prefixed with `file:` a Python file, or when prefixed with `python:` a Python module.

probably have to set with files, and restart, see if there is a plugin to restart?


## Notes

- [Flask](https://flask.palletsprojects.com)
    - [Nginx uWSGI](https://uwsgi-docs.readthedocs.io/en/latest/Nginx.html) 
    - [Apache mod_proxy_uwsgi](https://uwsgi-docs.readthedocs.io/en/latest/Apache.html#mod-proxy-uwsgi),
- [Django](https://www.djangoproject.com/)
    - deploys using wsgi or asgi
    - gunicorn
    - daphne
    - uvicorn
- pyramid
    - uses cherrypy
- [tornado](http://www.tornadoweb.org/)
    - http only
- [https://fastapi.tiangolo.com/](https://fastapi.tiangolo.com/)
    - use gunicorn / uvicorn
- [https://sanic.dev](https://sanic.dev)
    - use the python ssl context directly
    - asgi also
- [https://www.starlette.io/](https://www.starlette.io/)
    - asgi
- [https://falcon.readthedocs.io/en/stable/](https://falcon.readthedocs.io/en/stable/)
    - run behind nginx/apache
- [https://python-eve.org](https://python-eve.org)
    - flask app

pip install -U "Twisted[tls,http2]"

python openssl context object has the sni callback

SSLContext.sni_callback[¶](https://docs.python.org/3/library/ssl.html#ssl.SSLContext.sni_callback "Permalink to this definition")

nginx / unit needs a directory / does look to support sni

wsgi servers
- bjoern - no ssl
- gunicorn - pure python
    - write an ssl_context callback
- uWSGI
- waitress
    - 
- werkzeug
    - pass in a ssl.SSLContext object

asgi serveris
- uvicorn - uses 
- - hypercorn
    - set with files - restart
