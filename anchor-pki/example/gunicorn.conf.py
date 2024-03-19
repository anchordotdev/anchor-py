import ssl
import pathlib
from anchor_pki.autocert import configuration, sni_callback, terms_of_service

# gunicon requires a `certfile` setting in order to call the ssl_context
# and the certfile setting requires a file to exist. So we create a dummy
# file here and set the certfile to that dummy file.

pathlib.Path("./certfile-marker-for-gunicorn").touch()
certfile = "./certfile-marker-for-gunicorn"

# Create an SniCallback class to handle the sni_callback. This is required
# so that we can pass the config to the sni_callback function.
# Full information on all the configuration options is available in the
# Configuration class documention
autocert_config = configuration.Configuration(
    # specify the name of this configuration, this will only come into play in
    # situations where there is more than one configuration.
    name="gunicorn",
    # specify the terms of service acceptor, or an array of acceptors.
    tos_acceptors=terms_of_service.AnyAcceptor(),
    # specify the identifiers that this configuration will handle.
    allow_identifiers=["myapp.lcl.host"],
)

the_callback = sni_callback.SniCallback(autocert_config)

# Set the ssl_context to use the sni_callback from anchor_pki, this will get
# called on every request to determine which certificate to use and setup the
# ssl context for that request.
# class SniCallback:


def ssl_context(config, default_ssl_context_factory):
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        # assign the sni_callback associated with the configuration to the ssl_context
        context.sni_callback = the_callback.sni_callback

        return context
    except Exception as e:
        print(f"Exception in gunicorn config ssl_context: {e}")
        return None
