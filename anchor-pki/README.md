# Anchor

Python client for Anchor PKI. See https://anchor.dev/ for details

## Configuration

The Following environment variables are available to configure the default
[`AutoCert::Manager`](./src/anchor-pki/autocert/manager.py).

* `HTTPS_PORT` - the TCP numerical port to bind SSL to.
* `ACME_ALLOW_IDENTIFIERS` - A comma separated list of hostnames for provisioning certs
* `ACME_DIRECTORY_URL` - the ACME provider's directory
* `ACME_KID` - your External Account Binding (EAB) KID for authenticating with the ACME directory above with an
* `ACME_HMAC_KEY` - your EAB HMAC_KEY for authenticating with the ACME directory above
* `ACME_RENEW_BEFORE_SECONDS` - **optional** Start a renewal this number number of seconds before the cert expires. This defaults to 30 days (2592000 seconds)
* `ACME_RENEW_BEFORE_FRACTION` - **optional** Start the renewal when this fraction of a certificate's valid window is left. This defaults to 0.5, which means when the cert is in the last 50% of its lifespan a renewal is attempted.
* `AUTO_CERT_CHECK_EVERY` - **optional** the number of seconds to wait between checking if the certificate has expired. This defaults to 1 hour (3600 seconds)

If both `ACME_RENEW_BEFORE_SECONDS` and `ACME_RENEW_BEFORE_FRACTION` are set,
the one that causes the renewal to take place earlier is used.

Example:

* Cert start (not_before) moment is : `2023-05-24 20:53:11 UTC`
* Cert expiration (not_after) moment is : `2023-06-21 20:53:10 UTC`
* `ACME_RENEW_BEFORE_SECONDS` is `1209600` (14 days)
* `ACME_RENEW_BEFORE_FRACTION` is `0.25` - which equates to a before seconds value of `604799` (~7 days)

The possible moments to start renewing are:

* 14 days before expiration moment - `2023-06-07 20:53:10 UTC`
* when 25% of the valid time is left - `2023-06-14 20:53:11 UTC`

Currently the `AutoCert::Manager` will use whichever is earlier.

### Example configuration

```sh
HTTPS_PORT=44300
ACME_ALLOW_IDENTIFIERS=my.lcl.host,*.my.lcl.host
ACME_DIRECTORY_URL=https://acme-v02.api.letsencrypt.org/directory
ACME_KID=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ACME_HMAC_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

## Notes

The HTTP User Agent for the anchor-autocert client is

`anchor-pki autocert python client v{VERSION}`
## Development

Development and distribution is facilitated with poetry. 

- lint the project - 2 steps:
    - `poetry run black ./`
    - `poetry run pylint ./src/anchor_pki`
- run tests `poetry run pytest tests/`
- run tests with coverage `poetry run pytest --cov-report=term-missing --cov=./src/anchor_pki/ tests/`
- build `poetry build`

Development assumes a `.env` file at the root of the python module.
Currently the only required items in it are:

```
ACME_KID=...
ACME_HMAC_KEY=...
VCR_RECORD_MODE=none # set to have new tests record new cassets
```

**To re-record all cassettes**
Make sure the `ACME_KID` and `ACME_HMAC_KEY` values in the
[`tests/anchor_pki/autocert/test_manager.py`](tests/anchor_pki/autocert/test_manager.py)
is kept in sync with the values in the `.env` file when re-recording the
cassettes as the values will need to be available during CI to match the
cassette data.

Update the `.env` file with:

```
VCR_RECORD_MODE=all
```

Then update the value for `vcr_recorded_at` in `tests/anchor_pki/autocert/test_manager.py`
to be sometime after the cassettes were recorded but before the certificates expire.

## License

The python packages is available as open source under the terms of the [MIT
License](./LICENSE.txt)
