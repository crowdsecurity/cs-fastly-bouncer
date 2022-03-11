# cs-fastly-bouncer

This bouncer creates VCL rules and modifies ACL lists of the provided fastly services according to decisions provided by CrowdSec

# Installation using docker image

The bouncer needs config file which contains details about fastly services, tokens etc.

You can auto generate most of the config via:

```
docker run \
crowdsecurity/fastly-bouncer \
-g <FASTLY_TOKEN_1>,<FASTLY_TOKEN_2> > cfg.yaml
```

Now in the `cfg.yaml` file fill values of 

- `recaptcha_secret_key` and `recaptcha_site_key`: See instructions about obtaining them [here](http://www.google.com/recaptcha/admin). This would allow captcha remediations.

- `lapi_key` and `lapi_url`:  The `lapi_url` is where crowdsec LAPI is listening. Make sure the container can access this URL. The `lapi_key` can be obtained by running 
```bash
sudo cscli bouncers add fastlybouncer
```

- Also make sure the logs are emitted to stdout by setting value of `log_mode` to `stdout`.

After reviewing the `cfg.yaml` file, let's create a cache file which we will later mount to the container.

```
touch cache.json
```


Finally let's run the bouncer:

```
docker run\
-v $PWD/cfg.yaml:/etc/crowdsec/bouncers/crowdsec-fastly-bouncer.yaml\
-v $PWD/cache.json/:/var/lib/crowdsec/crowdsec-fastly-bouncer/cache/fastly-cache.json\
crowdsecurity/fastly-bouncer
```

## Config

```yaml
crowdsec_config: 
  lapi_key: ${LAPI_KEY} 
  lapi_url: "http://localhost:8080/"

fastly_account_configs:
  - account_token: <FASTLY_ACCOUNT_TOKEN> # Obtain this from fastly
    services: 
      - id: <FASTLY_SERVICE_ID> # The id of the service
        recaptcha_site_key: <RECAPTCHA_SITE_KEY> # Required for captcha support
        recaptcha_secret_key: <RECAPTCHA_SECRET_KEY> # Required for captcha support
        max_items: 20000 # max_items refers to the capacity of IP/IP ranges to ban/captcha. 
        activate: false
        reference_version: <REFERENCE_VERSION># version to clone/use
        clone_reference_version: true # whether to clone the "reference_version".
        captcha_cookie_expiry_duration: '1800'  # Duration to persist the cookie containing proof of solving captcha

update_frequency: 10 # Duration in seconds to poll the crowdsec API
log_level: info # Valid choices are either of "debug","info","warning","error"
log_mode: stdout # Valid choices are "file" or "stdout" or "stderr"
log_file: /var/log/crowdsec-fastly-bouncer.log # Ignore if logging to stdout
cache_path: /var/lib/crowdsec/crowdsec-fastly-bouncer/cache/fastly-cache.json
```