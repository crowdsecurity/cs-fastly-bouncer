# cs-fastly-bouncer

This bouncer creates VCL rules and modifies ACL lists of the provided fastly services according to decisions provided by CrowdSec

# Installation using docker image

The bouncer needs config file which contains details about fastly services, tokens etc.

You can auto generate most of the config via:

```
docker run \
crowdsecurity/fastly-bouncer \
-g <FASTLY_TOKEN_1>,<FASTLY_TOKEN_2> -o cfg.yaml
```

Now in the `cfg.yaml` file fill values of 

- `recaptcha_secret_key` and `recaptcha_site_key`: See instructions about obtaining them [here](http://www.google.com/recaptcha/admin). This would allow captcha remediation.

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
  only_include_decisions_from:
  - crowdsec
  - cscli
  exclude_scenarios_containing: []
  include_scenarios_containing: []
  ca_cert_path: ''
  cert_path: ''
  insecure_skip_verify: false
  key_path: ''

fastly_account_configs:
  - account_token: <FASTLY_ACCOUNT_TOKEN> # Get this from fastly
    services: 
      - id: <FASTLY_SERVICE_ID> # The id of the service
        recaptcha_site_key: <RECAPTCHA_SITE_KEY> # Required for captcha support
        recaptcha_secret_key: <RECAPTCHA_SECRET_KEY> # Required for captcha support
        max_items: 20000 # max_items refers to the capacity of IP/IP ranges to ban/captcha. 
        activate: false # Set to true, to activate the new config in production
        captcha_cookie_expiry_duration: '1800'  # Duration to persist the cookie containing proof of solving captcha
        reference_version: null # # Optional: specify a specific version to clone from instead of the active version

update_frequency: 10 # Duration in seconds to poll the crowdsec API
log_level: info # Valid choices are either of "debug","info","warning","error"
log_mode: stdout # Valid choices are "file" or "stdout" or "stderr"
log_file: /var/log/crowdsec-fastly-bouncer.log # Ignore if logging to stdout
cache_path: /var/lib/crowdsec/crowdsec-fastly-bouncer/cache/fastly-cache.json
```