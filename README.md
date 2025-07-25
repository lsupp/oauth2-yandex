# Yandex OAuth2 client provider
This package provides [Yandex.com](https://yandex.ru/) integration for OAuth2 Client by the League.
## Installation
```
composer require lsupp/oauth2-yandex
```
## Add to config/packages/knpu_oauth2_client.yaml
```
  yandex_main:
      type: generic
      provider_class: Lsupp\OAuth2\Client\Provider\Yandex
      # add and set these environment variables in your .env files
      client_id: '%env(OAUTH_YANDEX_CLIENT_ID)%'
      client_secret: '%env(OAUTH_YANDEX_CLIENT_SECRET)%'
      # a route name you'll create
      redirect_route: connect_yandex_check
      redirect_params: {}
      # whether to check OAuth2 "state": defaults to true
      # use_state: true
```
