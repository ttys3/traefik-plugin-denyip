# DenyIP

DenyIP is a middleware plugin for [Traefik](https://github.com/traefik/traefik) which accepts IP addresses or IP address ranges and blocks requests originating from those IPs.

## Configuration

### Static

In the example below `fowardedHeaders.insecure` is enabled in order to allow the IP address to be available from proxied requests. In a production environment, you may want to consider using [`forwardedHeaders.trustedIPs`](https://docs.traefik.io/routing/entrypoints/#forwarded-headers)

```yaml
experimental:
  plugins:
    denyip:
      modulename = "github.com/ttys3/traefik-plugin-denyip"
      version = "v2.0.5"

entryPoints:
  http:
    address: ":80"
    forwardedHeaders:
      insecure: true
```

### Local Mode

see https://github.com/traefik/plugindemo#local-mode

```yaml
# Static configuration

experimental:
  localPlugins:
    denyip:
      moduleName: github.com/ttys3/traefik-plugin-denyip
```

### Dynamic

To configure the `DenyIP` plugin you should create a [middleware](https://docs.traefik.io/middlewares/overview/) in your dynamic configuration as explained [here](https://docs.traefik.io/middlewares/overview/). The following example creates and uses the `denyip` middleware plugin to deny all requests originating from [Comcast](https://postmaster.comcast.net/dynamic-IP-ranges.html). `ipDenyList` will also accept non-CIDR ips, eg. `127.0.0.1`.

> Note: Providing invalid ip addresses or ranges in `ipDenyList` will cause an error and the plugin will not load.

```yaml
http:
  # Add the router
  routers:
    my-router:
      entryPoints:
      - http
      middlewares:
      - denyip
      service: service-foo
      rule: Path(`/foo`)

  # Add the middleware
  middlewares:
    denyip:
      plugin:
        enabled: true
        redis:
          addr: "localhost:6379"
          password: "your_redis_password"
          db: 0
          keyPrefix: "denyip"
          maxSubnetRanges: 100

  # Add the service
  services:
    service-foo:
      loadBalancer:
        servers:
        - url: http://localhost:5000/
        passHostHeader: false
```

## refs

https://http-wasm.io/http-handler/

https://plugins.traefik.io/install

https://github.com/http-wasm/http-wasm-guest-tinygo/blob/main/handler/handler.go

https://github.com/traefik/plugindemo

https://github.com/traefik/plugindemowasm

https://wazero.io/languages/tinygo/

https://github.com/tinygo-org/tinygo

https://tinygo.org/docs/reference/lang-support/stdlib/

https://traefik.io/blog/traefik-3-deep-dive-into-wasm-support-with-coraza-waf-plugin/

## Credits

this plugin is based on [kevtainer/denyip](https://github.com/kevtainer/denyip)