package = "kong-plugin-keycloak-introspect"
version = "0.1-1"
source = {
  url = "./"
}
description = {
  summary = "Keycloak Token Introspection plugin for Kong CE",
  license = "Apache 2.0",
  homepage = "https://github.com/yourname/kong-plugin-keycloak-introspect"
}
dependencies = {
  "lua-resty-http",
  "lua-cjson",
  "kong >= 3.0"
}
build = {
  type = "none"
}
