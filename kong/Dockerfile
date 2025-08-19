FROM kong:3.9

USER root

# Cài curl để luarocks có thể tải được package
RUN apt-get update && apt-get install -y curl

# Cài dependencies (lua-resty-openidc và lua-resty-http)
RUN luarocks install lua-resty-openidc
RUN luarocks install lua-resty-http

# Copy kong-oidc plugin nguyên thư mục
COPY kong-oidc/kong/plugins/oidc /usr/local/share/lua/5.1/kong/plugins/oidc

# Chỉnh quyền nếu cần
RUN chown -R kong:kong /usr/local/share/lua/5.1/kong/plugins

#==
RUN mkdir -p /usr/local/share/lua/5.1/kong/plugins/keycloak-introspect

# Copy plugin source code vào đúng vị trí Kong expects
COPY kong-plugin-keycloak-introspect/kong/plugins/keycloak-introspect /usr/local/share/lua/5.1/kong/plugins/keycloak-introspect
COPY kong-plugin-keycloak-introspect/init.lua /usr/local/share/lua/5.1/kong/plugins/keycloak-introspect/init.lua

#==
USER kong

ENV KONG_PLUGINS=bundled,keycloak-introspect,oidc
