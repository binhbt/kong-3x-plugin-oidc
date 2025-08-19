#!/bin/bash

# ========================
# ⚙️  Cấu hình
# ========================
KEYCLOAK_URL="http://localhost:8080"
REALM="demo"
CLIENT_ID="spring-boot-app"
CLIENT_SECRET="AQxbMiF79vSqdaY0oWQxA8ExPsFKFrSm"
API_BASE_URL="http://localhost:80"

# ========================
# 🧾 Lấy Access Token
# ========================
echo "==> Lấy Access Token từ Keycloak..."

TOKEN_RESPONSE=$(curl -s --request POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  --header "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=${CLIENT_ID}" \
  --data-urlencode "client_secret=${CLIENT_SECRET}")

ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r .access_token)

if [ "$ACCESS_TOKEN" == "null" ] || [ -z "$ACCESS_TOKEN" ]; then
  echo "❌ Không thể lấy Access Token. Kiểm tra lại client_id, client_secret và realm."
  exit 1
fi

echo "✅ Access Token đã lấy thành công."

# ========================
# 🌐 Gọi API công khai
# ========================
echo -e "\n==> Gọi API công khai (không cần token): /public/hello"
curl -s "${API_BASE_URL}/public/hello"
echo

# ========================
# 🔐 Gọi API bảo vệ (cần token)
# ========================
echo -e "\n==> Gọi API bảo vệ (cần token): /private/hello"
curl -s "${API_BASE_URL}/private/hello" \
  --header "Authorization: Bearer ${ACCESS_TOKEN}"
echo
