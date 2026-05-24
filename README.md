https://ppusso.devoutsys.com/admin/master/console/
admin/PempekAduo@@

# Test
make sure redis server is up at 6379
http://localhost:8080/api/hello/headers
http://localhost:8080/vaadin/
http://localhost:8081/api/hello/headers
http://localhost:8082/

use curl -v http://localhost:8080/vaadin

# Cara verifikasi
curl -s -X POST \
  "https://ppusso.devoutsys.com/realms/los-realm/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=cashier-1-client" \
  -d "client_secret=<your secret here>" | jq .


  Fix — Keycloak Admin Console Checklist
1. Open the client
https://ppusso.devoutsys.com/admin → los-realm → Clients → cashier-1-client
2. Settings tab — check these fields:
FieldRequired value

Client authentication ON (this makes it Confidential, enabling a client secret)
Authorization can be OFF
Authentication flow ✅ Standard flow must be checked (= Authorization Code)
Valid redirect URIs must include http://localhost:8080/*
Web origins http://localhost:8080 or +