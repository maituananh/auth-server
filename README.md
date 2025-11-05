# auth-server

how to get token:
1. access to https://oauthdebugger.com/
http://localhost:8080/oauth2/authorize?client_id=client&redirect_uri=https://oauthdebugger.com/debug&scope=openid&response_type=code&response_mode=query&state=cd6strbk829&nonce=ekuwcenu3yn
2. go to form username and password
3. get code from after login success
4. use postman to get access token:
curl --location 'http://localhost:8080/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Basic Y2xpZW50OnNlY3JldA==' \
--header 'Cookie: JSESSIONID=20F3A0D0C5C7BCC8D35B736BE5C9A6D1' \
--data-urlencode 'grant_type=authorization_code' \
--data-urlencode 'code=KQtM6gS3MS7bNDGeoYMn991ggBVo1bueCQOS4YRF2fa44svGyp9tosjHvDkPwlGHXxSTPk_202pIBkEoGQlOUhpMK-BGVhOQrCwwJYkDseIk2J8ymbzaSf7BZirV0RFt' \
--data-urlencode 'redirect_uri=https://oauthdebugger.com/debug'