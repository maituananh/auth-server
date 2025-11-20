
## API Reference

#### Get token without PKCE (Authentication)
Step 1: Get code
```http
  Get code: GET /oauth2/authorize
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `client_id` | `string` | **Required**. client |
| `redirect_uri` | `string` | **Required**. https://oauthdebugger.com/debug |
| `scope` | `string` | **Required**. openid profile email |
| `response_type` | `string` | **Required**. code |
| `response_mode` | `string` | **Required**. query |
| `state` | `string` | **Required**. 30a09b17lei |
| `nonce` | `string` | **Required**. eq1ombaqctq |

Step 2: Go to Login page of backend (admin/admin)

Step 3: Get token

```http
  Get Token POST /oauth2/token
  Content-Type: application/x-www-form-urlencoded
  Add basic auth: client/secret
```
| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `grant_type` | `string` | **Required**. authorization_code |
| `code` | `string` | **Required**. get code from response of STEP 1 |
| `redirect_uri` | `string` | **Required**. https://oauthdebugger.com/debug |
| `client_id` | `string` | **Required**. client |
| `scope`      | `string` | **Required**. openid profile email |



#### Get token with PKCE (Authentication exclude client_secret)
Step 1: Get code
```http
  Get code: GET /oauth2/authorize
```

| Parameter | Type     | Description                |
| :-------- | :------- | :------------------------- |
| `client_id` | `string` | **Required**. client |
| `redirect_uri` | `string` | **Required**. https://oauthdebugger.com/debug |
| `scope` | `string` | **Required**. openid profile email |
| `response_type` | `string` | **Required**. code |
| `response_mode` | `string` | **Required**. query |
| `state` | `string` | **Required**. 30a09b17lei |
| `nonce` | `string` | **Required**. eq1ombaqctq |
| `code_challenge_method` | `string` | **Required**. S256 |
| `code_challenge` | `string` | **Required**. hWK5gRdSoBMfUicBNZS0ywhmiqCIPnfIX_hmFjF9EqE |

Step 2: Go to Login page of backend (admin/admin)

Step 3: Get token

```http
  Get Token POST /oauth2/token
  Content-Type: application/x-www-form-urlencoded
```
| Parameter | Type     | Description                       |
| :-------- | :------- | :-------------------------------- |
| `grant_type` | `string` | **Required**. authorization_code |
| `code` | `string` | **Required**. get code from response of STEP 1 |
| `redirect_uri` | `string` | **Required**. https://oauthdebugger.com/debug |
| `client_id` | `string` | **Required**. client |
| `scope`      | `string` | **Required**. openid profile email |
| `code_verifier` | `string` | **Required**. sT0Q8WDKxhct31PC4HFSFGKHSASsNqKil2bkObCapLP |




## Environment Variables

To run this project, you will need to add the following environment variables to your .env file

Java >= 21

Postgresql >= 18

Database:`DB_URL`
`DB_NAME`
`DB_USERNAME`
`DB_PASSWORD`

Redis: `REDIS_USERNAME`
`REDIS_PASSWORD`
`REDIS_HOST`
`REDIS_PORT`
## Run Locally

Clone the project

```bash
  git clone git@github.com:maituananh/auth-server.git
```

Go to the project directory

```bash
  cd auth-server
```

Install dependencies

```bash
  ./gradlew build
```

Start the server

```bash
  ./gradlew bootRun
```


## Running Tests

To run tests, run the following command

```bash
  ./gradlew test
```


## Acknowledgements

- How to create private and public keys PEM
- Currently, keys pem saved at /resources/certs/xxxx_key.pem
    1. Generate the Private Key: openssl genrsa -out private_key.pem 2048
    2. Extract the Public Key: openssl rsa -in private_key.pem -pubout -out public_key.pem
    3. Optional (For enhanced security, you can encrypt the private key with a passphrase during generation. This requires entering a passphrase when prompted): Encrypting the Private Key: openssl genrsa -aes256 -out private_key_encrypted.pem 2048




## Documentation

[Setting security filter chain](https://docs.spring.io/spring-authorization-server/reference/getting-started.html)

[Implement Authorization Server](https://docs.spring.io/spring-authorization-server/reference/guides/how-to-jpa.html)


## Support

Redis: no-password for default

1. Access container: docker exec -it redis redis-cli
2. ACL LIST -> see: nopass
3. Set new password for Redis: ACL SETUSER default on >[mypassword] allcommands allkeys

For support, email maituananh12061998@gmail.com


## Authors

- [@anhmt](https://github.com/maituananh)

