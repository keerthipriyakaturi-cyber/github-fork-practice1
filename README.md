# Login mini app (React + Java + JWT)

A small login application with a React frontend and a Java backend that issues **HS256 JWT** access tokens.

## What you get

- React login page (`frontend/`)
- Java HTTP API (`backend/`)
- Signed JWT on login (`alg=HS256`, 15-minute expiry)
- Protected `GET /api/me` that verifies signature, expiry, and revocation
- Logout adds the token `jti` to a denylist until it expires

## Demo accounts

| Username | Password  |
| -------- | --------- |
| admin    | admin123  |
| keerthi  | password  |

## Run it

You only need **Java 17**. From this folder:

```bat
run.bat
```

Or:

```bat
javac -d out backend\src\com\loginapp\*.java
java -cp out com.loginapp.LoginServer
```

Optional: set a production secret (at least 32 characters):

```bat
set JWT_SECRET=replace-with-a-long-random-secret-key
java -cp out com.loginapp.LoginServer
```

Open [http://localhost:8080](http://localhost:8080)

## API

- `POST /api/login` with `{ "username": "admin", "password": "admin123" }`
  - Response includes `token` (JWT), `tokenType: Bearer`, `expiresIn`
- `GET /api/me` with `Authorization: Bearer <jwt>`
- `POST /api/logout` with `Authorization: Bearer <jwt>`
