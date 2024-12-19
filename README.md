# oauth_server_handmade
Authentication and Authorization server with secure coding

Setup and configuration instructions:
- Postgres Database needed with following configuration
    -  DB name= cct
    -  tables names(fields)= users (name, password); tokens (id,name,password,token,created_at,expires_at); lltokens (name,lltoken)
    -  username, password and port for DB is hardcoded.
- Libraries for venv in "requirements.txt" file.
- To run, for both client and server: host is harcoded 0.0.0.0; port are also harcoded;
- Username and password requirements to login:
    - username: must be minimum 8 characters, maximum 30 characters.
    - password: must be minimum 12 characters incluiding at least 1 number, 1 special caracter, 1 upper case and 1 lower case.

- Considerations for users, password and tokens: if user exists the server validate user and password combination, if user does not exists in DB the server register user and pass combination in DB
