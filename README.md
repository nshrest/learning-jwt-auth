# learning-jwt-auth
This is a learning code that creates 3 endpoints (/signup, /login and /protected) and stores userinfo to postgres db from elephantsql.com. 
Based on successful login, server provides a JWT token which then can be used as a header to pass to server and access /protected endpoint.

create a free db instance in elephantsql.com , also  create a table and use the url into a code to access
sql query to create a table:

```
create table users (
  id serial primary key,
  username text not null unique,
  password text not null
);
```

For postgres connection refer example from `https://www.elephantsql.com/docs/go.html` or `go-pq-example.go` file.

**Note:** refer learning-jwt-auth-refactored repo for refactored code & notes.
