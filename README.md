# hash_password_algorithm

## Overview
This is a password manager with a database. Alice can access to the database to login, add accounts and read the database.

## Build and Install
```
cd hash_password_algorithm
```

get into the file

```
mkdir build
```

```
cd build
```

```
cmake..
```

```
cd ..
```

```
cd cmake-build-debug
```

```
./hash_password_algorithm
```

then you can run the code

Please make sure you get a mysql-server and start it, and create the local database password with the user Alice and the password Alice. Then create a table called passwordstorage.

Make sure that you install the openssl and mysql to /usr/local/include. The main.c needs to be linked to openssl and mysql.

## Functions introduction
connect_to_database: Log in to the password manager (database), this database is a local database, and only Alice knows the username and password of the database, and only Alice can log in to the database. It is equivalent to logging in to the password manager.

hash_login: After logging into the password manager, Alice can choose to log in. Alice enters the logged in user and password, the function will automatically query the salt value corresponding to this user, and hash the password with this salt value. Finally, compare with the hash value stored in the database. If they are the same, the login is successful, and if they are different, the login fails.

hash_add_account: After logging into the password manager, Alice can choose to add an account. Alice enters the user and password of the new account, the function will automatically generate a salt value, hash the password with this salt value, and finally save the user, hash value and salt value to the database.

read_database: After logging in to the password manager, Alice can choose to read the database. Alice can read all users, hashes and salts in the database at once.

input: Before executing the hash_login function and the hash_add_account function, the input function needs to be executed. This function requires the user to enter a username and password. The password needs to contain uppercase letters, lowercase letters and numbers, and the length needs to be greater than 8 digits.

parse_hexdigest: This function converts data of type const unsigned char to data of type char. It is difficult to output the hash value in the unsigned char type, and it is difficult to input it into the database for query, so the function of this conversion type is designed.

sandbox: At the beginning of the program, the sandbox function will be run first. This function defines a whitelist, any systemcall not on the whitelist will be blocked. See code for details.

## Copyright
Copyritht(c)2000-2022 Ruizhe Wang