import json
import logging
#import requests
import boto3
import psycopg2
import boto3

if __name__ == '__main__':
    dburl = '127.0.0.1'
    dbport = 5432
    master = { 'username': 'postgres', 'password': 'lowsecurity'}
    con = psycopg2.connect(dbname='postgres', user=master['username'], host=dburl, port=dbport,
                                     password=master['password'])
    con.autocommit = True
    keys = [
        {'username': 'vincepub', 'password': 'vincepub'},
        {'username': 'vincetrack', 'password': 'vincetrack'},
        {'username': 'vincecomm', 'password': 'vincecomm'},

    ]
    username = 'vincepub'
    password = 'meow'

    print(f"Creating user {username}...")
    cur = con.cursor()
    for key in keys:
        username = key['username']
        password = key['password']
        try:
            cur.execute(f"CREATE USER {username} WITH ENCRYPTED PASSWORD '{password}';")
            print(f"User {username} created.")
        except psycopg2.ProgrammingError as e:
            if not 'already exists' in str(e):
                raise e
            else:
                print(str(e))

        print(f"Creating database {username}..")
        try:
            cur.execute(f"CREATE DATABASE {username};")
            print(f"Database {username} created.")

            new_con = psycopg2.connect(dbname=username, user=master['username'], host=dburl, port=dbport,
                                       password=master['password'])
            new_con.autocommit = True
            print(f"Connecting to {username}.")
            new_con.cursor().execute('CREATE EXTENSION BTREE_GIN;')
            print(f"Added BTREE_GIN extension to {username}.")


        except psycopg2.ProgrammingError as e:
            if not 'already exists' in str(e):
                raise e
            else:
                print(str(e))
        else:
            print(f"Altering database {username}'s owner to {username}")
            cur.execute(f"ALTER DATABASE {username} owner to {username};")
            print(f"Ownership updated.")

