import mysql.connector

db=mysql.connector.connect(
    host="localhost",
    user='root',
    password='root',
    database='personal_records'
)
cursor=db.cursor()