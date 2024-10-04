import sqlite3

con = sqlite3.connect("test.db")
cur = con.cursor()

cur.execute("drop table users")
cur.execute("create table users(username varchar(20) primary key not null,password varchar(1000) not null)")
print("Executed")