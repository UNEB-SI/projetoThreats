import peewee
from peewee import *

mysql_db = peewee.MySQLDatabase('log_analysis', user='root', password='1234', host='127.0.0.1', port=3306)

class BaseModel(Model):
    class Meta:
        database = mysql_db

class TypeContentTraffic(BaseModel):
    name = peewee.CharField()
    description = peewee.TextField()

type_content = [
    {'name': 'start', 'description': 'session started'},
    {'name': 'end', 'description': 'session ended'},
    {'name': 'drop', 'description': 'session dropped before the application is '
                                    'identified and there is no rule that allows the session'},
    {'name': 'deny', 'description': 'session dropped after the application is identified and '
                                    'there is a rule to block or no rule that allows the session'}
]

def add_type_content():
    TypeContentTraffic.insert_many(type_content).execute()

if __name__ == '__main__':
    mysql_db.connect()
    add_type_content()

