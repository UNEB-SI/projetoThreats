import peewee
from peewee import *

mysql_db = peewee.MySQLDatabase('log_analysis', user='root', password='1234', host='127.0.0.1', port=3306)
mysql_db.connect()

class BaseModel(Model):
    class Meta:
        database = mysql_db

class UserDestination(BaseModel):
    username = peewee.CharField()
    permission = peewee.CharField()

class UserSource(BaseModel):
    username = peewee.CharField()
    permission = peewee.CharField()

class User(BaseModel):
    userSource = peewee.ForeignKeyField(UserSource)
    userDestination = peewee.ForeignKeyField(UserDestination)

class Threat(BaseModel):
    name = peewee.CharField()
    description = peewee.TextField()
    severety = peewee.CharField()
    thr_category = peewee.CharField()

class Rule(BaseModel):
    name = peewee.CharField()

class AddressIPThreats(BaseModel):
    sourceAddress = peewee.CharField()
    destinationAddress = peewee.CharField()
    sourceZone = peewee.CharField()
    destinationZone = peewee.CharField()
    destinationPort = peewee.IntegerField()

class AboutThreat(BaseModel):
    receiveTime = peewee.DateTimeField()
    generateTime = peewee.DateTimeField()
    application = peewee.CharField()
    direction = peewee.CharField()
    sessionID = peewee.IntegerField()
    repeatCount = peewee.IntegerField()
    rule = peewee.ForeignKeyField(Rule, on_delete='NO ACTION')
    user = peewee.ForeignKeyField(User, on_delete='NO ACTION')
    threat = peewee.ForeignKeyField(Threat, on_delete='NO ACTION')
    addressIp = peewee.ForeignKeyField(AddressIPThreats, on_delete='NO ACTION')

mysql_db.create_tables(
    [UserSource, UserDestination, User, Threat, Rule, AddressIPThreats, AboutThreat],
    safe=True)
mysql_db.close()