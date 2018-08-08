import peewee
from peewee import *
from database.modelThreats import User, Rule

mysql_db = peewee.MySQLDatabase('log_analysis', user='root', password='1234', host='127.0.0.1', port=3306)
mysql_db.connect()

class BaseModel(Model):
    class Meta:
        database = mysql_db

class TypeContentTraffic(BaseModel):
    name = peewee.CharField()
    description = peewee.TextField()

class SessionEndReason(BaseModel):
    name = peewee.CharField()
    description = peewee.TextField()

class AddressIPTraffic(BaseModel):
    sourceAddress = peewee.CharField()
    destinationAddress = peewee.CharField()
    sourceZone = peewee.CharField()
    destinationZone = peewee.CharField()
    destinationPort = peewee.IntegerField()

class Traffic(BaseModel):
    receiveTime = peewee.DateTimeField()
    generateTime = peewee.DateTimeField()
    application = peewee.CharField()
    sessionID = peewee.IntegerField()
    repeatCount = peewee.IntegerField()
    ipProtocol = peewee.CharField()
    action = peewee.CharField()
    action_source = peewee.CharField()
    pkts_sent = peewee.IntegerField()
    pkts_received = peewee.IntegerField()
    SessionEndReason = peewee.ForeignKeyField(SessionEndReason, on_delete='NO ACTION')
    User = peewee.ForeignKeyField(User, on_delete='NO ACTION')
    Rule = peewee.ForeignKeyField(Rule, on_delete='NO ACTION')
    ThreatTypeContent = peewee.ForeignKeyField(TypeContentTraffic, on_delete='NO ACTION')
    AddressIp = peewee.ForeignKeyField(AddressIPTraffic, on_delete='NO ACTION')

mysql_db.create_tables([TypeContentTraffic, SessionEndReason, AddressIPTraffic, Traffic], safe=True)
mysql_db.close()