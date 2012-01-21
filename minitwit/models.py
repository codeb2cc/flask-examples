# -*- coding:utf-8 -*-

from mongoengine import Document
from mongoengine import IntField, StringField, EmailField, ListField, DateTimeField
from mongoengine import ReferenceField
from mongoengine import CASCADE

class Message(Document):
    author = StringField()
    text = StringField()
    pub_date = DateTimeField()

class User(Document):
    username = StringField()
    email = EmailField()
    pw_hash = StringField()
    messages = ListField(ReferenceField(Message))
    followers = ListField(ReferenceField('User', reverse_delete_rule=CASCADE))
    followees = ListField(ReferenceField('User', reverse_delete_rule=CASCADE))

