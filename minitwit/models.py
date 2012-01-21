# -*- coding:utf-8 -*-

from mongoengine import IntField, StringField, EmailField, ListField, DateTimeField
from mongoengine import ReferenceFiled

class Message(Document):
    author = StringField()
    text = StringField()
    pub_date = DateTimeField()

class User(Document):
    username = StringField()
    email = EmailField()
    pw_hash = StringField()
    messages = ListField(ReferenceFiled(Message))
    followers = ListField(ReferenceFiled(User, reverse_delete_rule=CASCADE))
    followees = ListField(ReferenceFiled(User, reverse_delete_rule=CASCADE))

