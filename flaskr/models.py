# -*- coding:utf-8 -*-

import mongoengine

class Entry(mongoengine.Document):
    title = mongoengine.StringField()
    text = mongoengine.StringField()
