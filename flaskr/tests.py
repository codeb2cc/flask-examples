# -*- coding:utf-8 -*-
"""
    Flaskr Tests
    ~~~~~~~~~~~~

    Tests the Flaskr application
"""

import os
import unittest

import pymongo

import flaskr

class FlaskrTestCase(unittest.TestCase):

    def setUp(self):
        """Before each test, set up a blank database"""
        # Create MongoDB test database
        connection = pymongo.Connection('localhost', 27017)
        db = connection['flaskr_test']
        connection.close()

        flaskr.app.config['TESTING'] = True
        flaskr.connect_db('flaskr_test')

        self.app = flaskr.app.test_client()

    def tearDown(self):
        """Get rid of the database again after each test"""
        connection = pymongo.Connection('localhost', 27017)
        connection.drop_database('flaskr_test')
        connection.close()

    def login(self, username, password):
        return self.app.post('/login', data=dict(
                username = username,
                password = password
            ), follow_redirects=True)

    def logout(self):
        return self.app.get('/logout', follow_redirects=True)

    # Testing functions
    def test_empty_db(self):
        """Start with a blank database."""
        rv = self.app.get('/')
        assert 'No entries here so far' in rv.data

    def test_login_logout(self):
        """Make sure login and logout works"""
        rv = self.login(
                flaskr.app.config['USERNAME'],
                flaskr.app.config['PASSWORD']
            )
        assert 'You were logged in' in rv.data

        rv = self.logout()
        assert 'You were logged out' in rv.data

        # Wrong username
        rv = self.login(
                flaskr.app.config['USERNAME'] + 'x',
                flaskr.app.config['PASSWORD']
            )
        assert 'Invalid Username' in rv.data

        # Wrong password
        rv = self.login(
                flaskr.app.config['USERNAME'],
                flaskr.app.config['PASSWORD'] + 'x'
            )
        assert 'Invalid Password' in rv.data

    def test_messages(self):
        """Test that messages work"""
        self.login(
                flaskr.app.config['USERNAME'],
                flaskr.app.config['PASSWORD']
            )
        rv = self.app.post('/add', data=dict(
                title = '<Hello>',
                text = '<strong>HTML</strong> allowed here'
            ), follow_redirects=True)
        assert 'No entries here so far' not in rv.data
        assert '&lt;Hello&gt;' in rv.data
        assert '<strong>HTML</strong> allowed here' in rv.data

if __name__ == '__main__':
    unittest.main()
