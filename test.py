import json
import logging
import types
import webapp2
from datetime import datetime, timedelta

import persistentcache
from google.appengine.api import memcache
from google.appengine.ext import db


TEST1_KEY = "test1"
TEST2_KEY = "test2"

# 2 megabyte payload
# (uncomment if you can figure out how to work around appengine's inability to store huge entities)
#TEST2_PAYLOAD = ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.." * 1000) # 31250

class TestModel(db.Model):
    payload = db.TextProperty()
    #blobload = db.BlobProperty()

    def memcache_key(self):
        return self.payload

    @staticmethod
    def getcache(key):
        return persistentcache.get(key)

    def putcache(self, ttl=None):
        # Send this to both persistentcache and the datastore.
        rv = self.put()
        mk = self.memcache_key()
        persistentcache.set(mk, self, ttl)
    
    def deletecache(self):
        mk = self.memcache_key()
        persistentcache.delete(mk)
        self.delete()
        
class CacheTestRequestHandler(webapp2.RequestHandler):
    def report_failure(self, msg=None):
        if msg is not None:
            self.response.write("Error: %s\n" % msg)
        self.response.write("Failure")

    def report_exception(self, e):
        if e is not None:
            import traceback
            msg = "Exception: (%s) %s\n%s" % (type(e).__name__, e.message, traceback.format_exc())
            self.response.write(msg)
            logging.exception(msg)
        self.response.write("Failure")
    
    def report_success(self):
        self.response.write("Success")

    def get(self):
        self.report_failure("Abstract method CacheTestRequestHandler.get called") 

class SetupTest(CacheTestRequestHandler):
    def get(self):
        try:
            e = TestModel(key_name=TEST1_KEY, payload=TEST1_KEY)
            e.putcache()
            #e = TestModel(key_name=TEST2_KEY, payload=TEST2_KEY, blobload=TEST2_PAYLOAD)
            #e.putcache()
            self.report_success()
        except Exception, e:
            self.report_exception(e)

class CleanupTest(CacheTestRequestHandler):
    def get(self):
        try:
            q = TestModel.all()
            n = q.count()
            while n > 0:
                for m in q.run(limit=None):
                    m.deletecache()
                q = TestModel.all()
                n = q.count()
            self.report_success()
        except Exception, e:
            self.report_exception(e)

class TestCacheRetrieve(CacheTestRequestHandler):
    def get(self):
        try:
            # Retrieve a small entity that will fit in one memcache chunk.
            m = TestModel.getcache(TEST1_KEY)
            assert(m is not None)
            assert(m.payload == TEST1_KEY)

            # Retrieve a large entity that will not fit into one memcache chunk.
            #m = TestModel.getcache(TEST2_KEY)
            #assert(m is not None)
            #assert(m.payload == TEST2_PAYLOAD)

            # Make sure that the large entity was properly chunked.
            #test2_mc_key = "%s-overflow-0" % persistentcache.make_pckey(TEST2_KEY)
            #assert(persistentcache.get(test2_mc_key, None, False) is not None)
            
            self.report_success()
        except Exception, e:
            self.report_exception(e)

class SetupTTLTest(CacheTestRequestHandler):
    def get(self):
        try:
            ttl_sec = int(self.request.get("ttl_sec", 5))
            logging.info("Re-caching with TTL=%d seconds." % ttl_sec)
            test1_dict = {'foo': 1, 'bar': 2}
            test2_dict = {'bar': 1, 'foo': 2}
            persistentcache.set("test1_dict", test1_dict, ttl_sec, True)
            persistentcache.set("test2_dict", test2_dict, ttl_sec, False)
            # Deliberately expire from memcache
            memcache.delete("pc2:test1_dict")
            memcache.delete("pc2:test2_dict")
            self.report_success()
        except Exception, e:
            self.report_exception(e)

class RunTTLTest(CacheTestRequestHandler):
    def get(self):
        try:
            # Retrieve objects from cache after ttl expired
            d = persistentcache.get("test1_dict", True, False)
            assert(d is not None)
            assert(d['foo'] == 1)
            assert(d.has_key("ttl"))
            d = persistentcache.get("test2_dict", True, True)
            assert(d is not None)
            assert(d['bar'] == 2)
            assert(d.has_key("ttl"))

            # Try retrieving after ttl expired but without
            # ttl_if_stale; this should result in None.
            d = persistentcache.get("test1_dict")
            assert(d is None)
            d = persistentcache.get("test2_dict")
            assert(d is None)

            self.report_success()
        except Exception, e:
            self.report_exception(e)

# ----------------------------------------------------------------------------------------------------
# APPLICATION
# ----------------------------------------------------------------------------------------------------
application = webapp2.WSGIApplication([
                                       ('/test/setup', SetupTest),
                                       ('/test/cleanup', CleanupTest),
                                       ('/test/test_retrieve', TestCacheRetrieve),
                                       ('/test/setup_ttl', SetupTTLTest),
                                       ('/test/test_ttl', RunTTLTest),
                                       ],
                                      debug=True)
