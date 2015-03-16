#
#
# persistentcache.py
#
# persistentcache ("pc") is a little library for Google App Engine,
# which provides a backing store for memcache.
#
# Copyright (c) 2012 and beyond, Buyer's Best Friend
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

"""
persistentcache ("pc") is a little library for Google App Engine,
which provides a backing store for memcache.
"""

import logging, datetime, cPickle as pickle, base64, zlib, re, time, inspect
from google.appengine.ext import db
# don't bother with versioned_memcache since we're writing to disk
from google.appengine.api import memcache

# on set - if > 1mb - write to multiple memcaches with appended keys (write the zipdata_str)
# on get - attempt to get memcache, otherwise grab db object and unzip + append the zipdata_strs

MAX_CACHED_BYTES = 1000000
OVERFLOW_MAX_BYTES = int(.97 * MAX_CACHED_BYTES)

def now():
  "Obtain the current time."
  return datetime.datetime.now()

def get_caller(depth):
  "Return the name of the calling function at depth (depth)."
  return inspect.stack()[depth][3]

class PersistentCache(db.Model):
  "A model to support caching of objects in coordination with memcache."
  zipdata_str = db.TextProperty(default='')
  ttl_ts = db.DateTimeProperty(name="ttl_ts", default=None)
  creation_ts = db.DateTimeProperty(name="creation_ts", auto_now_add=True, required=True)
  lastmod_ts = db.DateTimeProperty(name="lastmod_ts", auto_now=True, required=True)
  num_overflow_chunks = db.IntegerProperty(indexed=False, default=0)

def cleanse(days):
  "Remove PersistentModel entities that are more than (days) days old."
  very_old_ttl_ts = now() - datetime.timedelta(days)
  for unused in range(100):
    keys = PersistentCache.all(keys_only=True).filter(  # pylint:disable=E1101
        "ttl_ts <", very_old_ttl_ts).order("ttl_ts").fetch(500)    # pylint:disable=E1101
    if len(keys) == 0:
      break
    logging.warning("cleansing %d keys from persistentcache", len(keys))
    db.delete(keys)

def unpack(zipdata_str, unzip=True):
  "Re-inflate a pickled object and return it, or None if the data cannot be reconstituted."
  try:
    return pickle.loads(zlib.decompress(base64.b64decode(zipdata_str))) if unzip else zipdata_str
  except Exception:
    logging.error("ERROR unpacking pc zipdata_str:" + get_caller(depth=4))
    return None

def pack(payload):
  """
  Deflate an object into a lump of pickled data.
  Return the pickled data, or None if the object cannot be pickled.
  """
  try:
    return base64.b64encode(zlib.compress(pickle.dumps(payload)))
  except Exception:
    logging.error("ERROR packing pc zipdata:" + get_caller(depth=4))
    return None

def set_memcache(key, payload, ttl):
  """
  Insert (payload) into memcache with key (key).
  If (ttl) is not None, set the time-to-live value to (ttl).
  """
  # memcache doesn't allow ttl=None as parameter, so use this to cleanup the code
  if ttl:
    memcache.set(key, payload, ttl)
  else:
    memcache.set(key, payload)

KEY_PREFIX = "pc2:"
def make_pckey(key):
  "Construct a module-private key for memcache to use to store our cached objects."
  # make sure key's don't double up on pc2 if passed to itself
  return KEY_PREFIX + re.sub("^" + KEY_PREFIX, '', key)

def set(key, payload, ttl=None, zipped=False): # pylint:disable=W0622
  """ Same semantics as memcache.  We wrap memcache with a disk cache.
      We overflow memcache if the zipped payload is > 1mb, but with no record for the orig pckey
      That miss on the pckey is the signal to get() to look for the Cache disk obj """

  key = make_pckey(key)
  puts = []
  #logging.info('Saving persistent cache to disk and memcache: %s', key)
  cache = PersistentCache(key_name=key)

  zipdata = payload if zipped else pack(payload)

  if len(zipdata) >= OVERFLOW_MAX_BYTES:
    #logging.info("length of zipdata: %d", len(zipdata))
    count = 0
    while len(zipdata) > 0:

      def write_overflow(zipdata):
        "Write a chunk of zipped data to datastore and memcache."
        overflow_key = "%s-overflow-%d" % (key, count)
        #logging.info("setting overflow record:" + overflow_key)
        current_chunk = zipdata[:OVERFLOW_MAX_BYTES]

        overflow_cache = PersistentCache(key_name=overflow_key)
        overflow_cache.zipdata_str = current_chunk
        if ttl:
          overflow_cache.ttl_ts = datetime.datetime.now() + datetime.timedelta(0, ttl)
        puts.append(overflow_cache)

        set_memcache(overflow_key, current_chunk, ttl)
        zipdata = zipdata[OVERFLOW_MAX_BYTES:]
        return zipdata

      zipdata = write_overflow(zipdata)
      count += 1

    cache.num_overflow_chunks = count

    # have to delete the memcache key without any overflow records for the case where one key
    # grows past 1mb between successive set calls
    delete(key)
  else:
    cache.zipdata_str = zipdata
    set_memcache(key, zipdata, ttl)

  if ttl:
    cache.ttl_ts = datetime.datetime.now() + datetime.timedelta(0, ttl)

  puts.append(cache)
  # TODO - is db.put_async faster than one large batch call?
  db.put(puts)

  return payload


def get(key, ttl_if_stale=None, unzip=True):
  """ Attempts to pull from memcache, in case of a miss we'll hit the ds. A miss on the original
      pckey is the signal as well for the zipped data being > 1mb. If that hits we'll cache for
      the remaining time in memcache.
      ttl_if_stale: if a dict is passed, then can return stale data and fill dict with 'ttl'  """
  t_now = datetime.datetime.now()
  key = make_pckey(key)
  try:
    res = memcache.get(key)
  except Exception:
    #logging.error("This should never happen - memcache fails to get on key: " + key)
    return None

  # memcache will always miss on overflow records - they are stored in pckey-overflow-N records
  if res:
    #logging.info('Memcache hit on key (non-overflow): %s' % key)
    return unpack(res, unzip)
  cache = PersistentCache.get_by_key_name(key)
  if cache is None:
    #logging.info('Persistent cache miss for key: %s', key)
    return None

  zipdata_str = cache.zipdata_str
  if cache.num_overflow_chunks > 0:
    for idx in range(0, cache.num_overflow_chunks):
      overflow_key = "%s-overflow-%d" % (key, idx)
      overflow_data = get(overflow_key, ttl_if_stale=ttl_if_stale, unzip=False)
      if overflow_data is None:
        break
      zipdata_str += overflow_data

  if cache.ttl_ts and cache.ttl_ts < t_now:
    if ttl_if_stale is None:
      #logging.info('Persistent cache miss for key: %s', key)
      delete(key)
      return None
    # this will return stale cache, from disk and leave memcache alone.  next hit will
    # also miss unless the caller recomputes, ie async recompute task
    data = unpack(zipdata_str, unzip)
    if isinstance(data, dict):
      data['ttl'] = cache.ttl_ts
    #logging.info("Memcache hit on key (stale but ttl_if_stale=True): %s" % key)
    return data
  elif cache.ttl_ts and cache.num_overflow_chunks > 0:
    # this is still valid, but is no longer stored in memcache.
    # memcache will always miss for the base pc key on overflow recs
    # needs to be reinserted into memcache with the remaining ttl
    ttl_remaining = t_now - cache.ttl_ts
    #logging.info("Persistent cache (ds) hit on key, refreshing memcache: %s" % key)
    set(key, zipdata_str, ttl_remaining.seconds, zipped=True)

  #logging.info('Memcache hit on key (overflow): %s' % key)
  return unpack(zipdata_str, unzip)

def delete(key):
  """ Same semantics as memcache, but also deletes disk copy. """
  # delete disk first, to handle race conditions
  key = make_pckey(key)
  cache = PersistentCache.get_by_key_name(key) # pylint:disable=E1101
  if cache:
    cache.delete()
  memcache.delete(key)

def is_content_type_text(content_type):
  "Return True if the content_type represents text content, False otherwise."
  return content_type.startswith("text/")

def cache_http_response(handler, key, ttl=None):
  """handle binary data properly in python 2.x; for debugging, this is a standalone function."""
  content_type = handler.response.headers.get('Content-Type', "")  # "" = text/html
  out = handler.response.out
  if is_content_type_text(content_type):
    handler.response.charset = "UTF-8"  # needs to be called before resp.out.text
    val = content_type + ":" + out.text
  else:
    # I shit you not dept:
    # https://developers.google.com/appengine/docs/python/tools/webapp/responseclass
    # http://stackoverflow.com/questions/10672796/return-binary-data-by-webob-response
    # http://stackoverflow.com/questions/11606481/anyone-know-how-to-fix-a-unicode-error
    # http://docs.webob.org/en/latest/reference.html#body-app-iter
    # File "/.../pageviewer.py", line 174, in recompute
    # logging.info("calling pc.set(%s, %d bytes, ttl=%d)", pckey, len(resp.out.text)...
    # File "/.../webob-1.1.1/webob/response.py", line 326, in _text__get
    # return body.decode(handler.charset, handler.unicode_errors)
    # File "/.../lib/python2.7/encodings/utf_8.py", line 16, in decode
    # return codecs.utf_8_decode(input, errors, True)
    # UnicodeDecodeError: 'utf8' codec can't decode byte 0xff in position 0: ...
    val = content_type + ":" + ''.join([base64.b64encode(val) for val in out.app_iter])
  logging.info("cache_http_response(%s, %d bytes, ttl=%d)", key, len(val), ttl)
  set(key, val, ttl=ttl)

def get_cas_value(key):
  ''' need to use client.gets(key) if value was set using cas '''
  client = memcache.Client()
  return client.gets(key)

def do_cas(key, func, initial=None):
  ''' atomic functional update to a memcache value
      does NOT use the persistent cache architecture - it could still be pushed from memcache b/c
      of memory pressures
      IMPORTANT: needs to use client.gets() to retrieve any value set with cas
      uses an exponential backoff starting at .01 seconds  with max_tries = 99 '''
  client = memcache.Client()
  delay = .01
  tries = 0
  max_tries = 99
  while True and tries < max_tries:
    obj = client.gets(key)
    if obj is None:
      client.add(key, initial)
      break
    if client.cas(key, func(obj)):
      break
    time.sleep(delay)
    delay = delay * 2
    tries += 1
