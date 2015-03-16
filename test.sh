#/bin/sh
#

# Setup test data.
http GET http://localhost:8089/test/setup

# Test simple retrieval.
http GET http://localhost:8089/test/test_retrieve

#
# Uncomment the following, then fix test.py, to make TTL testing work.
#

# Set up for TTL test by rewriting entity to cache with a 5 second TTL.
#http GET http://localhost:8089/test/setup_ttl\?ttl_sec=5
# Wait for 6 seconds before testing post-TTL retrieval
#sleep 15
# Test retrieval post-TTL.
#http GET http://localhost:8089/test/test_ttl

# Clean up data.
http GET http://localhost:8089/test/cleanup
