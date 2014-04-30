var sha512 = require('../')

require('terst')

var testVectors = require('./sha512-vectors.test.js')

describe('sha512', function() {
  describe('> when test vectors', function() {
    it('should produce the correct result', function() {
      testVectors.forEach(function(v) {
        var out = sha512(v[0])
        EQ (out.toString(), v[1])
      })
    })
  })
})
