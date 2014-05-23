var C = require('./cryptojs')
var Base = C.lib.Base;
var sha512 = require('./sha512').sha512
var WordArray = require('./word-array')

var HMAC = Base.extend({
  /**
   * Initializes a newly created HMAC.
   *
   * @param {Hasher} hasher The hash algorithm to use.
   * @param {WordArray|string} key The secret key.
   *
   * @example
   *
   *     var hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key);
   */
  init: function (key) {
    // Init hasher
    hasher = this._hasher = new sha512.init()//new hasher.init();

    // Convert string to WordArray, else assume WordArray already
    if (typeof key == 'string') {
      key = WordArray.fromBuffer(new Buffer(key, 'utf8'));
    }

    if (Buffer.isBuffer(key)) {
      key = WordArray.fromBuffer(key)
    }

    // Shortcuts
    var hasherBlockSize = hasher.blockSize;
    var hasherBlockSizeBytes = hasherBlockSize * 4;

    // Allow arbitrary length keys
    if (key.sigBytes > hasherBlockSizeBytes) {
        key = hasher.finalize(key);
    }

    // Clamp excess bits
    key.clamp();

    // Clone key for inner and outer pads
    var oKey = this._oKey = key.clone();
    var iKey = this._iKey = key.clone();

    // Shortcuts
    var oKeyWords = oKey.words;
    var iKeyWords = iKey.words;

    // XOR keys with pad constants
    for (var i = 0; i < hasherBlockSize; i++) {
      oKeyWords[i] ^= 0x5c5c5c5c;
      iKeyWords[i] ^= 0x36363636;
    }
    oKey.sigBytes = iKey.sigBytes = hasherBlockSizeBytes;

    // Set initial values
    this.reset();
  },

  /**
   * Resets this HMAC to its initial state.
   *
   * @example
   *
   *     hmacHasher.reset();
   */
  reset: function () {
    // Shortcut
    var hasher = this._hasher;

    // Reset
    hasher.reset();
    hasher.update(this._iKey);
  },

  /**
   * Updates this HMAC with a message.
   *
   * @param {WordArray|string} messageUpdate The message to append.
   *
   * @return {HMAC} This HMAC instance.
   *
   * @example
   *
   *     hmacHasher.update('message');
   *     hmacHasher.update(wordArray);
   */
  update: function (messageUpdate) {
    if (typeof messageUpdate == 'string')
      messageUpdate = WordArray.fromBuffer(new Buffer(messageUpdate, 'utf8'))

    if (Buffer.isBuffer(messageUpdate))
      messageUpdate = WordArray.fromBuffer(messageUpdate)

    this._hasher.update(messageUpdate);

    // Chainable
    return this;
  },

  /**
   * Finalizes the HMAC computation.
   * Note that the finalize operation is effectively a destructive, read-once operation.
   *
   * @param {WordArray|string} messageUpdate (Optional) A final message update.
   *
   * @return {WordArray} The HMAC.
   *
   * @example
   *
   *     var hmac = hmacHasher.finalize();
   *     var hmac = hmacHasher.finalize('message');
   *     var hmac = hmacHasher.finalize(wordArray);
   */
  finalize: function (messageUpdate) {
     if (typeof messageUpdate == 'string')
      messageUpdate = WordArray.fromBuffer(new Buffer(messageUpdate, 'utf8'))

    if (Buffer.isBuffer(messageUpdate))
      messageUpdate = WordArray.fromBuffer(messageUpdate)

    // Shortcut
    var hasher = this._hasher;

    // Compute HMAC
    var innerHash = hasher.finalize(messageUpdate);
    hasher.reset();
    var hmac = hasher.finalize(this._oKey.clone().concat(innerHash));

    return hmac;
  }
  
});

module.exports = HMAC
