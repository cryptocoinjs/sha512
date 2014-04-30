var C = require('./cryptojs')
var Base = C.lib.Base;
var X32WordArray = C.lib.WordArray;


function X64Word(high, low) {
  this.high = high
  this.low = low
}

function X64WordArray (words, sigBytes) {
  words = this.words = words || [];

  if (sigBytes != undefined) {
      this.sigBytes = sigBytes;
  } else {
      this.sigBytes = words.length * 8;
  }
}

/**
 * Converts this 64-bit word array to a 32-bit word array.
 */
X64WordArray.prototype.toX32 = function () {
  // Shortcuts
  var x64Words = this.words;
  var x64WordsLength = x64Words.length;

  // Convert
  var x32Words = [];
  for (var i = 0; i < x64WordsLength; i++) {
      var x64Word = x64Words[i];
      x32Words.push(x64Word.high);
      x32Words.push(x64Word.low);
  }

  return X32WordArray.create(x32Words, this.sigBytes);
}


module.exports.Word = X64Word
module.exports.WordArray = X64WordArray

