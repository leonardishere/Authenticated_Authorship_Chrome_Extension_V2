'use strict';
'use babel';

//npm imports. importing inside the export because it keeps them more (but not completely) hidden
kbpgp: require('kbpgp');
fs: require('fs');
sha256: require("crypto-js/sha256");
base64: require("crypto-js/enc-base64");
https: require("https");
triplesec: require('triplesec');
kbLogin: require("keybase-login");
//msgpack: require('msgpack');
msgpack: require('msgpack-lite');
mpack: require('mpack-js');
//typedArrays: require('crypto-js/lib-typedarrays.js');
base642: require('base64-js');
aes: require('crypto-js/aes');
encUtf8: require('crypto-js/enc-utf8');
//  CryptoJS: require('crypto-js');

chrome.runtime.onInstalled.addListener(details => {
  console.log('previousVersion', details.previousVersion);
});

console.log('\'Allo \'Allo! Event Page');
