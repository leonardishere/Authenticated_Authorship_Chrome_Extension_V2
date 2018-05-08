exports.int32a_to_uint8a = int32a_to_uint8a;
exports.string_to_uint8a = string_to_uint8a;
exports.ascii_to_string = ascii_to_string;

//Converts a word array to a byte array.
function int32a_to_uint8a(arr){
  var arr2 = new Uint8Array(arr.length*4);
  for(var i = 0; i < arr.length; ++i){
    for(var j = 0; j < 4; ++j){
      var num = arr[i] << (j*8);
      num = num >>> 24;
      arr2[i*4+j] = num;
    }
  }
  return arr2;
}

//Converts a string (2 byte elements) to a byte array.
function string_to_uint8a(str){
  var arr = new Uint8Array(str.length*2);
  for(var i = 0; i < str.length; ++i){
    for(var j = 0; j < 2; ++j){
      var num = str[i] << (j*8);
      num = num >>> 8;
      arr[i*2+j] = num;
    }
  }
  return arr;
}

//Converts an ascii array to string.
function ascii_to_string(ascii){
  var str = "";
  for(var i = 0; i < ascii.length; ++i){
    str += String.fromCharCode(ascii[i]);
  }
  return str;
}
