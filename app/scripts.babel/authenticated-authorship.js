'use babel';

function int32a_to_uint8a(arr) {
  var arr2 = new Uint8Array(arr.length * 4);
  for (var i = 0; i < arr.length; ++i) {
    for (var j = 0; j < 4; ++j) {
      var num = arr[i] << j * 8;
      num = num >>> 24;
      arr2[i * 4 + j] = num;
    }
  }
  return arr2;
}

//Converts a string (2 byte elements) to a byte array.
function string_to_uint8a(str) {
  var arr = new Uint8Array(str.length * 2);
  for (var i = 0; i < str.length; ++i) {
    for (var j = 0; j < 2; ++j) {
      var num = str[i] << j * 8;
      num = num >>> 8;
      arr[i * 2 + j] = num;
    }
  }
  return arr;
}

//Converts an ascii array to string.
function ascii_to_string(ascii) {
  var str = "";
  for (var i = 0; i < ascii.length; ++i) {
    str += String.fromCharCode(ascii[i]);
  }
  return str;
}

/**
Define the Authenticated Authorship module.
*/
//npm imports. importing inside the export because it keeps them more (but not completely) hidden
var kbpgp = require('kbpgp');
var fs = require('fs');
var sha256 = require("crypto-js/sha256");
var base64 = require("crypto-js/enc-base64");
var https = require("https");
var triplesec = require('triplesec');
var kbLogin = require("keybase-login");
//msgpack: require('msgpack');
var msgpack = require('msgpack-lite');
var mpack = require('mpack-js');
var typedArrays = require('crypto-js/lib-typedarrays.js');
var base642 = require('base64-js');
var aes = require('crypto-js/aes');
var encUtf8 = require('crypto-js/enc-utf8');
var CryptoJS = require('crypto-js');

//The verification data flow begins here.

//Verifies text messages.
function verifyText(postText, bundle, cb) {
  /*get message
  let editor = atom.workspace.getActiveTextEditor();
  if(!editor) {
    atom.notifications.addError("Editor does not exist. Try again.");
  }*/

  var trimmedPost = postText.trim();
  var messageIndex = trimmedPost.indexOf("-----Begin Authenticated Authorship Message-----");
  if (messageIndex === -1) {

    //console.log("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
    return "The text doesn't contain a valid signature. Try again.";
  }

  var startIndex = messageIndex + "-----Begin Authenticated Authorship Message-----".length;
  var endIndex = trimmedPost.lastIndexOf("-----End Authenticated Authorship Message-----");

  if (startIndex === -1 || endIndex === -1 || startIndex > endIndex) {

    //console.log("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
    return "The text doesn't contain a valid Authenticated Authorship Message. Try again.";
  }

  var endEndIndex = endIndex + "-----End Authenticated Authorship Message-----".length;
  var prefix = trimmedPost.substring(0, messageIndex);
  var suffix = trimmedPost.substring(endEndIndex);
  var signedArticle = trimmedPost.substring(startIndex, endIndex).trim();

  var metaIndex = signedArticle.lastIndexOf("Author:");
  if (metaIndex === -1) {

    //console.log("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
    return "The text is missing metadata. Try again.";
  }

  var article = signedArticle.substring(0, metaIndex).trim();
  var whitespaceModifiedArticle = article.replace(/\s+/g, " ");

  var metaData = signedArticle.substring(metaIndex);
  var authorIndex = metaData.lastIndexOf("Author:");
  var signatureIndex = metaData.lastIndexOf("Signature:");
  var hashIndex = metaData.lastIndexOf("Hash:");
  var versionIndex = metaData.lastIndexOf("Version:");

  if (authorIndex === -1 || signatureIndex === -1 || hashIndex === -1 || versionIndex === -1) {

    //console.log("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
    return "The text is missing metadata. Try again.";
  }
  /*could add more intelligent parsing, but this will work*/
  if (authorIndex > signatureIndex || signatureIndex > hashIndex || hashIndex > versionIndex) {

    //console.log("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
    return "The metadata has been altered. Try again.";
  }

  authorIndex += "Author: ".length;
  var author = metaData.substring(authorIndex, signatureIndex).trim();
  signatureIndex += "Signature: ".length;
  var signature = metaData.substring(signatureIndex, hashIndex).trim();
  hashIndex += "Hash: ".length;
  var hash = metaData.substring(hashIndex, versionIndex).trim();
  versionIndex += "Version: ".length;
  var version = metaData.substring(versionIndex).trim();

  if (!author || !signature || !hash || !version) {

    //console.log("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
    return "The text is missing metadata. Try again.";
  }

  var ascii = signature.length % 4 === 0 ? base642.toByteArray(signature) : ""; /*string length must be multiple of 4*/
  var pgpSignature = /*self.*/ascii_to_string(ascii);

  var newHash = base64.stringify(sha256(whitespaceModifiedArticle));
  var found;
  /*now that metadata is retrieved, verify article against author*/

  var getAuthorInfoUrl = "https://keybase.io/" + author + "/pgp_keys.asc";
  https.get(getAuthorInfoUrl, res => {
    res.setEncoding("utf8");
    var body = "";
    res.on("data", data => {
      body += data;
    });
    res.on("end", function () {
      /*body = public key*/

      createPubKeyManager(body, function (km) {
        kbpgp.unbox({ keyfetch: km, armored: pgpSignature }, function (err, literals) {
          if (err) {
            return "Article could not be verified. Restart and try again.";
          } else if (!literals || literals.length === 0) {
            return "Article could not be verified. Restart and try again.";
          } else {
            found = true;
            var originalHashedArticle = literals[0].toString();
            if (newHash !== originalHashedArticle) {
              console.log("Signature created by " + author + " but article was edited.");
              var unverifiedArticle = prefix + "<br/>-----Begin Authenticated Authorship Message-----<br/>" + article + "<br/><br/>" + "Signature was created by: " + author + "<br/>" + "But the article was altered.<br/>" + "-----End Authenticated Authorship Message-----<br/>" + suffix;
			  cb(unverifiedArticle, false, author, "Signature created by " + author + " but article was edited.", article, bundle);
              /*let editor = atom.workspace.getActiveTextEditor();
              if(editor) {
                editor.setText(unverifiedArticle);
              }else{
                atom.notifications("Editor could not be read. Try again.");
              }*/
            } else if (originalHashedArticle !== hash) {
              //console.log("Signature created by " + author.name + " but article was edited.");
              console.log("Signature created by " + author + " but hash was edited.");
              var unverifiedArticle = prefix + "<br/>-----Begin Authenticated Authorship Message-----<br/>" + article + "<br/><br/>" + "Signature was created by: " + author + "<br/>" + "But the hash was altered.<br/>" + "-----End Authenticated Authorship Message-----<br/>" + suffix;
			  cb(unverifiedArticle, false, author, "Signature created by " + author + " but hash was edited.", article, bundle);
              /*let editor = atom.workspace.getActiveTextEditor();
              if(editor) {
                editor.setText(unverifiedArticle);
              }else{
                atom.notifications("Editor could not be read. Try again.");
              }*/
            } else {
              console.log("Verified Article!");

              var verifiedArticle = prefix + "<br/>-----Begin Authenticated Authorship Message-----<br/>" + article + "<br/><br/>" + "Article was signed by: " + author + "<br/>" + "-----End Authenticated Authorship Message-----<br/>" + suffix;
			  cb(verifiedArticle, true, author, "Article Verified",  article, bundle);
              /*let editor = atom.workspace.getActiveTextEditor();
                       if(editor) {
                         editor.setText(verifiedArticle);
                       }else{
                         atom.notifications("Editor could not be read. Try again.");
                       }*/
            // }
          }
        });
      });
    });
  });
}

//Verified html messages.
function verifyHtml(articleText, articleDataset, bundle, cb){
  var author = articleDataset.author;
  var signature = articleDataset.signature;
  var hash = articleDataset.hash;
  var version = articleDataset.version;
  var whitespaceModifiedArticle = articleText.replace(/\s+/g, " ");

  var ascii = signature.length % 4 === 0 ? base642.toByteArray(signature) : ""; /*string length must be multiple of 4*/
  var pgpSignature = ascii_to_string(ascii);

  var newHash = base64.stringify(sha256(whitespaceModifiedArticle));
  var found;
  /*now that metadata is retrieved, verify article against author*/

  var getAuthorInfoUrl = "https://keybase.io/" + author + "/pgp_keys.asc";
  https.get(getAuthorInfoUrl, res => {
    res.setEncoding("utf8");
    var body = "";
    res.on("data", data => {
      body += data;
    });
    res.on("end", function () {
      /*body = public key*/

      createPubKeyManager(body, function (km) {
        kbpgp.unbox({ keyfetch: km, armored: pgpSignature }, function (err, literals) {
          if (err) {
            return "Article could not be verified. Restart and try again.";
          } else if (!literals || literals.length === 0) {
            return "Article could not be verified. Restart and try again.";
          } else {
            found = true;
            var originalHashedArticle = literals[0].toString();
            if (newHash !== originalHashedArticle) {
              console.log("Signature created by " + author + " but article was edited.");
              var unverifiedArticle = prefix + "<br/>-----Begin Authenticated Authorship Message-----<br/>" + article + "<br/><br/>" + "Signature was created by: " + author + "<br/>" + "But the article was altered.<br/>" + "-----End Authenticated Authorship Message-----<br/>" + suffix;
			        cb(unverifiedArticle, false, author, "Signature created by " + author + " but article was edited.", articleText, bundle);

            } else if (originalHashedArticle !== hash) {
              //console.log("Signature created by " + author.name + " but article was edited.");
              console.log("Signature created by " + author + " but hash was edited.");
              var unverifiedArticle = prefix + "<br/>-----Begin Authenticated Authorship Message-----<br/>" + article + "<br/><br/>" + "Signature was created by: " + author + "<br/>" + "But the hash was altered.<br/>" + "-----End Authenticated Authorship Message-----<br/>" + suffix;
			        cb(unverifiedArticle, false, author, "Signature created by " + author + " but hash was edited.", article, bundle);

            } else {
              console.log("Verified Article!");

              var verifiedArticle = prefix + "<br/>-----Begin Authenticated Authorship Message-----<br/>" + article + "<br/><br/>" + "Article was signed by: " + author + "<br/>" + "-----End Authenticated Authorship Message-----<br/>" + suffix;
			        cb(verifiedArticle, true, author, "Article Verified",  article, bundle);

            }
          }
        });
      });
    });
  });
}

//Creates public key manager.
function createPubKeyManager(key, callback) {
  var km = null;
  this.kbpgp.KeyManager.import_from_armored_pgp({ armored: key }, function (err, self) {
    if (err) {
      console.log("Error creating key manager");
    } else {
      callback(self);
    }
  });
}

function contains(haystack, needle){
  return haystack.indexOf(needle) !== -1;
}

function verifyTextElements(){
  var userPosts = document.getElementsByClassName("_1dwg _1w_m _q7o");
  var postText;
  var processedText;

  for (var i = 0; i < userPosts.length; i++) {
    if(userPosts[i].getElementsByClassName("_5pbx userContent _3576").length == 0 || userPosts[i].getElementsByClassName("_5pbx userContent _3576")[0].getElementsByClassName("text_exposed_root").length == 0) continue;

    postText = "";
    var post = userPosts[i].getElementsByClassName("_5pbx userContent _3576")[0].getElementsByClassName("text_exposed_root")[0];
    if(post.getElementsByTagName('p')[0].length < 2) continue;
    postText += post.getElementsByTagName('p')[0].textContent;
    postText += post.getElementsByTagName('p')[1].textContent;
    /*console.log(postText);

    // Strip the non-important stuff from the Facebook post due to hiding part of the text*/
    postText = postText.substring(0, postText.indexOf("...")) + postText.substring(postText.indexOf("...") + 3);

    /* Testing stuff*/

    /*var test = document.createTextNode(postText);
    d.appendChild(test);
    userPosts[i].appendChild(d);*/

    verifyText(postText, function(verifiedArticle, success, author, failureMessage, article) {
    	processedText = verifiedArticle;
    	var post = userPosts[i].getElementsByClassName("_5pbx userContent _3576")[0].getElementsByClassName("text_exposed_root")[0];
    	//post.getElementsByTagName('p')[0].innerHTML = processedText;
    	//post.getElementsByTagName('p')[1].innerHTML = "";

      if(success){
        post.getElementsByTagName('p')[0].innerHTML = article;
        post.getElementsByTagName('p')[1].innerHTML = "";
        //post.removeChild(post.getElementsByTagName('span'));
        var nestedSpans = post.getElementsByTagName('span');
        for(var i = 0; i < nestedSpans.length; ++i) post.removeChild(nestedSpans[i]);
        var div = document.createElement('div');
        div.style.background = "rgb(66, 103, 178)";
        div.style.color = "rgb(255, 255, 255)";
        div.innerHTML =
        `<p>Article Verified</p>
        <a style="color:white;" href="https://keybase.io/`+author+`">Author: `+author+`</a>`;
        post.insertBefore(div, post.getElementsByTagName('p')[0]);
      }else{
        var div = document.createElement('div');
        div.style.background = "rgb(255, 0, 0)";
        div.style.color = "rgb(255, 255, 255)";
        div.innerHTML = "<p>" + failureMessage + "</p>";
        post.insertBefore(div, post.getElementsByTagName('p')[0]);
      }

    });
  }
}

function treeParse(){
  var firstNode = null;
  var state = 0;
  var buffer = "";
  var workingSet = [];
  workingSet.push(document);
  var otherNodes = [];

  while(workingSet.length > 0){
    var node = workingSet[workingSet.length-1];
    workingSet.pop();
    var justFound = false;

    if(state == 0){ //nothing found yet
      if(node.nodeName === "#text"){
          if(contains(node.textContent, "-----Begin Authenticated Authorship Message-----") || contains(node.textContent, "Use the Trust Project: Authenticated Authorship plugin for Google Chrome to view this signature and validate my identity!")){
          state = 1;
          firstNode = node;
          justFound = true;
        }
      }
    }
    if(state == 1){ //beginning was found
      if(!justFound){
        otherNodes.push(node);
      }
      if(node.nodeName === "#text"){
        buffer += node.textContent;
        if(contains(buffer, "-----End Authenticated Authorship Message-----")){
          //console.log("AA message was found in tree");
          //console.log("message: ", buffer);
          //console.log("first node: ", firstNode);
          var bundle = {'firstNode': firstNode, 'otherNodes': otherNodes};
          verifyText(buffer, bundle, (verifiedArticle, success, author, failureMessage, article, retBundle) => {
            console.log("in callback of article ", article);
          	var processedText = verifiedArticle;
            var retFirstNode = retBundle['firstNode'];
            var retOtherNodes = retBundle['otherNodes'];
            //console.log("returned bundle: ", retBundle);
            console.log("returned first node: ", retFirstNode);
            console.log("returned other nodes: ", retOtherNodes);

            if(success){
              for(var i = 0; i < retOtherNodes.length; ++i){
                retOtherNodes[i].parentNode.removeChild(retOtherNodes[i]);
              }

              var div = document.createElement('div');
              div.style.background = "rgb(66, 103, 178)";
              div.style.color = "rgb(255, 255, 255)";
              div.innerHTML =
              `<p>Article Verified</p>
              <a style="color:white;" href="https://keybase.io/`+author+`">Author: `+author+`</a>`;
              retFirstNode.parentNode.parentNode.insertBefore(div, retFirstNode.parentNode);
              retFirstNode.parentNode.innerText = article;
            }else{
              //clear elements
              for(var i = 0; i < retOtherNodes.length; ++i){
                retOtherNodes[i].parentNode.removeChild(retOtherNodes[i]);
              }

              var div = document.createElement('div');
              div.style.background = "rgb(255, 0, 0)";
              div.style.color = "rgb(255, 255, 255)";
              div.innerHTML = "<p>" + failureMessage + "</p>";
              retFirstNode.parentNode.parentNode.insertBefore(div, retFirstNode.parentNode);
              retFirstNode.parentNode.innerText = article;


            }
          });
          buffer = "";
          firstNode = null;
          state = 0;
          otherNodes = [];
        }
      }
    }

    //add all children nodes
    var childNodes = node.childNodes;
    var elementsToSkip = ["SCRIPT", "INPUT"]; //skip scripts and inputs
    var classesToSkip = ["text_exposed_hide", "navigationFocus", "_1mf"]; //skip "see more", facebook post inputs, and facebook messenger inputs
    for(var i = childNodes.length-1; i >= 0; --i){
      var nodeName = childNodes[i].nodeName;
      var className = childNodes[i].className;
      //console.log("tree parse node ", childNodes[i]);
      var success = true;
      for(var j = 0; j < elementsToSkip.length && success; ++j){
        if(nodeName === elementsToSkip[j]) success = false;
      }
      if(className){
        for(var j = 0; j < classesToSkip.length && success; ++j){
          if(contains(className, classesToSkip[j])) success = false;
        }
      }
      /*
      if(
        childNodes[i].nodeName !== "SCRIPT" &&                      //skip scripts
        childNodes[i].nodeName !== "INPUT" &&                       //skip inputs
        (!childNodes[i].className ||
         !contains(childNodes[i].className, "text_exposed_hide") || //skip the "see more" in facebook
         !contains(childNodes[i].className, "navigationFocus")   || //skip facebook post divs (because they're not input elements? whats up with that)
         !contains(childNodes[i].className, "_1mf")                 //skip facebook messenger input
        )
      )
      */
      if(success){
        workingSet.push(childNodes[i]);
        //console.log("add", childNodes[i]);
      }
      //else console.log("skip", childNodes[i]);
    }
  }
}

function verifyHtmlElements(){
  var articles = document.querySelectorAll("article.authenticated_authorship");
  console.log("articles: ");
  for(var i = 0; i < articles.length; ++i){
    console.log(articles[i]);
    var article = articles[i];
    var articleText = article.innerText;
    var dataset = article.dataset;
    if(!dataset || dataset.status) continue; //failure or already verified
    var status = "";
    var verified = false;
    if(!dataset.author || !dataset.hash || !dataset.signature || !dataset.version){
      status = "Article is missing metadata";
      var div = document.createElement('div');
      div.style.background = "rgb(255, 0, 0)";
      div.style.color = "rgb(255, 255, 255)";
      div.innerHTML = "<p>Article is missing metadata</p>";
      //post.insertBefore(div, post.getElementsByTagName('p')[0]);
      article.parentNode.insertBefore(div, article);

    }else{
      var bundle = {'article': article};
      verifyHtml(articleText, dataset, bundle, (verifiedArticle, success, author, failureMessage, article, retBundle) => {
        verified = success;
        status = failureMessage

        if(success){
          //post.getElementsByTagName('p')[0].innerHTML = article;
          //post.getElementsByTagName('p')[1].innerHTML = "";
          //post.removeChild(post.getElementsByTagName('span'));
          //var nestedSpans = post.getElementsByTagName('span');
          //for(var i = 0; i < nestedSpans.length; ++i) post.removeChild(nestedSpans[i]);
          //var parent = node.parentNode;
          /*
          for(var i = 0; i < retOtherNodes.length; ++i){
            retOtherNodes[i].parentNode.removeChild(retOtherNodes[i]);
          }
          */

          var div = document.createElement('div');
          div.style.background = "rgb(66, 103, 178)";
          div.style.color = "rgb(255, 255, 255)";
          div.innerHTML =
          `<p>Article Verified</p>
          <a style="color:white;" href="https://keybase.io/`+author+`">Author: `+author+`</a>`;
          //post.insertBefore(div, post.getElementsByTagName('p')[0]);
          //retFirstNode.parentNode.parentNode.insertBefore(div, retFirstNode.parentNode);
          //retFirstNode.parentNode.innerText = article;
          bundle.article.parentNode.insertBefore(div, bundle.article);
        }else{
          var div = document.createElement('div');
          div.style.background = "rgb(255, 0, 0)";
          div.style.color = "rgb(255, 255, 255)";
          div.innerHTML = "<p>" + failureMessage + "</p>";
          //post.insertBefore(div, post.getElementsByTagName('p')[0]);
          //retFirstNode.parentNode.insertBefore(div, retFirstNode);
          bundle.article.parentNode.insertBefore(div, bundle.article);
        }

      });
    }
  }
}

window.setInterval(function(){
  //console.log("verify text elements");
  //verifyTextElements();

  //console.log("parse tree");
  treeParse();

  //console.log("verify html elements");
  verifyHtmlElements();
}, 1000);


//The verification data flow ends here.
