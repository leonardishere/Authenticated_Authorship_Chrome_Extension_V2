'use babel';
import 'authenticated-authorship.js';

var userPosts = document.getElementsByClassName("_1dwg _1w_m _q7o");
var postText;

for (var i = 0; i < userPosts.length; i++) {
	postText = "";
	var post = userPosts[i].getElementsByClassName("_5pbx userContent _3576")[0].getElementsByClassName("text_exposed_root")[0];
	postText += post.getElementsByTagName('p')[0].textContent;
	postText += post.getElementsByTagName('p')[1].textContent;
	//console.log(postText);
	
	// Strip the non-important stuff from the Facebook post due to hiding part of the text
	postText = postText.substring(0, postText.indexOf("...")) + postText.substring(postText.indexOf("...") + 3);
	
	// Testing stuff
	var d = document.createElement('div');
	var test = document.createTextNode(postText);
	d.appendChild(test);
	userPosts[i].appendChild(d);
	
	var processedText;
	if (postText.includes("-----Begin Authenticated Authorship Message-----")) {
		processedText = verify(postText);
		userPosts[i].getElementsByClassName("")[0].textContent = processedText;
	}
	
	// Inject text back into post here
	
}

function verify(postText){
  //get message
  /*let editor = atom.workspace.getActiveTextEditor();
  if(!editor) {
    atom.notifications.addError("Editor does not exist. Try again.");
  }*/

  var trimmedPost = postText.trim();
  var messageIndex = trimmedPost.indexOf("-----Begin Authenticated Authorship Message-----");
  if(messageIndex === -1){
    console.log("The text doesn't contain a valid signature. Try again.");
    console.log("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
    return;
  }

  var startIndex = messageIndex + "-----Begin Authenticated Authorship Message-----".length;
  var endIndex = trimmedPost.lastIndexOf("-----End Authenticated Authorship Message-----");

  if(startIndex === -1 || endIndex === -1 || startIndex > endIndex){
    console.log("The text doesn't contain a valid Authenticated Authorship Message. Try again.");
    console.log("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
    return;
  }

  var endEndIndex = endIndex + "-----End Authenticated Authorship Message-----".length;
  var prefix = trimmedPost.substring(0, messageIndex);
  var suffix = trimmedPost.substring(endEndIndex);
  var signedArticle = trimmedPost.substring(startIndex, endIndex).trim();

  var metaIndex = signedArticle.lastIndexOf("Author:");
  if(metaIndex === -1){
    console.log("The text is missing metadata. Try again.");
    console.log("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
    return;
  }

  var article = signedArticle.substring(0, metaIndex).trim();
  var whitespaceModifiedArticle = article.replace(/\s+/g, " ");

  var metaData = signedArticle.substring(metaIndex);
  var authorIndex = metaData.lastIndexOf("Author:");
  var signatureIndex = metaData.lastIndexOf("Signature:");
  var hashIndex = metaData.lastIndexOf("Hash:");
  var versionIndex = metaData.lastIndexOf("Version:");

  if(authorIndex === -1 || signatureIndex === -1 || hashIndex === -1 || versionIndex === -1){
    console.log("The text is missing metadata. Try again.");
    console.log("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
    return;
  }
  //could add more intelligent parsing, but this will work
  if(authorIndex > signatureIndex || signatureIndex > hashIndex || hashIndex > versionIndex){
    console.log("The metadata has been altered. Try again.")
    console.log("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
    return;
  }

  authorIndex += "Author: ".length;
  var author = metaData.substring(authorIndex, signatureIndex).trim();
  signatureIndex += "Signature: ".length;
  var signature = metaData.substring(signatureIndex, hashIndex).trim();
  hashIndex += "Hash: ".length;
  var hash = metaData.substring(hashIndex, versionIndex).trim();
  versionIndex += "Version: ".length;
  var version = metaData.substring(versionIndex).trim();

  if(!author || !signature || !hash || !version){
    console.log("The text is missing metadata. Try again.");
    console.log("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
    return;
  }

  var self = this;
  var ascii = signature.length % 4 === 0 ? toByteArray(signature) : ""; //string length must be multiple of 4
  var pgpSignature = /*self.*/ascii_to_string(ascii);

  var newHash = this.base64.stringify(this.sha256(whitespaceModifiedArticle));

  //now that metadata is retrieved, verify article against author

  var getAuthorInfoUrl = "https://keybase.io/" + author + "/pgp_keys.asc";
  this.https.get(getAuthorInfoUrl, res => {
    res.setEncoding("utf8");
    var body = "";
    res.on("data", data => {
      body += data;
    });
    res.on("end", () => {
      //body = public key
      self.createPubKeyManager(body, (km) => {
        self.kbpgp.unbox({keyfetch: km, armored: pgpSignature}, (err, literals) => {
          if(err){
            console.log("Article could not be verified. Restart and try again.");
          } else if(!literals || literals.length === 0){
            console.log("Article could not be verified. Restart and try again.");
          }else{
            found = true;
            var originalHashedArticle = literals[0].toString();
            if(newHash !== originalHashedArticle){
              atom.notifications.addError("Signature created by " + author + " but article was edited.");
              var unverifiedArticle = prefix
              + "-----Begin Authenticated Authorship Message-----\n"
              + article + "\n\n"
              + "Signature was created by: " + author + "\n"
              + "But the article was altered.\n"
              + "-----End Authenticated Authorship Message-----\n"
              + suffix;
			  
			  return unverifiedArticle;
			  
              /*let editor = atom.workspace.getActiveTextEditor();
              if(editor) {
                editor.setText(unverifiedArticle);
              }else{
                atom.notifications("Editor could not be read. Try again.");
              }*/

            }else if(originalHashedArticle !== hash){
              //console.log("Signature created by " + author.name + " but article was edited.");
              console.log("Signature created by " + author + " but hash was edited.");
              var unverifiedArticle = prefix
              + "-----Begin Authenticated Authorship Message-----\n"
              + article + "\n\n"
              + "Signature was created by: " + author + "\n"
              + "But the hash was altered.\n"
              + "-----End Authenticated Authorship Message-----\n"
              + suffix;
			  
			  return unverifiedArticle;
			  
              /*let editor = atom.workspace.getActiveTextEditor();
              if(editor) {
                editor.setText(unverifiedArticle);
              }else{
                atom.notifications("Editor could not be read. Try again.");
              }*/

            }else{
              console.log("Verified Article!");

              var verifiedArticle = prefix
              + "-----Begin Authenticated Authorship Message-----\n"
              + article + "\n\n"
              + "Article was signed by: " + author + "\n"
              + "-----End Authenticated Authorship Message-----\n"
              + suffix;
			  
			  return verifiedArticle;

			  /*let editor = atom.workspace.getActiveTextEditor();
              if(editor) {
                editor.setText(verifiedArticle);
              }else{
                atom.notifications("Editor could not be read. Try again.");
              }*/
            }
          }
        });
      });
    });
  });
}

function fetchPosterData(postText) {
	return;
}