'use babel';
import {int32a_to_uint8a, string_to_uint8a, ascii_to_string} from './helper.js';

/**
Define the Authenticated Authorship module.
*/
export default {
  //npm imports. importing inside the export because it keeps them more (but not completely) hidden
  kbpgp: require('kbpgp'),
  fs: require('fs'),
  sha256: require("crypto-js/sha256"),
  base64: require("crypto-js/enc-base64"),
  https: require("https"),
  triplesec: require('triplesec'),
  kbLogin: require("keybase-login"),
  //msgpack: require('msgpack'),
  msgpack: require('msgpack-lite'),
  mpack: require('mpack-js'),
  //typedArrays: require('crypto-js/lib-typedarrays.js'),
  base642: require('base64-js'),
  aes: require('crypto-js/aes'),
  encUtf8: require('crypto-js/enc-utf8'),
//  CryptoJS: require('crypto-js'),

  //some vars
  config: packageConfig,
  modalView: null,
  modalPanel: null,
  modalView2: null,
  modalPanel2: null,
  modalView3: null,
  modalPanel3: null,
  modalView4: null,
  modalPanel4: null,
  subscriptions: null,

  //Activates the module.
  activate(){
    var self = this;

    //modal 1 setup
    this.modalView = new AuthenticatedAuthorshipView();
    this.modalPanel = atom.workspace.addModalPanel({
      item: this.modalView.getElement(),
      visible: false
    });
    //configure modal 1 element listeners
    var loginHandler = this.handleLoginWrapper(self);
    var cancelHandler = this.handleCancelWrapper(self);
    this.modalView.getLoginButton().onclick = loginHandler;
    this.modalView.getCancelButton().onclick = cancelHandler;
    //restore tab and enter functionality to input elements
    this.modalView.getUsernameElement().onkeydown = function(event){
      if(event.key === "Tab"){
        self.modalView.getPasswordElement().focus();
      }else if(event.key === "Enter"){
        loginHandler(); //these were okay as is but I changed them for uniformity
      }else if(event.key === "Escape"){
        cancelHandler();
      }
    };
    this.modalView.getPasswordElement().onkeydown = function(event){
      if(event.key === "Tab"){
        self.modalView.getUsernameElement().focus();
      }else if(event.key === "Enter"){
        loginHandler();
      }else if(event.key === "Escape"){
        cancelHandler();
      }
    };

    //modal 2 setup
    this.modalView2 = new AuthenticatedAuthorshipView2();
    this.modalPanel2 = atom.workspace.addModalPanel({
      item: this.modalView2.getElement(),
      visible: false
    });
    //configure modal 2 element listeners
    var signToTextHandler2 = this.handleSignToTextWrapper2(self);
    var signToHtmlHandler2 = this.handleSignToHtmlWrapper2(self);
    var cancelHandler2 = this.handleCancelWrapper2(self);
    this.modalView2.getSignToTextButton().onclick = signToTextHandler2;
    this.modalView2.getSignToHtmlButton().onclick = signToHtmlHandler2;
    this.modalView2.getCancelButton().onclick = cancelHandler2;
    //restore tab and enter functionality to input elements
    this.modalView2.getUsernameElement().onkeydown = function(event){
      if(event.key === "Tab"){
        if(event.shiftKey){
          self.modalView2.getPrivateKeyElement().focus();
        }else{
          self.modalView2.getPasswordElement().focus();
        }
      }else if(event.key === "Enter"){
        signToTextHandler2();
      }else if(event.key === "Escape"){
        cancelHandler2();
      }
    };
    this.modalView2.getPasswordElement().onkeydown = function(event){
      if(event.key === "Tab"){
        if(event.shiftKey){
          self.modalView2.getUsernameElement().focus();
        }else{
          self.modalView2.getPrivateKeyElement().focus();
        }
      }else if(event.key === "Enter"){
        signToTextHandler2();
      }else if(event.key === "Escape"){
        cancelHandler2();
      }
    };
    this.modalView2.getPrivateKeyElement().onkeydown = function(event){
      if(event.key === "Tab"){
        if(event.shiftKey){
          self.modalView2.getPasswordElement().focus();
        }else{
          self.modalView2.getUsernameElement().focus();
        }
      }else if(event.key === "Enter"){
        signToTextHandler2();
      }else if(event.key === "Escape"){
        cancelHandler2();
      }
    };


    //modal 3 setup
    this.modalView3 = new AuthenticatedAuthorshipStoreKeyView();
    this.modalPanel3 = atom.workspace.addModalPanel({
      item: this.modalView3.getElement(),
      visible: false
    });
    //configure modal 3 element listeners
    var storeToFileHandler = this.handleStoreToFileWrapper(self);
    var cancelHandler3 = this.handleCancelWrapper3(self);
    this.modalView3.getStoreToFileButton().onclick = storeToFileHandler;
    this.modalView3.getCancelStoreButton().onclick = cancelHandler3;
    //restore tab and enter functionality to input elements
    this.modalView3.getPrivateKeyStoreElement().onkeydown = function(event){
      if(event.key === "Tab"){
        if(event.shiftKey){
          self.modalView3.getPasswordStoreRepeatElement().focus();
        }else{
          self.modalView3.getPasswordStoreElement().focus();
        }
      }else if(event.key === "Enter"){
        storeToFileHandler();
      }else if(event.key === "Escape"){
        cancelHandler3();
      }
    };
    this.modalView3.getPasswordStoreElement().onkeydown = function(event){
      if(event.key === "Tab"){
        if(event.shiftKey){
          self.modalView3.getPrivateKeyStoreElement().focus();
        }else{
          self.modalView3.getPasswordStoreRepeatElement().focus();
        }
      }else if(event.key === "Enter"){
        storeToFileHandler();
      }else if(event.key === "Escape"){
        cancelHandler3();
      }
    };
    this.modalView3.getPasswordStoreRepeatElement().onkeydown = function(event){
      if(event.key === "Tab"){
        if(event.shiftKey){
          self.modalView3.getPasswordStoreElement().focus();
        }else{
          self.modalView3.getPrivateKeyStoreElement().focus();
        }
      }else if(event.key === "Enter"){
        storeToFileHandler();
      }else if(event.key === "Escape"){
        cancelHandler3();
      }
    };

    //modal 4 setup
    this.modalView4 = new AuthenticatedAuthorshipView3();
    this.modalPanel4 = atom.workspace.addModalPanel({
      item: this.modalView4.getElement(),
      visible: false
    });
    //configure modal 2 element listeners
    var signToTextHandler4 = this.handleSignToTextWrapper4(self);
    var signToHtmlHandler4 = this.handleSignToHtmlWrapper4(self);
    var cancelHandler4 = this.handleCancelWrapper4(self);
    this.modalView4.getSignToTextButton().onclick = signToTextHandler4;
    this.modalView4.getSignToHtmlButton().onclick = signToHtmlHandler4;
    this.modalView4.getCancelButton().onclick = cancelHandler4;
    //restore tab and enter functionality to input elements
    this.modalView4.getUsernameElement().onkeydown = function(event){
      if(event.key === "Tab"){
        if(event.shiftKey){
          self.modalView4.getPrivateKeyElement().focus();
        }else{
          self.modalView4.getPasswordElement().focus();
        }
      }else if(event.key === "Enter"){
        signToTextHandler4();
      }else if(event.key === "Escape"){
        cancelHandler4();
      }
    };
    this.modalView4.getPasswordElement().onkeydown = function(event){
      if(event.key === "Tab"){
        if(event.shiftKey){
          self.modalView4.getUsernameElement().focus();
        }else{
          self.modalView4.getPrivateKeyElement().focus();
        }
      }else if(event.key === "Enter"){
        signToTextHandler4();
      }else if(event.key === "Escape"){
        cancelHandler4();
      }
    };
    this.modalView4.getPrivateKeyElement().onkeydown = function(event){
      if(event.key === "Tab"){
        if(event.shiftKey){
          self.modalView4.getPasswordElement().focus();
        }else{
          self.modalView4.getUsernameElement().focus();
        }
      }else if(event.key === "Enter"){
        signToTextHandler4();
      }else if(event.key === "Escape"){
        cancelHandler4();
      }
    };


    // Events subscribed to in atom's system can be easily cleaned up with a CompositeDisposable
    this.subscriptions = new CompositeDisposable();

    // Register commands
    this.subscriptions.add(atom.commands.add('atom-workspace', {
      'authenticated-authorship:authenticate': () => this.authenticate(),
      'authenticated-authorship:verify': () => this.verify(),
      'authenticated-authorship:hardware-authenticate': () => this.hardwareAuthenticate(),
      'authenticated-authorship:store-to-file': () => this.storeToFile(),
      'authenticated-authorship:hardware-authenticate2': () => this.hardwareAuthenticate2(),
    }));

    // Register changes in settings
    this.subscriptions.add(atom.config.onDidChange(
      'authenticated-authorship.defaultUsername', (event) => {
        if(event.newValue){
          console.log("Thank you for configuring your system, " + event.newValue + "!");
        }else{
          console.log("Default user cleared.");
        }
        self.modalView.setDefaultUsername(event.newValue);
        self.modalView2.setDefaultUsername(event.newValue);
        self.modalView4.setDefaultUsername(event.newValue);
    }));
    if(atom.config.settings['authenticated-authorship'] && atom.config.settings['authenticated-authorship'].defaultUsername) {
      self.modalView.setDefaultUsername(atom.config.settings['authenticated-authorship'].defaultUsername);
      self.modalView2.setDefaultUsername(atom.config.settings['authenticated-authorship'].defaultUsername);
      self.modalView4.setDefaultUsername(atom.config.settings['authenticated-authorship'].defaultUsername);
    }else{
      self.modalView.setDefaultUsername('');
      self.modalView2.setDefaultUsername('');
      self.modalView4.setDefaultUsername('');
    }
  },

  //Deactivates the module.
  deactivate() {
    this.subscriptions.dispose();
  },

  //The authentication data flow begins here.

  //Just a thin wrapper that displays the login modal.
  authenticate(){
    this.displayModal();
  },

  //Displays the modal.
  displayModal(){
    this.modalPanel.show();
    this.modalView.open();
  },

  //Hides the modal.
  hideModal(){
    this.modalPanel.hide();
  },

  //Hides the modal and clears the inputs.
  exitModal(){
    this.modalPanel.hide();
    this.modalView.clearInput();
  },

  hardwareAuthenticate(){
    this.displayModal2();
  },

  displayModal2(){
    this.modalPanel2.show();
    this.modalView2.open();
  },

  hideModal2(){
    this.modalPanel2.hide();
  },

  exitModal2(){
    this.modalPanel2.hide();
    this.modalView2.clearInput();
  },


  storeToFile(){
    this.displayModal3();
  },

  displayModal3(){
    this.modalPanel3.show();
  },

  hideModal3(){
    this.modalPanel3.hide();
  },

  exitModal3(){
    this.modalPanel3.hide();
    this.modalView3.clearInput();
  },


  hardwareAuthenticate2(){
    this.displayModal4();
  },

  displayModal4(){
    this.modalPanel4.show();
    this.modalView4.open();
  },

  hideModal4(){
    this.modalPanel4.hide();
  },

  exitModal4(){
    this.modalPanel4.hide();
    this.modalView4.clearInput();
  },


  //Creates the function that handles logins.
  //It hurts me to do it this way, but I had to thanks to JavaScript closures.
  handleLoginWrapper(self){
    return function(){
      var username = self.modalView.getUsername();
      var password = self.modalView.getPassword();

      self.modalView.clearInput();
      self.modalPanel.hide();

      self.kbLogin.login(
        {'username': username, 'passphrase': password},
        (err, res)=>{
        if(err) console.log(err);
        else{
          console.log('attempting to decypt private key bundle');

          //step 1: base64 decode
          var step1 = self.base64.parse(res.me.private_keys.primary.bundle);
          //console.log('step1', step1);

          //step 2: messagepack decode
          var uint8a = /*self.*/int32a_to_uint8a(step1.words);
          var step2 = self.mpack.decode(uint8a);
          //console.log('step2:', step2);

          //step 3: triplesec decrypt
          var data = Buffer.from(step2.body.priv.data);
          var key = Buffer.from(password);
          self.triplesec.decrypt(
            {'key': key, 'data': data},
            (err, result)=>{
            if(err){
              console.log('err:', err);
            }else{
              //console.log('result:', result);

              self.createPriKeyManager(username, result, key);
              self.createPriKeyManager(username, key, result);
            }
          });
        }
      });
    }
  },

  //Creates the function that handles logins.
  handleLoginWrapper2(self){
    return function(){
      var username = self.modalView2.getUsername();
      var password = self.modalView2.getPassword();
      var privateKey = self.modalView2.getPrivateKey();

      self.modalView2.clearInput();
      self.modalPanel2.hide();

      self.createPriKeyManager({privateKey: privateKey, password: password})
      .then(keyManager => self.sign({keyManager: keyManager}))
      .then(obj => {
        obj.username = username;
        //self.signToText(obj);
        self.signToHtml(obj);
      })
      .then(message => atom.notifications.addSuccess(message))
      .catch(err => atom.notifications.addError(err));
    }
  },

  //Creates the function that handles signing to text.
  handleSignToHtmlWrapper2(self){
    return function(){
      var username = self.modalView2.getUsername();
      var password = self.modalView2.getPassword();
      var privateKey = self.modalView2.getPrivateKey();

      self.modalView2.clearInput();
      self.modalPanel2.hide();

      self.createPriKeyManager({privateKey: privateKey, password: password})
      .then(keyManager => self.sign({keyManager: keyManager}))
      .then(obj => {
        obj.username = username;
        self.signToHtml(obj);
      })
      .then(message => atom.notifications.addSuccess(message))
      .catch(err => atom.notifications.addError(err));
    }
  },

  //Creates the function that handles signing to text.
  handleSignToTextWrapper2(self){
    return function(){
      var username = self.modalView2.getUsername();
      var password = self.modalView2.getPassword();
      var privateKey = self.modalView2.getPrivateKey();

      self.modalView2.clearInput();
      self.modalPanel2.hide();

      self.createPriKeyManager({privateKey: privateKey, password: password})
      .then(keyManager => self.sign({keyManager: keyManager}))
      .then(obj => {
        obj.username = username;
        self.signToText(obj);
      })
      .then(message => atom.notifications.addSuccess(message))
      .catch(err => atom.notifications.addError(err));
    }
  },

  //Creates the function that handles signing to text.
  handleStoreToFileWrapper(self){
    return function(){
      var privateKey = self.modalView3.getPrivateKeyStore();
      var password = self.modalView3.getPasswordStore();
      var passwordRepeat = self.modalView3.getPasswordStoreRepeat();
      var filename = 'encryptedPrivateKey.aak';

      self.modalView3.clearInput();
      self.modalPanel3.hide();

      // function download(filename, text) {
      //   var element = document.createElement('a');
      //   element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
      //   element.setAttribute('download', filename);
      //
      //   element.style.display = 'none';
      //   document.body.appendChild(element);
      //
      //   element.click();
      //
      //   document.body.removeChild(element);
      // }

      function download(filename, text) {
        var pom = document.createElement('a');
        pom.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
        pom.setAttribute('download', filename);

        if (document.createEvent) {
          var event = document.createEvent('MouseEvents');
          event.initEvent('click', true, true);
          pom.dispatchEvent(event);
        }
        else {
          pom.click();
        }
      }

      if (password === passwordRepeat) {
          var encrypted = self.aes.encrypt(privateKey, password);

          download(filename, encrypted);
      }
      // self.modalView3.clearInput();
      // self.modalPanel3.hide();
      //
      // self.createPriKeyManager({privateKey: privateKey, password: password})
      // .then(keyManager => self.sign({keyManager: keyManager}))
      // .then(obj => {
      //   obj.username = username;
      //   self.signToText(obj);
      // })
      // .then(message => atom.notifications.addSuccess(message))
      // .catch(err => atom.notifications.addError(err));
    }
  },



  //Creates the function that handles logins.
  handleLoginWrapper4(self){
    return function(){
      var username = self.modalView4.getUsername();
      var password = self.modalView4.getPassword();
      var privateKeyTemp = self.modalView4.getPrivateKey();
      var passwordPrivate = self.modalView4.getPasswordPrivate();


      console.log(privateKeyTemp);
      var reader = new FileReader();

      reader.onload = function(e) {
        var privateKeyEncrypted = reader.result;

        console.log(privateKeyEncrypted);
        console.log(passwordPrivate);
        var decrypted = self.aes.decrypt(privateKeyEncrypted, passwordPrivate);
        var privateKey = self.encUtf8.stringify(decrypted);
        console.log(decrypted);
        console.log(privateKey);

        self.modalView4.clearInput();
        self.modalPanel4.hide();

        self.createPriKeyManager({privateKey: privateKey, password: password})
        .then(keyManager => self.sign({keyManager: keyManager}))
        .then(obj => {
          obj.username = username;
          //self.signToText(obj);
          self.signToHtml(obj);
        })
        .then(message => atom.notifications.addSuccess(message))
        .catch(err => atom.notifications.addError(err));
      }

      reader.readAsText(privateKeyTemp);
      console.log(reader);
      //console.log(reader.result);
      //var privateKeyEncrypted = reader.result;


      // reader.addEventListener('load', function (e) {
      //   privateKeyEncrypted = e.target.result;
      // });

      //;

    }
  },

  //Creates the function that handles signing to text.
  handleSignToHtmlWrapper4(self){
    return function(){
      var username = self.modalView4.getUsername();
      var password = self.modalView4.getPassword();
      var privateKeyTemp = self.modalView4.getPrivateKey();
      var passwordPrivate = self.modalView4.getPasswordPrivate();


      console.log(privateKeyTemp);
      var reader = new FileReader();

      reader.onload = function(e) {
        var privateKeyEncrypted = reader.result;

        console.log(privateKeyEncrypted);
        console.log(passwordPrivate);
        var decrypted = self.aes.decrypt(privateKeyEncrypted, passwordPrivate);
        var privateKey = self.encUtf8.stringify(decrypted);
        console.log(decrypted);
        console.log(privateKey);

        self.modalView4.clearInput();
        self.modalPanel4.hide();

        self.createPriKeyManager({privateKey: privateKey, password: password})
        .then(keyManager => self.sign({keyManager: keyManager}))
        .then(obj => {
          obj.username = username;
          self.signToHtml(obj);
        })
        .then(message => atom.notifications.addSuccess(message))
        .catch(err => atom.notifications.addError(err));
      }

      reader.readAsText(privateKeyTemp);
      console.log(reader);
      //console.log(reader.result);
      //var privateKeyEncrypted = reader.result;


    }
  },

  //Creates the function that handles signing to text.
  handleSignToTextWrapper4(self){
    return function(){
      var username = self.modalView4.getUsername();
      var password = self.modalView4.getPassword();
      var privateKeyTemp = self.modalView4.getPrivateKey();
      var passwordPrivate = self.modalView4.getPasswordPrivate();


      console.log(privateKeyTemp);
      var reader = new FileReader();

      reader.onload = function(e) {
        var privateKeyEncrypted = reader.result;

        console.log(privateKeyEncrypted);
        console.log(passwordPrivate);
        var decrypted = self.aes.decrypt(privateKeyEncrypted, passwordPrivate);
        var privateKey = self.encUtf8.stringify(decrypted);
        console.log(decrypted);
        console.log(privateKey);

        self.modalView4.clearInput();
        self.modalPanel4.hide();

        self.createPriKeyManager({privateKey: privateKey, password: password})
        .then(keyManager => self.sign({keyManager: keyManager}))
        .then(obj => {
          obj.username = username;
          self.signToText(obj);
        })
        .then(message => atom.notifications.addSuccess(message))
        .catch(err => atom.notifications.addError(err));
      }

      reader.readAsText(privateKeyTemp);
      console.log(reader);
      //console.log(reader.result);
      //var privateKeyEncrypted = reader.result;


    }
  },




  //Creates the function that handles canceled logins.
  //It hurts me to do it this way, but I had to thanks to JavaScript closures.
  handleCancelWrapper(self){
    return function(){
      self.exitModal();
    }
  },

  //Creates the function that handles canceled logins.
  handleCancelWrapper2(self){
    return function(){
      self.exitModal2();
    }
  },

  //Creates the function that handles canceled logins.
  handleCancelWrapper3(self){
    return function(){
      self.exitModal3();
    }
  },


  //Creates the function that handles canceled logins.
  handleCancelWrapper4(self){
    return function(){
      self.exitModal4();
    }
  },

  //Creates a private key manager.
  //More accurately, returns a promise that returns a private key manager on resolve.
  createPriKeyManager(obj) {
    var key = obj.privateKey;
    var passphrase = obj.password;

    return new Promise((resolve, reject) => {
      this.kbpgp.KeyManager.import_from_armored_pgp({armored: key}, (err, keyManager) => {
        if(err) {
          reject("Error creating private key manager. (1)");
          return;
        }
        if(keyManager.is_pgp_locked()){
          keyManager.unlock_pgp({passphrase: passphrase}, (err) => {
            if(err){
              reject("Error creating private key manager. (2)");
              return;
            }
            resolve(keyManager);
          })
        }else{
          resolve(keyManager);
        }
      });
    });
  },

  //Signs the message.
  //More accurately, returns a promise that will sign the article on resolve.
  sign(obj){
    var priKeyManager = obj.keyManager;

    var self = this;
    let editor = atom.workspace.getActiveTextEditor();
    if(!editor) {
      return new Promise((resolve, reject) => {
        reject("Editor does not exist. Try again.");
      })
    }

    var article = editor.getText();
    var trimmedArticle = article.trim();
    article += "\n\n";
    var whitespaceModifiedArticle = trimmedArticle.replace(/\s+/g, " ");
    var hashedArticle = this.base64.stringify(this.sha256(whitespaceModifiedArticle));

    var params = {
      msg: hashedArticle,
      sign_with: priKeyManager
    };
    return new Promise((resolve, reject) => {
      this.kbpgp.box(params, (err, result_string, result_buffer) => {
        if(err){
          reject("Error boxing the article.");
          return;
        }
        resolve({
          trimmedArticle: trimmedArticle,
          signature: self.base642.fromByteArray(Buffer.from(result_string, "ascii")),
          hash: hashedArticle,
          version: "1.0.0"
        });
      });
    });
  },

  //Signs the article to plain text.
  signToText(obj){
    console.log("signedToText().obj: ", obj);
    var username = obj.username;
    var trimmedArticle = obj.trimmedArticle;
    var signature = obj.signature;
    var hash = obj.hash;
    var version = obj.version;

    let editor = atom.workspace.getActiveTextEditor();
    if(!editor) {
      return new Promise((resolve, reject) => {
        reject("Editor does not exist. Try again.");
      })
    }

    //maybe this promise is extraneous but whatever
    return new Promise((resolve, reject) => {
      var signedArticle = "Use the Trust Project: Authenticated Authorship plugin for Google Chrome to view this signature and validate my identity!\n"
      + "-----Begin Authenticated Authorship Message-----\n"
      + trimmedArticle + "\n"
      + "\n"
      + "Author: " + username + "\n"
      + "Signature: " + signature + "\n"
      + "Hash: " + hash + "\n"
      + "Version: " + version + "\n"
      + "-----End Authenticated Authorship Message-----\n";
      editor.setText(signedArticle);
      resolve("Signed Article!");
    });
  },

  //Signs the article to HTML.
  signToHtml(obj){
    console.log("signedToText().obj: ", obj);
    var username = obj.username;
    var trimmedArticle = obj.trimmedArticle;
    var signature = obj.signature;
    var hash = obj.hash;
    var version = obj.version;

    let editor = atom.workspace.getActiveTextEditor();
    if(!editor) {
      return new Promise((resolve, reject) => {
        reject("Editor does not exist. Try again.");
      })
    }

    //maybe this promise is extraneous but whatever
    return new Promise((resolve, reject) => {
      var signedArticle = '<article class="authenticated_authorship" '
      + 'data-author="' + username + '" '
      + 'data-signature="' + signature + '" '
      + 'data-hash="' + hash + '" '
      + 'data-version="' + version + '">' + '\n'
      + '\t<p>' + trimmedArticle + '</p>' + '\n'
      + '</article>' + '\n';
      editor.setText(signedArticle);
      resolve("Signed Article!");
    });
  },

  //The authentication data flow ends here.

  //The verification data flow begins here.

  //Verifies the message.
  //Currently only verifies plain text messages, not html.
  verify(){
    //get message
    let editor = atom.workspace.getActiveTextEditor();
    if(!editor) {
      atom.notifications.addError("Editor does not exist. Try again.");
    }

    var post = editor.getText();
    var trimmedPost = post.trim();
    var messageIndex = trimmedPost.indexOf("-----Begin Authenticated Authorship Message-----");
    if(messageIndex === -1){
      atom.notifications.addError("The text doesn't contain a valid signature. Try again.");
      atom.notifications.addInfo("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
      return;
    }

    var startIndex = messageIndex + "-----Begin Authenticated Authorship Message-----".length;
    var endIndex = trimmedPost.lastIndexOf("-----End Authenticated Authorship Message-----");

    if(startIndex === -1 || endIndex === -1 || startIndex > endIndex){
      atom.notifications.addError("The text doesn't contain a valid Authenticated Authorship Message. Try again.");
      atom.notifications.addInfo("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
      return;
    }

    var endEndIndex = endIndex + "-----End Authenticated Authorship Message-----".length;
    var prefix = trimmedPost.substring(0, messageIndex);
    var suffix = trimmedPost.substring(endEndIndex);
    var signedArticle = trimmedPost.substring(startIndex, endIndex).trim();

    var metaIndex = signedArticle.lastIndexOf("Author:");
    if(metaIndex === -1){
      atom.notifications.addError("The text is missing metadata. Try again.");
      atom.notifications.addInfo("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
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
      atom.notifications.addError("The text is missing metadata. Try again.");
      atom.notifications.addInfo("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
      return;
    }
    //could add more intelligent parsing, but this will work
    if(authorIndex > signatureIndex || signatureIndex > hashIndex || hashIndex > versionIndex){
      atom.notifications.addError("The metadata has been altered. Try again.")
      atom.notifications.addInfo("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
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
      atom.notifications.addError("The text is missing metadata. Try again.");
      atom.notifications.addInfo("Verifying HTML messages is not yet currently supported. If that is what you are trying to do, then please wait for a developer to get busy :)");
      return;
    }

    var self = this;
    var ascii = signature.length % 4 === 0 ? self.base642.toByteArray(signature) : ""; //string length must be multiple of 4
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
              atom.notifications.addError("Article could not be verified. Restart and try again.");
            } else if(!literals || literals.length === 0){
              atom.notifications.addError("Article could not be verified. Restart and try again.");
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
                let editor = atom.workspace.getActiveTextEditor();
                if(editor) {
                  editor.setText(unverifiedArticle);
                }else{
                  atom.notifications("Editor could not be read. Try again.");
                }

              }else if(originalHashedArticle !== hash){
                //console.log("Signature created by " + author.name + " but article was edited.");
                atom.notifications.addError("Signature created by " + author + " but hash was edited.");
                var unverifiedArticle = prefix
                + "-----Begin Authenticated Authorship Message-----\n"
                + article + "\n\n"
                + "Signature was created by: " + author + "\n"
                + "But the hash was altered.\n"
                + "-----End Authenticated Authorship Message-----\n"
                + suffix;
                let editor = atom.workspace.getActiveTextEditor();
                if(editor) {
                  editor.setText(unverifiedArticle);
                }else{
                  atom.notifications("Editor could not be read. Try again.");
                }

              }else{
                atom.notifications.addSuccess("Verified Article!");

                var verifiedArticle = prefix
                + "-----Begin Authenticated Authorship Message-----\n"
                + article + "\n\n"
                + "Article was signed by: " + author + "\n"
                + "-----End Authenticated Authorship Message-----\n"
                + suffix;

                let editor = atom.workspace.getActiveTextEditor();
                if(editor) {
                  editor.setText(verifiedArticle);
                }else{
                  atom.notifications("Editor could not be read. Try again.");
                }
              }
            }
          });
        });
      });
    });
  },

  //Creates public key manager.
  createPubKeyManager(key, callback){
    var km = null;
    this.kbpgp.KeyManager.import_from_armored_pgp({armored: key}, (err, self) => {
      if(err){
        console.log("Error creating key manager");
      }else{
        callback(self);
      }
    });
  }

  //The verification data flow ends here.
};
