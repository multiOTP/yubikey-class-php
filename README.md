YubiKey PHP class
=================

Yubikey PHP class is a GNU LGPL class to check a YubiKey authentication locally

(c) 2014 SysCo systemes de communication sa  
The Yubikey PHP class is a subset of the multiOTP open source project.  
http://www.multiOTP.net/

Current build: 4.3.1.3 (2014-12-26)

No external file is needed (no PEAR, no PECL).

In Yubico OTP mode, when the YubiKey button is pressed, the returned
string is 44 characters long, with 12 characters for the fixed public id,
and 32 characters for the dynamic OTP part. With the 12 characters of the
public id, the right AES key (the secret) can be retrieved from your user
identification handler to decrypt the dynamic OTP part.


# Usage

    <?php
        require_once('yubikey.class.php');
        $yubikey = new Yubikey();
        $result = $yubikey->CheckYubicoOtp($yubico_modhex_encrypted_part,
                                           $secret,
                                           $last_valid_position);
    ?>


# Possible returned value is one of the following:  
    
              OK  The OTP is valid.
         BAD_OTP  The OTP is invalid format.
    REPLAYED_OTP  The OTP has already been used.

  Check yubikey.demo.php for a full implementation example.
