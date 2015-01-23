YubiKey PHP class
=================

Yubikey PHP class is a GNU LGPL class to check a YubiKey authentication locally

(c) 2014-2015 SysCo systemes de communication sa  
The Yubikey PHP class is a subset of the multiOTP open source project.  
http://www.multiOTP.net/

Current build: 4.3.2.0 (2015-01-04)

No external file is needed (no PEAR, no PECL).

AES 128 encryption and decryption algorithms using pure PHP code (LGPLv2.1)
from Jose Manuel Busto Lopez is directly integrated in the source code.

In Yubico OTP mode, when the YubiKey button is pressed, the returned
string is 44 characters long, with 12 characters for the fixed public id,
and 32 characters for the dynamic OTP part. With the 12 characters of the
public id, the right AES key (the secret) can be retrieved from your user
identification handler to decrypt the dynamic OTP part.


# Usage

    <?php
        require_once('yubikey.class.php');
        $yubikey = new Yubikey();
        $result = $yubikey->checkYubicoOtp($yubico_modhex_encrypted_part,
                                           $secret,
                                           $last_valid_position);
    ?>


# Possible returned value is one of the following:  
    
              OK  The OTP is valid.
         BAD_OTP  The OTP is invalid format.
    REPLAYED_OTP  The OTP has already been used.

  Check yubikey.demo.php for a full implementation example.


You can support our open source projects with donations and sponsoring.
Sponsorships are crucial for ongoing and future development!
If you'd like to support our work, then consider making a donation, any support
is always welcome even if it's as low as $1!
You can also sponsor the development of a specific feature. Please contact
us in order to discuss the detail of the implementation.

**[Donate via PayPal by clicking here][1].** [![Donate via PayPal][2]][1]
[1]: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=N56M9E2SEAUD4
[2]: https://www.paypalobjects.com/webstatic/mktg/logo/pp_cc_mark_37x23.jpg


And for more PHP classes, have a look on [PHPclasses.org](http://syscoal.users.phpclasses.org/browse/), where a lot of authors are sharing their classes for free.
