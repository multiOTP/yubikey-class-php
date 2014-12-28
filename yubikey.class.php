<?php
/**
 * @file  yubikey.class.php
 * @brief Yubikey LGPLv3 PHP class
 *
 * @mainpage
 *
 * Yubikey PHP class - an all-in-one class to check Yubikey authentication locally.
 * Pure PHP implementation based on the Yubikey Manual, Version 3.3
 * (https://www.yubico.com/wp-content/uploads/2014/10/YubiKey-Manual-v3.3.pdf)
 *
 * No external file is needed (no PEAR, no PECL).
 *
 * The Yubikey PHP class is a subset of the multiOTP open source project.
 *   (http://www.multiOTP.net/)
 *
 * In Yubico OTP mode, when the YubiKey button is pressed, the returned
 * string is 44 characters long, with 12 characters for the fixed public id,
 * and 32 characters for the dynamic OTP part. With the 12 characters of the
 * public id, the right AES key (the secret) can be retrieved from your user
 * identification handler to decrypt the dynamic OTP part.
 *
 * PHP 5.3.0 or higher is supported.
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   4.3.1.3
 * @date      2014-12-25
 * @since     2014-11-04
 * @copyright (c) 2014 SysCo systemes de communication sa
 * @copyright GNU Lesser General Public License
 *
 *//*
 *
 * LICENCE
 *
 *   Copyright (c) 2014 SysCo systemes de communication sa
 *   SysCo (tm) is a trademark of SysCo systemes de communication sa
 *   (http://www.sysco.ch/)
 *   All rights reserved.
 * 
 *   Yubikey PHP class is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public License as
 *   published by the Free Software Foundation, either version 3 of the License,
 *   or (at your option) any later version.
 * 
 *   Yubikey PHP class is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Lesser General Public License for more details.
 * 
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with Yubikey PHP class.
 *   If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Usage
 *
 *   <?php
 *     require_once('yubikey.class.php');
 *     $yubikey = new Yubikey();
 *     $result = $yubikey->CheckYubicoOtp($yubico_modhex_encrypted_part,
 *                                        $secret,
 *                                        $last_valid_position);
 *   ?>
 *
 *   Possible returned value is one of the following:
 *                      OK  The OTP is valid.
 *                 BAD_OTP  The OTP is invalid format.
 *            REPLAYED_OTP  The OTP has already been used.
 *
 *   Check yubikey.demo.php for a full implementation example.
 *
 *
 * Integrated package used
 *
 *   AES128 - AES 128 encryption and description algorithms using pure PHP code (LGPLv2.1)
 *   Jose Manuel Busto Lopez
 *   http://www.phpclasses.org/package/3650-PHP-A-pure-PHP-AES-128-encryption-implementation.html
 *
 *
 * Change Log
 *
 *   2014-12-25 4.3.1.3 SysCo/al Dvorak auto-detection and support for ModHexToHex and CheckYubicoOtp
 *   2014-12-22 4.3.1.2 SysCo/al AES128 integration
 *   2014-11-04 4.3.0.0 SysCo/al Initial release, version number is synchronized with the multiOTP project
 *********************************************************************/

class Yubikey
/**
 * @class     Yubikey
 * @brief     Class definition for Yubikey handling.
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   4.3.1.3
 * @date      2014-12-25
 * @since     2014-11-04
 */
{
    var $_yubikey_last_response      = array();            // YubiKey last response array
	var $_yubico_modhex_chars        = "cbdefghijklnrtuv"; // ModHex values (instead of 0,1,2,3,4,5,6,7,8,9,0,a,b,c,d,e,f)
	var $_yubico_modhex_dvorak_chars = "jxe.uidchtnbpygk"; // Dvorak ModHex values (instead of 0,1,2,3,4,5,6,7,8,9,0,a,b,c,d,e,f)
    var $_yubico_otp_last_count      = -1;                 // Default value of the last otp counter


    // AES stuff, based on Jose Manuel Busto Lopez AES128 library

    var $aes_Sbox = array(
        99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 
        118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 
        114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 
        216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 
        235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214,
        179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203,
        190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69,
        249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 
        188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68,
        23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42,
        144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73,
        6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109,
        141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37,
        46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62,
        181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225,
        248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
        140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22);
    
    var $aes_Sboxi = array(
        82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215,
        251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222,
        233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66,
        250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109,
        139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204,
        93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87,
        167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5,
        184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1,
        19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240,
        180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232,
        28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14,
        170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254,
        120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39,
        128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147,
        201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60,
        131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85,
        33, 12, 125);
    
    var $aes_rcon = array (
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4,
        0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91);
    
    var $aes_T2 = array( 
        0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 
        32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 
        62, 64, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84, 86, 88, 90, 
        92, 94, 96, 98, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 
        122, 124, 126, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 
        152, 154, 156, 158, 160, 162, 164, 166, 168, 170, 172, 174, 176, 178, 180, 
        182, 184, 186, 188, 190, 192, 194, 196, 198, 200, 202, 204, 206, 208, 210, 
        212, 214, 216, 218, 220, 222, 224, 226, 228, 230, 232, 234, 236, 238, 240, 
        242, 244, 246, 248, 250, 252, 254, 27, 25, 31, 29, 19, 17, 23, 21, 
        11, 9, 15, 13, 3, 1, 7, 5, 59, 57, 63, 61, 51, 49, 55, 
        53, 43, 41, 47, 45, 35, 33, 39, 37, 91, 89, 95, 93, 83, 81, 
        87, 85, 75, 73, 79, 77, 67, 65, 71, 69, 123, 121, 127, 125, 115, 
        113, 119, 117, 107, 105, 111, 109, 99, 97, 103, 101, 155, 153, 159, 157, 
        147, 145, 151, 149, 139, 137, 143, 141, 131, 129, 135, 133, 187, 185, 191, 
        189, 179, 177, 183, 181, 171, 169, 175, 173, 163, 161, 167, 165, 219, 217, 
        223, 221, 211, 209, 215, 213, 203, 201, 207, 205, 195, 193, 199, 197, 251, 
        249, 255, 253, 243, 241, 247, 245, 235, 233, 239, 237, 227, 225, 231, 229);
    
    var $aes_T3 = array( 
        0, 3, 6, 5, 12, 15, 10, 9, 24, 27, 30, 29, 20, 23, 18, 17, 
        48, 51, 54, 53, 60, 63, 58, 57, 40, 43, 46, 45, 36, 39, 34, 
        33, 96, 99, 102, 101, 108, 111, 106, 105, 120, 123, 126, 125, 116, 119, 
        114, 113, 80, 83, 86, 85, 92, 95, 90, 89, 72, 75, 78, 77, 68, 
        71, 66, 65, 192, 195, 198, 197, 204, 207, 202, 201, 216, 219, 222, 221, 
        212, 215, 210, 209, 240, 243, 246, 245, 252, 255, 250, 249, 232, 235, 238, 
        237, 228, 231, 226, 225, 160, 163, 166, 165, 172, 175, 170, 169, 184, 187, 
        190, 189, 180, 183, 178, 177, 144, 147, 150, 149, 156, 159, 154, 153, 136, 
        139, 142, 141, 132, 135, 130, 129, 155, 152, 157, 158, 151, 148, 145, 146, 
        131, 128, 133, 134, 143, 140, 137, 138, 171, 168, 173, 174, 167, 164, 161, 
        162, 179, 176, 181, 182, 191, 188, 185, 186, 251, 248, 253, 254, 247, 244, 
        241, 242, 227, 224, 229, 230, 239, 236, 233, 234, 203, 200, 205, 206, 199, 
        196, 193, 194, 211, 208, 213, 214, 223, 220, 217, 218, 91, 88, 93, 94, 
        87, 84, 81, 82, 67, 64, 69, 70, 79, 76, 73, 74, 107, 104, 109, 
        110, 103, 100, 97, 98, 115, 112, 117, 118, 127, 124, 121, 122, 59, 56, 
        61, 62, 55, 52, 49, 50, 35, 32, 37, 38, 47, 44, 41, 42, 11, 
        8, 13, 14, 7, 4, 1, 2, 19, 16, 21, 22, 31, 28, 25, 26);
    
    var $aes_T9 = array( 
        0, 9, 18, 27, 36, 45, 54, 63, 72, 65, 90, 83, 108, 101, 126, 119, 
        144, 153, 130, 139, 180, 189, 166, 175, 216, 209, 202, 195, 252, 245, 238, 
        231, 59, 50, 41, 32, 31, 22, 13, 4, 115, 122, 97, 104, 87, 94, 
        69, 76, 171, 162, 185, 176, 143, 134, 157, 148, 227, 234, 241, 248, 199, 
        206, 213, 220, 118, 127, 100, 109, 82, 91, 64, 73, 62, 55, 44, 37, 
        26, 19, 8, 1, 230, 239, 244, 253, 194, 203, 208, 217, 174, 167, 188, 
        181, 138, 131, 152, 145, 77, 68, 95, 86, 105, 96, 123, 114, 5, 12, 
        23, 30, 33, 40, 51, 58, 221, 212, 207, 198, 249, 240, 235, 226, 149, 
        156, 135, 142, 177, 184, 163, 170, 236, 229, 254, 247, 200, 193, 218, 211, 
        164, 173, 182, 191, 128, 137, 146, 155, 124, 117, 110, 103, 88, 81, 74, 
        67, 52, 61, 38, 47, 16, 25, 2, 11, 215, 222, 197, 204, 243, 250, 
        225, 232, 159, 150, 141, 132, 187, 178, 169, 160, 71, 78, 85, 92, 99, 
        106, 113, 120, 15, 6, 29, 20, 43, 34, 57, 48, 154, 147, 136, 129, 
        190, 183, 172, 165, 210, 219, 192, 201, 246, 255, 228, 237, 10, 3, 24, 
        17, 46, 39, 60, 53, 66, 75, 80, 89, 102, 111, 116, 125, 161, 168, 
        179, 186, 133, 140, 151, 158, 233, 224, 251, 242, 205, 196, 223, 214, 49, 
        56, 35, 42, 21, 28, 7, 14, 121, 112, 107, 98, 93, 84, 79, 70);
    
    var $aes_T11 = array( 
        0, 11, 22, 29, 44, 39, 58, 49, 88, 83, 78, 69, 116, 127, 98, 105, 
        176, 187, 166, 173, 156, 151, 138, 129, 232, 227, 254, 245, 196, 207, 210, 
        217, 123, 112, 109, 102, 87, 92, 65, 74, 35, 40, 53, 62, 15, 4, 
        25, 18, 203, 192, 221, 214, 231, 236, 241, 250, 147, 152, 133, 142, 191, 
        180, 169, 162, 246, 253, 224, 235, 218, 209, 204, 199, 174, 165, 184, 179, 
        130, 137, 148, 159, 70, 77, 80, 91, 106, 97, 124, 119, 30, 21, 8, 
        3, 50, 57, 36, 47, 141, 134, 155, 144, 161, 170, 183, 188, 213, 222, 
        195, 200, 249, 242, 239, 228, 61, 54, 43, 32, 17, 26, 7, 12, 101, 
        110, 115, 120, 73, 66, 95, 84, 247, 252, 225, 234, 219, 208, 205, 198, 
        175, 164, 185, 178, 131, 136, 149, 158, 71, 76, 81, 90, 107, 96, 125, 
        118, 31, 20, 9, 2, 51, 56, 37, 46, 140, 135, 154, 145, 160, 171, 
        182, 189, 212, 223, 194, 201, 248, 243, 238, 229, 60, 55, 42, 33, 16, 
        27, 6, 13, 100, 111, 114, 121, 72, 67, 94, 85, 1, 10, 23, 28, 
        45, 38, 59, 48, 89, 82, 79, 68, 117, 126, 99, 104, 177, 186, 167, 
        172, 157, 150, 139, 128, 233, 226, 255, 244, 197, 206, 211, 216, 122, 113, 
        108, 103, 86, 93, 64, 75, 34, 41, 52, 63, 14, 5, 24, 19, 202, 
        193, 220, 215, 230, 237, 240, 251, 146, 153, 132, 143, 190, 181, 168, 163);
    
    var $aes_T13 = array( 
        0, 13, 26, 23, 52, 57, 46, 35, 104, 101, 114, 127, 92, 81, 70, 75, 
        208, 221, 202, 199, 228, 233, 254, 243, 184, 181, 162, 175, 140, 129, 150, 
        155, 187, 182, 161, 172, 143, 130, 149, 152, 211, 222, 201, 196, 231, 234, 
        253, 240, 107, 102, 113, 124, 95, 82, 69, 72, 3, 14, 25, 20, 55, 
        58, 45, 32, 109, 96, 119, 122, 89, 84, 67, 78, 5, 8, 31, 18, 
        49, 60, 43, 38, 189, 176, 167, 170, 137, 132, 147, 158, 213, 216, 207, 
        194, 225, 236, 251, 246, 214, 219, 204, 193, 226, 239, 248, 245, 190, 179, 
        164, 169, 138, 135, 144, 157, 6, 11, 28, 17, 50, 63, 40, 37, 110, 
        99, 116, 121, 90, 87, 64, 77, 218, 215, 192, 205, 238, 227, 244, 249, 
        178, 191, 168, 165, 134, 139, 156, 145, 10, 7, 16, 29, 62, 51, 36, 
        41, 98, 111, 120, 117, 86, 91, 76, 65, 97, 108, 123, 118, 85, 88, 
        79, 66, 9, 4, 19, 30, 61, 48, 39, 42, 177, 188, 171, 166, 133, 
        136, 159, 146, 217, 212, 195, 206, 237, 224, 247, 250, 183, 186, 173, 160, 
        131, 142, 153, 148, 223, 210, 197, 200, 235, 230, 241, 252, 103, 106, 125, 
        112, 83, 94, 73, 68, 15, 2, 21, 24, 59, 54, 33, 44, 12, 1, 
        22, 27, 56, 53, 34, 47, 100, 105, 126, 115, 80, 93, 74, 71, 220, 
        209, 198, 203, 232, 229, 242, 255, 180, 185, 174, 163, 128, 141, 154, 151);
    
    var $aes_T14 = array ( 
        0, 14, 28, 18, 56, 54, 36, 42, 112, 126, 108, 98, 72, 70, 84, 90, 
        224, 238, 252, 242, 216, 214, 196, 202, 144, 158, 140, 130, 168, 166, 180, 
        186, 219, 213, 199, 201, 227, 237, 255, 241, 171, 165, 183, 185, 147, 157, 
        143, 129, 59, 53, 39, 41, 3, 13, 31, 17, 75, 69, 87, 89, 115, 
        125, 111, 97, 173, 163, 177, 191, 149, 155, 137, 135, 221, 211, 193, 207, 
        229, 235, 249, 247, 77, 67, 81, 95, 117, 123, 105, 103, 61, 51, 33, 
        47, 5, 11, 25, 23, 118, 120, 106, 100, 78, 64, 82, 92, 6, 8, 
        26, 20, 62, 48, 34, 44, 150, 152, 138, 132, 174, 160, 178, 188, 230, 
        232, 250, 244, 222, 208, 194, 204, 65, 79, 93, 83, 121, 119, 101, 107, 
        49, 63, 45, 35, 9, 7, 21, 27, 161, 175, 189, 179, 153, 151, 133, 
        139, 209, 223, 205, 195, 233, 231, 245, 251, 154, 148, 134, 136, 162, 172, 
        190, 176, 234, 228, 246, 248, 210, 220, 206, 192, 122, 116, 102, 104, 66, 
        76, 94, 80, 10, 4, 22, 24, 50, 60, 46, 32, 236, 226, 240, 254, 
        212, 218, 200, 198, 156, 146, 128, 142, 164, 170, 184, 182, 12, 2, 16, 
        30, 52, 58, 40, 38, 124, 114, 96, 110, 68, 74, 88, 86, 55, 57, 
        43, 37, 15, 1, 19, 29, 71, 73, 91, 85, 127, 113, 99, 109, 215, 
        217, 203, 197, 239, 225, 243, 253, 167, 169, 187, 181, 159, 145, 131, 141);
    
    var $aes_Nr=10; // The number of rounds in AES Cipher.
    var $aes_Nb=4;  // The number of columns comprising a state in AES. This is a constant in AES. Value=4
    var $aes_Nk=4;  // The number of 32 bit words in a key.
    var $aes_state=array(array());
    var $aes_shifts_r=array(array(0, 1, 2, 3),array(3, 0, 1, 2),array(2, 3, 0, 1),array(1, 2, 3, 0));
    var $aes_shifts_l=array(array(0, 1, 2, 3),array(1, 2, 3, 0),array(2, 3, 0, 1),array(3, 0, 1, 2));
    
   
    function AesKeyAddition($rk) {
        //Para cada ronda hacemos una XOR entre aes_Sbox[i][j] y rk[round][i][j].
       for($i = 0; $i < 4; $i++)
            for($j = 0; $j < $this->aes_Nb; $j++)
                $this->aes_state[$i][$j] ^= $rk[$i][$j];
    }


    function AesByteSubShiftRow(){
        $tmp= array(array());
        for($i = 0; $i < 4; $i++)
            for($j = 0; $j < $this->aes_Nb; $j++)                
                $tmp[$i][$this->aes_shifts_r[$i][$j]]= $this->aes_Sbox[$this->aes_state[$i][$j]];
        $this->aes_state=$tmp;
    }


    function AesMixColumnKeyAddition($rk){
        $b= array(array());
        for($j = 0; $j < 4; $j++)
            for($i = 0; $i < $this->aes_Nb; $i++){
                $b[$i][$j] = $this->aes_T2[$this->aes_state[$i][$j]] ^ $this->aes_T3[$this->aes_state[($i + 1) % 4][$j]] ^ $this->aes_state[($i + 2) % 4][$j] ^ $this->aes_state[($i + 3) % 4][$j];
                $b[$i][$j]^=$rk[$i][$j];
            }
        $this->aes_state = $b;
    }


    function AesInvMixColumn() {
        $b= array(array());
        for($j = 0; $j < 4; $j++)
            for($i = 0; $i < $this->aes_Nb; $i++)
                $b[$i][$j] = $this->aes_T14[$this->aes_state[$i][$j]] ^ $this->aes_T11[$this->aes_state[($i + 1) % 4][$j]] ^ $this->aes_T13[$this->aes_state[($i + 2) % 4][$j]] ^ $this->aes_T9[$this->aes_state[($i + 3) % 4][$j]];
         $this->aes_state = $b;
    }

    
    function AesInvShiftRowInvByteSub() {
        $tmp= array(array());
        for($i = 0; $i < 4; $i++)
            for($j = 0; $j < $this->aes_Nb; $j++)
                $tmp[$i][$this->aes_shifts_l[$i][$j]]= $this->aes_Sboxi[$this->aes_state[$i][$j]];
        $this->aes_state=$tmp;
    }  

    
    function AesMakeKey($hash){
        $rconpocharer = 0;
        $tk=array(array());;
        $rk=array(array(array()));
        for($j = 0; $j < $this->aes_Nk; $j++)
            for($i = 0; $i < 4; $i++)
                $tk[$i][$j] = ord($hash{$j*4+$i})>256 ? ord($hash{$j*4+$i})%256 : ord($hash{$j*4+$i});
        $t = 0;
        
        for($j = 0; ($j < $this->aes_Nk) && ($t < ($this->aes_Nr+1)*$this->aes_Nb); $j++, $t++)
            for($i = 0; $i < 4; $i++)
                $rk[$t / $this->aes_Nb][$i][$t % $this->aes_Nb] = $tk[$i][$j];
        while ($t < ($this->aes_Nr+1)*$this->aes_Nb) {
            
            for($i = 0; $i < 4; $i++) 
                $tk[$i][0] ^= $this->aes_Sbox[$tk[($i+1)%4][$this->aes_Nk-1]];
            $tk[0][0] ^= $this->aes_rcon[$rconpocharer++];
            for($j = 1; $j < $this->aes_Nk; $j++)
                for($i = 0; $i < 4; $i++){
                     $tk[$i][$j] ^= $tk[$i][$j-1];
                }
            for($j = 0; ($j < $this->aes_Nk) && ($t < ($this->aes_Nr+1)*$this->aes_Nb); $j++, $t++)
                for($i = 0; $i < 4; $i++) {
                    $rk[$t / $this->aes_Nb][$i][$t % $this->aes_Nb] = $tk[$i][$j];
                }
        }
        return $rk;
    }


    function AesBlockEncrypt($in, $key){
        
        for ($i=0; $i<4; $i++){
            for ($j=0; $j<$this->aes_Nb; $j++){
                $this->aes_state[$j][$i]=ord($in{$i*4+$j});
            }
        }
        $this->AesKeyAddition($key[0]);
        for($r = 1; $r < $this->aes_Nr; $r++) {
            $this->AesByteSubShiftRow();
            $this->AesMixColumnKeyAddition($key[$r]);
         }
        $this->AesByteSubShiftRow();
        $this->AesKeyAddition($key[$this->aes_Nr]);
        $out="";
        for($i=0; $i<4; $i++)
          for ($j=0; $j<4; $j++)
            $out.=chr($this->aes_state[$j][$i]);
        return $out;
    }


    function AesBlockDecrypt($in, $key) {
        
        for ($i=0; $i<4; $i++){
            for ($j=0; $j<$this->aes_Nb; $j++){
                $this->aes_state[$j][$i]=ord($in{$i*4+$j});
            }
        }
        $this->AesKeyAddition($key[$this->aes_Nr]);
        for($r = $this->aes_Nr-1; $r > 0; $r--) {
            $this->AesInvShiftRowInvByteSub();
            $this->AesKeyAddition($key[$r]);
            $this->AesInvMixColumn();
         }
        $this->AesInvShiftRowInvByteSub();  
        $this->AesKeyAddition($key[0]);
        $out="";
        for($i=0; $i<4; $i++)
          for ($j=0; $j<4; $j++)
            $out.=chr($this->aes_state[$j][$i]);  
        return $out;
    }


    function Iso13239Crc16($buffer)
    // http://forum.yubico.com/viewtopic.php?f=2&t=69
    {
        $crc = 0xffff;
        for($loop=0; $loop<strlen($buffer); $loop++)
        {
            $crc ^= ord($buffer[$loop]) & 0xff;
            for ($bit=0; $bit<8; $bit++)
            {
                $j=$crc & 1;
                $crc >>= 1;
                if ($j)
                {
                    $crc ^= 0x8408;
                }
            }
        }
        return $crc;
    }


    function CheckYubicoOtp($yubico_modhex_encrypted_part,
                            $secret,
                            $last_count = -1,
                            $dvorak_only = FALSE)
    {
        $result = "BAD_OTP";

        $encrypted_part = hex2bin($this->ModHexToHex($yubico_modhex_encrypted_part, $dvorak_only));
        $decrypted_part = $this->AesBlockDecrypt($encrypted_part, $this->AesMakeKey(hex2bin($secret)));

        $uid        = bin2hex(substr($decrypted_part,  0, 6));
        $useCtr     = ord($decrypted_part[6]) + 256 * ord($decrypted_part[7]);
        $tstp       = ord($decrypted_part[8]) + 256 * ord($decrypted_part[9]) + 65536 * ord($decrypted_part[10]);
        $sessionCtr = ord($decrypted_part[11]);
        $rnd        = ord($decrypted_part[12]) + 256 * ord($decrypted_part[13]);
        $crc        = ord($decrypted_part[14]) + 256 * ord($decrypted_part[15]);
        $check_crc  = $this->Iso13239Crc16($decrypted_part);
        
        $this->_yubikey_last_response['uid']        = $uid;
        $this->_yubikey_last_response['useCtr']     = $useCtr;
        $this->_yubikey_last_response['tstp']       = $tstp;
        $this->_yubikey_last_response['sessionCtr'] = $sessionCtr;
        $this->_yubikey_last_response['rnd']        = $rnd;
        $this->_yubikey_last_response['crc']        = $crc;

        // Based on information available here: https://www.yubico.com/wp-content/uploads/2014/10/YubiKey-Manual-v3.3.pdf
        //
        // $uid         Private (secret) ID
        // $useCtr      Usage counter, non-volatile counter, incremented when device is used after a power-up or reset
        // $tstp        Timestamp, 8Hz, random value startup, wraps from 0xffffff to 0 (after 24 days)
        // $sessionCtr  Session usage counter, set to 0 at power-up, incremented by one after each generation
        // $rnd         Random number
        // $crc         Checksum, 16-bit ISO13239 1st complement checksum of the first 14 bytes, result added to the end
        //                $crc = 0xffff - $this->Iso13239Crc16(substr($decrypted_part, 0, 14)); // One's complement
        // $check_crc   Calculate the ISO13239 of the 16 bits, should give a fixed residual of 0xf0b8 if checksum is valid

        if (0xf0b8 == $check_crc) // Check should always give 0xf0b8
        {
            $counter_position = ($useCtr * 256) + $sessionCtr;
            if ($counter_position <= $last_count)
            {
                $result = "REPLAYED_OTP"; // ERROR: this token has already been used
            }
            else
            {
                $this->_yubico_otp_last_count = $counter_position;
                $result = "OK";
            }
        }
        elseif ((!$dvorak_only) && $this->IsModHex($yubico_modhex_encrypted_part) && $this->IsDvorakModHex($yubico_modhex_encrypted_part))
        {
            $result = $this->CheckYubicoOtp($yubico_modhex_encrypted_part,
                                            $secret,
                                            $last_count,
                                            TRUE); // Check for Dvorak only
        }
        return $result;
    }


    function GetYubikeyLastResponse()
    {
        return $this->_yubikey_last_response;
    }


    function GetYubicoOtpLastCount()
    {
        return $this->_yubico_otp_last_count;
    }


    function IsModHex($modhex)
    {
        $result = FALSE;
        if (0 == (strlen($modhex) % 2))
        {
            for ($loop = 0; $loop < strlen($modhex); $loop++)
            {
                $value = strpos($this->_yubico_modhex_chars, strtolower($modhex[$loop]));
                if (FALSE === $value)
                {
                    return FALSE;
                }
            }
            $result = TRUE;
        }
		return $result;		
    }


    function IsDvorakModHex($modhex)
    {
        $result = FALSE;
        if (0 == (strlen($modhex) % 2))
        {
            for ($loop = 0; $loop < strlen($modhex); $loop++)
            {
                $value = strpos($this->_yubico_modhex_dvorak_chars, strtolower($modhex[$loop]));
                if (FALSE === $value)
                {
                    return FALSE;
                }
            }
            $result = TRUE;
        }
		return $result;		
    }


	function HexToModHex($hexa)
    {
        $result = '';
        if (0 == (strlen($hexa) % 2))
        {
            for ($loop = 0; $loop < strlen($hexa); $loop++)
            {
                $value = hexdec(strtolower($hexa[$loop]));
                if ($value > 15)
                {
                    return FALSE;
                }
                $result.= $this->_yubico_modhex_chars[$value];
            }
        }
        else
        {
            $result = FALSE;
        }
		return $result;		
	}
    
    
	function ModHexToHex($modhex, $force_dvorak = FALSE)
    {
        $result = '';
        if ($this->IsModHex($modhex) && (!$force_dvorak))
        {
            for ($loop = 0; $loop < strlen($modhex); $loop++)
            {
                $value = strpos($this->_yubico_modhex_chars, strtolower($modhex[$loop]));
                $result.= dechex($value);
            }
        }
        elseif ($this->IsDvorakModHex($modhex))
        {
            for ($loop = 0; $loop < strlen($modhex); $loop++)
            {
                $value = strpos($this->_yubico_modhex_dvorak_chars, strtolower($modhex[$loop]));
                $result.= dechex($value);
            }
        }
        else
        {
            $result = FALSE;
        }
		return $result;		
	}
}
?>