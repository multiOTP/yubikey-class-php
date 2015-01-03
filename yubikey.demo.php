<?php
/**
 * @file  yubikey.demo.php
 * @brief Yubikey LGPLv3 PHP class demo implementation
 *
 * @mainpage
 *
 * This is a small demo implementation of the Yubikey PHP class.
 *
 * PHP 5.3.0 or higher is supported.
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   4.3.2.0
 * @date      2015-01-04
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
 *   This file is part of the Yubikey PHP class.
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
 * Change Log
 *
 *   2014-01-04 4.3.2.0 SysCo/al Some modifications for future PSR compliance (http://www.php-fig.org/)
 *   2014-12-26 4.3.1.3 SysCo/al Additional detailed information
 *   2014-12-22 4.3.1.2 SysCo/al Detailed response information
 *   2014-11-04 4.3.0.0 SysCo/al Initial release, version number is synchronized with the multiOTP project
 *********************************************************************/
    
    require_once('yubikey.class.php');
    
    $focus_field = "secret";

    $otp_to_check = trim(isset($_POST['otp'])?$_POST['otp']:'');
    $secret = trim(isset($_POST['secret'])?$_POST['secret']:'');
    $last_valid_position = trim(isset($_POST['last_valid_position'])?$_POST['last_valid_position']:'');
    
    $result = "";
    $detail_result = "";

    if (0 != strlen($otp_to_check)) {
        $yubikey = new Yubikey();
        $result = $yubikey->checkYubicoOtp(substr($otp_to_check,12),
                                           $secret,
                                           $last_valid_position);

        $detail_result.= "<hr />";
        $detail_result.= "OTP to check: <b>$otp_to_check</b>\n";
        $detail_result.= "<br />";
        $detail_result.= "Serial number: <b>".substr($otp_to_check,0,12)."</b>\n";
        $detail_result.= "<br />";
        $detail_result.= "Local check result: <b>$result</b>\n";

        if ("OK" == $result) {
            $last_valid_position = $yubikey->getYubicoOtpLastCount();
            $detail_result.= "<br />";
            $detail_result.= "Last valid position: <b>".$last_valid_position."</b>\n";
            $focus_field = "otp";
        }
        
        $detail_result.= "<br /><br />\n";
        
        $detail_result.= "Detailed response: <br />\n";
        $detail_result.= "<table>\n";
        
        foreach($yubikey->getYubikeyLastResponse() as $key=>$value) {
            $detail_result.= "<tr><td>$key ";
            $detail_result.= " :</td><td><b>$value</b></td><td><i>";
            switch ($key) {
                case "uid":
                    $detail_result.= "Private (secret) ID";
                    break;
                case "useCtr":
                    $detail_result.= "Usage counter, non-volatile counter, incremented when device is used after a power-up or reset";
                    break;
                case "tstp":
                    $detail_result.= "Timestamp, 8Hz, random value startup, wraps from 0xffffff to 0 (after 24 days)";
                    break;
                case "sessionCtr":
                    $detail_result.= "Session usage counter, set to 0 at power-up, incremented by one after each generation";
                    break;
                case "rnd":
                    $detail_result.= "Random number";
                    break;
                case "crc":
                    $detail_result.= "Checksum, 16-bit ISO13239 1st complement checksum of the first 14 bytes, result added to the end";
                    break;
            }
            $detail_result.= "</i></td></tr>\n";
        }
        $detail_result.= "</table>\n";
    }

    echo "<html>\n";
    echo "<head>\n";
    echo "<title>YubiKey local check demo</title>\n";
    echo "</head>\n";
    echo "<body onload=\"document.getElementById('".$focus_field."').focus();\">\n";
    echo "<form method=\"post\" action=\"yubikey.demo.php\">\n";
    echo "<fieldset>\n";
    echo "<legend>YubiKey local check demo</legend>\n";
    echo "<br />Secret (extracted from the YubiKey Personalization Tool traditional format log file) :<br />\n";
    echo "<input type=\"text\" id=\"secret\" name=\"secret\" value=\"".$secret."\" size=\"50\"><br />\n";
    echo "<br />Last valid position (<b>[256*useCtr + sessionCtr]</b>, type 0 if unknown) :<br />\n";
    echo "<input type=\"text\" id=\"last_valid_position\" name=\"last_valid_position\" value=\"".$last_valid_position."\" size=\"10\"><br />\n";
    echo "<br />Touch the YubiKey button:<br />\n";
    echo "<input type=\"text\" id=\"otp\" name=\"otp\" value=\"\" size=\"80\">\n";
    echo "<input type=\"submit\" value=\"Submit\">\n";
    echo "</fieldset>\n";
    echo "</form>\n";
    
    echo $detail_result;

    echo "</body>\n";
    echo "</html>";
?>