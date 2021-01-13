<?php
echo md5("admin_T1YSLHj7R");
// echo "\n";
// echo md5("admin_T1YSLHj7R") == "0" ? "true" : "false";
// echo "\n";


function convert($number, $base)
{
           $return = array();
           do{
                   $return[] = $number % $base;
                   $number = floor($number / $base);
           }while($number != 0);
           return $return;
}


function createString($i, $base)
{
           $res = convert($i, strlen($base));
           $str = "";
           foreach($res as $digit)
           {
                   $str = $base[$digit] . $str;
           }
           return $str;
}

$md5Regex = "/^0e[0-9]{14}$/";
echo preg_match($md5Regex,"0e12345678901234") === 1;
echo substr(str_shuffle("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"), 0, 5);



while(true) { 
    $passwordToTry = substr(str_shuffle("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"), 0, 5);
    // echo $passwordToTry;

    // $generated_salt = rand(10e16, 10e20);
    // $converted = base_convert($generated_salt, 10, 36);


    $realPassword = "anything else";

    // $passwordToTry = "admin";

    // $salt = $converted;
    $salt = "0";

    // md5("pw_0")

    // echo $md5."\n";

    $md5Regex = "/^0e[0-9]{30}/";
    $SYSTEMPASSWORDENCRYPTED = md5($realPassword."_".$salt);

    $md5 = md5($passwordToTry."_".$salt);
    if (preg_match($md5Regex, $md5) === 1){
        echo "preg: ".!!preg_match($md5Regex, $md5)."\n";

        echo $passwordToTry." is valid\n";
        echo "md5 with salt is ".$md5."\n";
        echo "will do condition: ".($md5 == "0")."\n";
        echo "\n";    
        die();
    }
}

?>
