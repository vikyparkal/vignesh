<?php
$encrypt = '';
$en = '';
$decrypt = '';
$de = '';
$privateKey = '';
if(isset($_POST['encryptbtn'])){
	$encrypt =  $_POST['encrypt'];
 
	$privateKey =  $_POST['privateKey'];
	$en = encrypt_reponse($encrypt,$privateKey);
}
if(isset($_POST['decryptbtn'])){
	if(isset($_POST['urldecode'])){
		if($_POST['urldecode'] == 'on'){
			$_POST['decrypt'] = urldecode($_POST['decrypt']);
		}		
	}
	$decrypt =  $_POST['decrypt'];
	$privateKey =  $_POST['privateKey'];
	$de = decrypt_request($decrypt, $privateKey);
	
}
$de = decrypt_request($decrypt, $privateKey);
?>
<html>
<head>
<title>Encrpt & Decrypt</title>
</head>
<body>

<div class="main">
<div class="left">
<form method="post" action="encryptdectypt_pigee.php">
<label>Encryption</label>
<textarea name="encrypt"><?php echo $encrypt; ?></textarea>
<label>Key</label>
<input type="text" name="privateKey" value="">
<input type="submit" class="submitbtn" value="Submit" name="encryptbtn">
</form>
<div>
<label>Result</label>
<div class="result">
<?php echo $en; ?>
</div>
</div>
</div>
<div class="right">
<form method="post" action="encryptdectypt_pigee.php">
<label>Decryption</label>
<textarea name="decrypt"><?php echo $decrypt; ?></textarea>
<label>Key</label>
<input type="text" name="privateKey" value="">
<br>Url Decode &nbsp;
<input type="checkbox" name="urldecode">
<input type="submit" class="submitbtn" value="Submit" name="decryptbtn">
</form>
<div>
<label>Result</label>
<div class="result">

<?php echo $de; ?>
</div>
</div>
</div>

</div>

<style>
body { margin :0px; padding:30px; }
.main { margin :0px; padding:0px; width:100%; }
.left { float:left; width:50%; }
.left label, .right label { display:block; padding:10px 0px; font-weight:bold; }
.right {  float:left; width:50%; }
textarea { width:95%; height:150px; }
.submitbtn { display:block;  padding:10px; margin:10px 0px;  }
.result { 
background-color: #ccc;
    word-break: break-word;
    padding: 10px;
	 margin:10px;
}
</style>
</body>

</html>
<?php 
function encrypt_reponse($string, $privateKey = '')
{
    $plaintext = ($string);
	if(empty($privateKey)) {
		$password = 'eSgVkYp3s6v9y$B&E)H@McQfTjWmZq4t';
	} else {
		$password = $privateKey;
	}
    
    $method = 'AES-256-CBC';    
    $password = (substr(hash('sha256', $password, true), 0, 32));
    $iv = chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0);
    $encrypted = (openssl_encrypt($plaintext, $method, $password, OPENSSL_RAW_DATA, $iv));
    
	//$hmac = hash_hmac('sha256', $encrypted, $password, $as_binary=true);
	return  base64_encode( $encrypted );
}

function decrypt_request($string, $privateKey = '')
{

if(empty($privateKey)) {
	$password_enc = 'eSgVkYp3s6v9y$B&E)H@McQfTjWmZq4t';
} else {
		$password_enc = $privateKey;
}
$method = 'aes-256-cbc';
$password_enc = (substr(hash('sha256', $password_enc, true), 0, 32));
$iv = '';

//$string = urldecode($string); //Need to update this line when app team get error
$decrypted = openssl_decrypt(base64_decode($string), $method, $password_enc, OPENSSL_RAW_DATA, $iv);

return  $decrypted;

}
/* 
function requestEncryptDecrypt($action, $string, $secret_key) {
        
        $encrypt_method = "AES-256-CBC";
        $secret_iv = '';
        
        if(empty($secret_key)) {
	$secret_key = 'eSgVkYp3s6v9y$B&E)H@McQfTjWmZq4t';
} 
        // hash
        $key = hash('sha256', $secret_key);
        
        // iv - encrypt method AES-256-CBC expects 16 bytes - else you will get a warning
        echo $iv = substr(hash('sha256', $secret_iv), 0, 32);
exit();
        if ( $action == 'encrypt' ) {
            $output = openssl_encrypt($string, $encrypt_method, $key, OPENSSL_RAW_DATA, $iv);
            $output = base64_encode($output);
        } else if( $action == 'decrypt' ) {
            $output = openssl_decrypt(base64_decode($string), $encrypt_method, $key, OPENSSL_RAW_DATA, $iv);
        }
        return $output;
    } */
?>