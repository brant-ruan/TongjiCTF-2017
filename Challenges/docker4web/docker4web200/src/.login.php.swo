<?php
header("content-type:text/html;charset=utf-8");
error_reporting(0);

include('flag.php');

$message = 'Invalid login.';
if (isset($_POST['username'])) {
    $md5a = md5('tj761306263');
    $md5b = md5($_POST['username']);
    if ($_POST['username'] == 'tj761306263') {
        $message = '安全问题，帐号tj761306263暂时停用';
    } else if (!($md5a == $md5b)) {
    	$message = '用户名无效，禁止登录';
    }
    else {
        $message = 'Welcome, the flag is: ' . $flag;
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
	<title>Login</title>
	<link rel="stylesheet" href="./css/bootstrap.min.css">
	<link rel="stylesheet" href="./css/bootstrap-theme.min.css">
	<script src="./js/jquery-3.1.1.js"></script>
	<script src="./js/bootstrap.js"></script>
</head>
<body>
	<nav class="navbar navbar-inverse">
		<div class="container">
			<a class="navbar-brand" href="./">Admin Panel</a>
			<ul class="nav navbar-nav">
				<li class="active"><a href="./">Login</a></li>
			</ul>
		</div>
	</nav>
	<div class="container" style="max-width: 500px;">
        <p><br /><?php echo $message; ?><br /><br /></p>
        <p><a class="btn btn-primary btn-block" href="./">OK</a></p>
	</div>
    
</body>
</html>