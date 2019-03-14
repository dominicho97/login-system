<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <title>Login</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  
<header>
  <nav>
    <a href = "#">
      <img src="img/lildomsq.PNG" alt="logo">
    </a>
    <ul>
      <li><a href="#">Home</li>
      <li><a href="#">Portfolio</li>
      <li><a href="#">About me</li>
      <li><a href="#">Contact</li>
    </ul>
  <div>

    <form action="includes/login.inc.php" method="post">
      <input type="text" name="mailuid" placeholder="Username/E-mail...">
      <input type="password" name="pwd" placeholder="Password...">
      <button type="submit" name="login-submit">Login</button>
    </form>

    <a href="signup.php">Signup</a>
    <form action="includes/logout.inc.php" method="post">
      <button type="submit" name="logout-submit">Logout</button>
    </form>
    </div>
  </nav>

</header>
