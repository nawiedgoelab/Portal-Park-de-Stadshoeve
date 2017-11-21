<?php
    ini_set('display_errors', 1); // 0 = uit, 1 = aan
    error_reporting(E_ALL);
    session_start();
    
    if ($_SERVER['REQUEST_METHOD'] == 'POST')
    {
        if (isset($_POST['username']) && trim($_POST['username']) != '' && 
            isset($_POST['password']) && trim($_POST['password']) != '')
        {
            try 
            {
                //initialisatie
                $maxAttempts = 3; //pogingen binnen aantal minuten (zie volgende)
                $attemptsTime = 5; //tijd waarin pogingen gedaan mogen worden (in minuten, wil je dat in seconden e.d. met je de query aanpassen)
                
                //vul hier je eigen databasegegevens in, verbinding maken met database
                $dbinfo = "mysql:host=localhost;dbname=kbs;port=8889";
                $user = "root";
                $pass = "root";
                $db = new PDO($dbinfo, $user, $pass);
                $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); 
                
                //ophalen gebruikersinformatie, testen of wachtwoord en gebruikersnaam overeenkomen
                $checkUsers = 
                    "SELECT 
                       user_id
                    FROM
                        users
                    WHERE
                        username = :username
                    AND
                        password = :password";
                $userStmt = $db->prepare($checkUsers);
                $userStmt->execute(array(
                                    ':username' => $_POST['username'],
                                    ':password' => hash('sha256', $_POST['username'] . $_POST['password'])
                                    ));
                $user = $userStmt->fetchAll();
                
                //ophalen inlogpogingen, alleen laatste vijf minuten
                $checkTries =
                    "SELECT
                        username
                    FROM
                        loginfail
                    WHERE
                        DateAndTime >= NOW() - INTERVAL :attemptsTime MINUTE
                    AND
                        username = :username    
                    GROUP BY
                        username, IP
                    HAVING
                        (COUNT(username) = :maxAttempts)";
                $triesStmt = $db->prepare($checkTries);
                $triesStmt->execute(array(
                                    ':username' => $_POST['username'],
                                    ':attemptsTime' => $attemptsTime,
                                    ':maxAttempts' => $maxAttempts
                                    ));
                $tries = $triesStmt->fetchAll();
                
                if (count($user) == 1 && count($tries) == 0)
                {
                    $_SESSION['user'] = array('user_id' => $user[0]['user_id'], 'IP' => $_SERVER['REMOTE_ADDR']);
                    //pagina waar naartoe nadat er succesvol is ingelogd
                    header('Location: home.php');
                    die;
                }
                else
                {
                    $insertTry = 
                        "INSERT INTO
                            loginfail
                                (username, 
                                IP,
                                dateAndTime)
                        VALUES
                            (:username,
                            :IP,
                            NOW())";
                    $insertStmt = $db->prepare($insertTry);
                    $insertStmt->execute(array(
                                            ':username' => $_POST['username'],
                                            ':IP' => $_SERVER['REMOTE_ADDR']
                                            ));
                    if(count($tries) > 0)
                    {
                        $message = 'Je hebt (tijdelijk) geblockt. Probeer het over 10 minuten opnieuw.';
                    }
                    else
                    {
                        $message = 'Onjuiste gebruikersnaam/wachtwoord. Probeer het opnieuw.';
                    }
                }
            }
            catch (PDOException $e)
            {
                $message = $e->getMessage();
            }
            $db = NULL;
        }
    }
?>   
<?php

    include 'header.php';
    
?>
<!DOCTYPE html>
<!--
To change this license header, choose License Headers in Project Properties.
To change this template file, choose Tools | Templates
and open the template in the editor.
-->
<html>
    <head>
        <meta charset="UTF-8">
        <title></title>
    </head>
    <body>
        <div class="container">
            <div class="login">
                <h1 class="title">Login</h1>
            </div>
            
            <form method="POST" action="">

                    <div class="form-group">
                        <input type="email" class="form-control" id="usr" name="username" placeholder="Email" required>
                    </div>
                    <div class="form-group">
                        <input type="password" class="form-control" id="pwd" name="password" placeholder="Wachtwoord" required>
                    </div>   
                        <?php
                            if (isset($message))
                            {
                            ?>
                                <div class="alert alert-danger">
                                <?php echo $message; ?>
                                </div>
                            <?php                          
                            }
                        ?>
                    <div>                
                        <button type="submit" class="btn btn-success" name="verstuur">Inloggen</button>
                    </div>
            </form>            
        </div>
    </body>
</html>
<?php

    include 'footer.php';
?>