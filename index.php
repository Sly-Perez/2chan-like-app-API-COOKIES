<?php

declare(strict_types = 1);
define("ROOT_PATH", __DIR__);

spl_autoload_register(function($class){
    if($class === 'DbConnection'){
        require_once(ROOT_PATH . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'database' . DIRECTORY_SEPARATOR . "$class.php");
    }
    else if(str_contains($class, "Gateway")){
        require_once(ROOT_PATH . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'gateway' . DIRECTORY_SEPARATOR . "$class.php");
    }
    else if(str_contains($class, "Controller")){
        require_once(ROOT_PATH . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'controller' . DIRECTORY_SEPARATOR . "$class.php");
    }
    else if(str_contains($class, "Handler")){
        require_once(ROOT_PATH . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'handler' . DIRECTORY_SEPARATOR . "$class.php");
    }
});

header("Content-type: application/json");
//make sure to habilitate this with the corresponding page of the client app
//header("Access-Control-Allow-Origin: http://localhost:5173");
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Allow-Methods: GET, POST, DELETE");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Max-Age: 10'); //86400 for 24 hours
    exit(0);
}

set_error_handler("ErrorHandler::handleError");
set_exception_handler("ErrorHandler::handleException");

$parts = explode("/", $_SERVER['REQUEST_URI']);

$url = NULL;

//handle paths
if(array_key_exists(3, $parts)){
    switch ($parts[3]) {
        //for the case of "login", "logout", "signup" we do not need to worry about the path to be "users/login", "users/logout" and so on.
        //The System will be able to handle a bad path itself
        case "login":
            $url = "login";
            break;
        case "signup":
            $url = "signup";
            break;
        case "logout":
            $url = "logout";
            break;
        case "my":
            //if it begins with "my" we check if there is another part such as: "profile", "posts", etc.
            //we concatenate them, e.g: "my/profile", "my/posts"
            if(!array_key_exists(4, $parts)){
                //otherwise, we will send back a 404 error.
                http_response_code(404);
                echo json_encode([
                    "errors"=>["Path Not found"]
                ]);
                return;
            }
            $url = "my/" . $parts[4];
            break;
        case "newest":
            $url = "newest";
            break;
        case "popular":
            $url = "popular";
            break;
        default:
            $url = NULL;
            break;
    }
}

$id = ($url===NULL && array_key_exists(3, $parts)) ? $parts[3] : NULL;

//handle display of images by resource
//localhost/PHP_API_COOKIE/users/3/pictures
if($id !== NULL && array_key_exists(4, $parts)){
    //verify the previous validation of url responded with a NULL, so that there won't be any conflicts and won't overwrite any valid urls
    switch ($parts[4]) {
        case "pictures":

            //get   /posts/:id/pictures/:number
            if((array_key_exists(5, $parts)) && ($parts[2] === "posts" || $parts[2] === "comments")){
                $url = "pictures/" . $parts[5];
                break;
            }

            //get   /users/:id/pictures
            $url = "pictures";
            break;
        case "my":

            if(!(array_key_exists(5, $parts))){
                http_response_code(404);
                echo json_encode([
                    "errors"=>["Path Not found"]
                ]);
                return;
            }
            
            $url = "my/" . $parts[5];
            break;
        case "comments":
            $url = "comments";
            break;
        case "replies":
            $url = "replies";
            break;
        default:
            //if the url did not belong to any of the previous options. It means it does not exist within our project
            //so we will send back a 404 error
            http_response_code(404);
            echo json_encode([
                "errors"=>["Path Not found"]
            ]);
            return;
    }
}
    
$dbConnection = new DbConnection();
$userGateway = new UserGateway($dbConnection);
$sessionGateway = new SessionGateway($dbConnection);
$userController = new UserController($userGateway, $sessionGateway);


$sessionIsValid = $userController->validateSessionMiddleware();


if(($parts[2] === "users" && $url != NULL) && ($_SERVER['REQUEST_METHOD'] === "POST") && ($url === "login" || $url === "signup")){

    if($sessionIsValid){
        http_response_code(400);
        echo json_encode([
            "errors"=>["Your session has not expired yet"]
        ]);
    }
    else{
        $userController->processRequest($_SERVER['REQUEST_METHOD'], $id, $url);
    }

    return;
}

if(!$sessionIsValid){
    http_response_code(401);
    echo json_encode([
        "errors"=>["Invalid or expired session"]
    ]);
    return;
}


switch ($parts[2]) {
    case "users":
        $gateway = new UserGateway($dbConnection);
        $controller = new UserController($gateway, $sessionGateway);
        $controller->processRequest($_SERVER['REQUEST_METHOD'], $id, $url);
        break;
    case "posts":
        $gateway = new PostGateway($dbConnection);
        $postImageGateway = new PostImageGateway($dbConnection);
        $commentGateway = new CommentGateway($dbConnection);
        $commentController = new CommentController($commentGateway, $userController, null, null);
        $controller = new PostController($gateway, $postImageGateway, $commentGateway, $commentController, $userController);
        $controller->processRequest($_SERVER['REQUEST_METHOD'], $id, $url);
        break;
    case "comments":
        $gateway = new CommentGateway($dbConnection);
        $commentImageGateway = new CommentImageGateway($dbConnection);
        $commentReactionGateway = new CommentReactionGateway($dbConnection);
        $controller = new CommentController($gateway, $userController, $commentImageGateway, $commentReactionGateway);
        $controller->processRequest($_SERVER['REQUEST_METHOD'], $id, $url);
        break;
    default:
        http_response_code(404);
        echo json_encode([
            "errors"=>["Path Not found"]
        ]);
        break;
}