<?php

class UserController{

    private UserGateway $gateway;
    private SessionGateway $sessionGateway;

    public function __construct(UserGateway $gateway, SessionGateway $sessionGateway){
        $this->gateway = $gateway;
        $this->sessionGateway = $sessionGateway;
    }

    public function processRequest(string $method, ?string $id, ?string $url): void{
        
        if($id){

            $this->processRequestWithId($method, $id, $url);

        }
        else{
            
            $this->processRequestWithoutId($method, $url);
            
        }

    }

    private function processRequestWithId(string $method, string $id, ?string $url): void{
        
        if($id !== "zero"){
            $user = $this->gateway->getById($id);
    
            if(!$user){
                http_response_code(404);
                echo json_encode([
                    "errors"=>["User with id $id was not found"]
                ]);
                return;
            }
        }

        switch ($method) {
            case "GET":
                if($url === "pictures"){

                    if($id === "zero"){
                        header("Content-Type: image/webp");
                        require_once(ROOT_PATH . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'images' . DIRECTORY_SEPARATOR . 'users' . DIRECTORY_SEPARATOR . 'profilePictures' . DIRECTORY_SEPARATOR . 'blank-profile-picture.webp');
                        return;
                    }

                    $fileName = $user['picture'];
                    $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

                    switch ($fileExtension) {
                        case "gif":
                            header("Content-Type: image/gif");
                            break;
                        case "jpeg":
                            header("Content-Type: image/jpeg");
                            break;
                        case "jpg":
                            header("Content-Type: image/jpeg");
                            break;
                        case "png":
                            header("Content-Type: image/png");
                            break;
                        case "webp":
                            header("Content-Type: image/webp");
                            break;
                        default:
                            http_response_code(500);
                            echo json_encode([
                                "errors"=>["Internal Server Error"]
                            ]);
                            return;
                    }
                    
                    $filePath = ROOT_PATH . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'images' . DIRECTORY_SEPARATOR . 'users' . DIRECTORY_SEPARATOR . 'profilePictures' . DIRECTORY_SEPARATOR . $fileName;
                    
                    if(!file_exists($filePath)){
                        $filePath = ROOT_PATH . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'images' . DIRECTORY_SEPARATOR . 'page' . DIRECTORY_SEPARATOR . "notFoundOnServer.webp";
                        http_response_code(404);
                        header("Content-Type: image/webp");
                        require_once($filePath);
                        return;
                    }

                    require_once($filePath);
                    return;
                }

                echo json_encode($user);
                break;
            case "DELETE":
                $userDB = $this->getUserByUUID();

                if(!$userDB){
                    http_response_code(401);
                    echo json_encode([
                        "errors"=>["Invalid Session"]
                    ]);
                    return;
                }

                //the regular User should have 1 as hierarchyLevelId
                if($userDB["hierarchyLevelId"] === 2){
                    http_response_code(403);
                    return;
                }

                if($userDB["userId"] === intval($id)){
                    http_response_code(403);
                    echo json_encode([
                        "errors"=>["Administrators Cannot delete their own profile"]
                    ]);
                    return;
                }

                if($user["hierarchyLevelId"] !== 2){
                    http_response_code(403);
                    echo json_encode([
                        "errors"=>["Cannot delete other administrators' profiles"]
                    ]);
                    return;
                }

                $this->gateway->deleteById($id);
                echo json_encode([
                    "message"=>["User with $id deleted successfully"]
                ]);

                break;
            default:
                http_response_code(405);
                header("Allow: GET, DELETE");
                break;
        }

    }

    private function processRequestWithoutId(string $method, ?string $url): void{
        switch ($method) {
            case "GET":
                switch ($url) {
                    case "my/profile":
                        //we get user by the sent COOKIES
                        //it will retrieve ALL their info
                        $userDB = $this->getUserByUUID();

                        if(!$userDB){
                            http_response_code(400);
                            echo json_encode([
                                "errors"=>["Invalid Session"]
                            ]);
                            return;
                        }

                        //we create a user with the information we want to display of the user
                        $user = $this->gateway->getById($userDB["userId"], true);

                        echo json_encode($user);
                        break;
                    default:
                        http_response_code(404);
                        echo json_encode([
                            "errors"=>["Path Not found"]
                        ]);
                        break;
                }
                break;
            case "POST":
                switch ($url) {
                    case "login":
                        $data = isset($_POST['jsonBody']) ? json_decode($_POST['jsonBody'], true) : json_decode(file_get_contents("php://input"), true);

                        $sanitizedData = $this->getSanitizedInputData($data ?? NULL, NULL);

                        $user = $this->gateway->getByEmail($sanitizedData['email']);

                        if(!$user){
                            http_response_code(401);
                            echo json_encode([
                                "errors"=>["Email or Password Invalid"]
                            ]);
                            return;
                        }

                        if(password_verify($sanitizedData['password'], $user['password'])){
                            $uuid = $this->generateUUID();
                            $this->setUserSession($user, $uuid);
                            echo json_encode([
                                "message"=>"User logged in successfully"
                            ]);
                        }
                        else{
                            http_response_code(401);
                            echo json_encode([
                                "errors"=>["Email or Password Invalid"]
                            ]);
                        }

                        break;
                    case "signup":
                        //if a $_POST['jsonBody'] is set, it means the user sent the data as a form-data object. 
                        //Otherwise, it means the user sent the data as a JSON object (with no picture)
                        $data = isset($_POST['jsonBody']) ? json_decode($_POST['jsonBody'], true) : json_decode(file_get_contents("php://input"), true);
                        $sanitizedData = $this->getSanitizedInputData($data ?? NULL, $_FILES['picture'] ?? NULL);
                        $pictureIsUploaded = false;

                        $errors = $this->getValidationInputErrors($sanitizedData);

                        if(count($errors) !== 0){
                            http_response_code(400);
                            echo json_encode([
                                "errors"=>$errors
                            ]);
                            return;
                        }
                        
                        $userDB = $this->gateway->getByEmail($sanitizedData["email"]);
                        
                        if($userDB !== false){
                            http_response_code(400);
                            echo json_encode([
                                "errors"=>["Email already registered"]
                            ]);
                            return;
                        }
                        
                        
                        if($sanitizedData['picture'] !== NULL){
                            $sanitizedData['picture'] = $this->uploadPicture($sanitizedData['picture']);
                            $pictureIsUploaded = true;
                        }
                        
                        $returnedId = $this->gateway->add($sanitizedData, $pictureIsUploaded);
                        http_response_code(201);
                        $user = $this->gateway->getById($returnedId);
                        echo json_encode($user);
                        
                        break;
                    case "logout":
                        
                        $user = $this->getUserByUUID();

                        if(!$user){
                            http_response_code(401);
                            echo json_encode([
                                "errors"=>["Invalid Session"]
                            ]);
                            return;
                        }

                        $this->unsetUserSession($user);

                        echo json_encode([
                            "message"=>"User logged out successfully"
                        ]);
                        break;
                    case "my/profile":

                        $userDB = $this->getUserByUUID();

                        if(!$userDB){
                            http_response_code(401);
                            echo json_encode([
                                "errors"=>["Invalid Session"]
                            ]);
                            return;
                        }

                        $data = isset($_POST['jsonBody']) ? json_decode($_POST['jsonBody'], true) : json_decode(file_get_contents("php://input"), true);
                        
                        $sanitizedData = $this->getSanitizedInputData($data ?? NULL, $_FILES['picture'] ?? NULL, true);
                        //if any field is NULL, it means the user did not send it. 
                        //Therefore, it will not be validated
                        $errors = $this->getValidationInputErrors($sanitizedData);
                        
                        if(count($errors) !== 0){
                            http_response_code(400);
                            echo json_encode([
                                "errors"=>$errors
                            ]);
                            return;
                        }                
                        
                        
                        //in case the user sent a new email to be updated, we will check if another user with the same email already exists
                        if($sanitizedData["email"] !== NULL){

                            $userFound = $this->gateway->getByEmail($sanitizedData["email"]);
                            //we take into account that if it is about the same user (requester), it will not affect anything
                            if( ($userFound !== false) && ($userFound['userId'] !== $userDB['userId']) ){
                                http_response_code(400);
                                echo json_encode([
                                    "errors"=>["Email already registered"]
                                ]);
                                return;
                            }

                        }


                        if($sanitizedData['picture'] !== NULL){
                            $sanitizedData['picture'] = $this->uploadPicture($sanitizedData['picture']);
                            $pictureIsUploaded = true;
                        }
                        
                        $this->gateway->update($userDB, $sanitizedData);
                        
                        $user = $this->gateway->getById($userDB["userId"], true);
                        echo json_encode($user);
                        break;
                    default:
                        http_response_code(404);
                        echo json_encode([
                            "errors"=>["Path Not found"]
                        ]);
                        break;
                }
                break;
            case "DELETE":
                if($url !== "my/profile"){
                    http_response_code(404);
                    echo json_encode([
                        "errors"=>["Path Not found"]
                    ]);
                    return;
                }

                $userDB = $this->getUserByUUID();

                if(!$userDB){
                    http_response_code(401);
                    echo json_encode([
                        "errors"=>["Invalid Session"]
                    ]);
                    return;
                }

                if($userDB["hierarchyLevelId"] !== 2){
                    http_response_code(403);
                    echo json_encode([
                        "errors"=>["Administrators Cannot delete their own profile"]
                    ]);
                    return;
                }

                $this->gateway->deleteById($userDB["userId"]);
                echo json_encode([
                    "message"=>["Your profile was deleted successfully"]
                ]);
                break;
            default:
                http_response_code(405);
                header("Allow: GET, POST, DELETE");
                break;
        }
    }

    private function uploadPicture(array $file): string{

        $extension = pathinfo($file['name'], PATHINFO_EXTENSION);

        $currentPath = $file['tmp_name'];

        $newFileName = uniqid('profile-picture-') . '.' . $extension;

        $path = ROOT_PATH . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'images' . DIRECTORY_SEPARATOR . 'users' . DIRECTORY_SEPARATOR . 'profilePictures' . DIRECTORY_SEPARATOR;
        
        $newPath = $path . $newFileName;

        move_uploaded_file($currentPath, $newPath);

        return $newFileName;
    }
    private function containsOnlyAscii(string $string): int | bool{
        return !preg_match('/[^\x00-\x7F]/', $string);
    }

    private function getSanitizedInputData(?array $data, ?array $image, bool $is_updated = false):array{

        $username = htmlspecialchars(trim($data['username'] ?? ""), ENT_NOQUOTES, 'UTF-8');
        $email = htmlspecialchars(trim($data['email'] ?? ""), ENT_NOQUOTES, 'UTF-8');
        $password = htmlspecialchars(trim($data['password'] ?? ""), ENT_NOQUOTES, 'UTF-8');
        
        if($image !== NULL && !empty($image['name']) && ($image['error'] === 0)){
            
            $picture = $image;
            
        }

        $sanitizedData = [];
        
        if($is_updated){
            $sanitizedData['username'] = isset($data['username']) ? $username : NULL;
            $sanitizedData['email'] = isset($data['email']) ? $email : NULL;
            $sanitizedData['password'] = isset($data['password']) ? $password : NULL;
        }
        else{
            $sanitizedData['username'] = $username;
            $sanitizedData['email'] = $email;
            $sanitizedData['password'] = $password;
        }

        $sanitizedData['picture'] = $picture ?? NULL;

        return $sanitizedData;
    }

    private function getValidationInputErrors(array $data, bool $password_will_be_checked = true):array{
        $errors = [];

        $username = $data['username'];
        $email = $data['email'];
        $password = $data['password'];
        $picture = $data['picture'];

        //username
        if($username !== NULL) {
            if(empty($username)){
                array_push($errors, "The User's username is required");
            }
            else if(is_numeric(substr($username, 0, 1)) || strlen($username) > 30){
                array_push($errors, "The User's username: Cannot start with numbers; Length cannot be greater than 30 characters");
            }
        }

        //email
        if($email !== NULL){
            if(empty($email)){
                array_push($errors, "The User's email is required");
            }
            else if(!(filter_var($email, FILTER_VALIDATE_EMAIL)) || strlen($email) > 100 || !$this->containsOnlyAscii($email)){
                array_push($errors, "The User's email: Must be a valid email; Length cannot be greater than 100 characters; Cannot contain non-latin characters");
            }
        }

        //password
        if($password_will_be_checked && $password !== NULL){
            if(empty($password) || strlen($password) > 30){
                array_push($errors, "The User's password: Cannot be empty; Length cannot be greater than 30 characters");
            }
        }

        //picture
        if($picture !== NULL){
            
            //max size of image will be 2MB
            $max_file_size = 2 * 1024 * 1024; //2MB in bytes

            $allowedTypes = ['image/gif', 'image/jpeg', 'image/png', 'image/webp'];
            $allowedExtensions = ['gif', 'jpeg', 'jpg', 'png', 'webp'];
            
            $fileName = basename($picture['name']);
            $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
            $fileType = mime_content_type($picture['tmp_name']);
            
            
            //validate file MIME type is allowed
            if(!in_array($fileType, $allowedTypes)){
                array_push($errors, "The User's picture Must be in format: jpeg, jpg, png, gif, webp");
            }
            //validate file extension is allowed (optional)
            else if(!in_array($fileExtension, $allowedExtensions)) {
                array_push($errors, "The User's picture Must be in format: jpeg, jpg, png, gif, webp");
            }
            //validate a max file size
            else if($picture['size'] > $max_file_size){
                array_push($errors, "The User's picture size cannot be more than 2MB");
            }
            //validate the width and height of the image
            else{
                $pictureSize = getimagesize($picture['tmp_name']);
                //$pictureSize[0]->width
                //$pictureSize[1]->height
                if($pictureSize[0] !== $pictureSize[1]){
                    array_push($errors, "The User's picture: Must have the same width and height");
                }
            }
            
        }
        
        return $errors;
    }

    private function generateUUID(): string{
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    private function generateSessionKey(string $uuid):string{
        
        $sessionKey = base64_encode(hash_hmac('sha256', $uuid, 'secret-key-that-no-one-knows', true));

        return $sessionKey;
    }

    public function getDecryptedUUID(string $encryptedUUID):string{
        $secretKey = hash('sha256', 'secret-key-no-one-knows', true);

        $data = base64_decode($encryptedUUID);
        $iv = substr($data, 0, 16);
        $encryptedData = substr($data, 16);
        $decryptedUUID = openssl_decrypt($encryptedData, 'AES-256-CBC', $secretKey, 0, $iv);

        return $decryptedUUID;
    }

    public function validateSession(string $sessionKey, string $sessionUUID):bool{

        $sessionDB = $this->sessionGateway->getByUUID($sessionUUID);
        
        if(!$sessionDB){
            return false;
        }

        return (base64_decode($sessionKey) === hash_hmac('sha256', $sessionUUID, 'secret-key-that-no-one-knows', true));
    }

    private function getEmailByUUID(string $uuid): string{

        $sessionDB = $this->sessionGateway->getByUUID($uuid);

        $userDB = $this->gateway->getById($sessionDB["userId"], true);

        return $userDB['email'];
    }

    private function setUserSession(array $data, string $uuid): void{

        $sessionKey = $this->generateSessionKey($uuid);

        $secretKey = hash('sha256', 'secret-key-no-one-knows', true);
        $iv = random_bytes(16);

        $encryptedUUID = base64_encode($iv . openssl_encrypt($uuid, 'AES-256-CBC', $secretKey, 0, $iv));

        $this->sessionGateway->add($data["userId"], $uuid);

        //if you are in localhost, you might want to consider to set cookies in a much simpler way, if you set them like this, you won't be able to use cookies properly from your client app
        setcookie("sessionUUID", $encryptedUUID, [
            "expires" => time() + 7200,
            "path" => "/",
            "secure" => true,
            "httponly" => true,
            "samesite" => "None"
        ]);

        setcookie("sessionKey", $sessionKey, [
            "expires" => time() + 7200,
            "path" => "/",
            "secure" => true, 
            "httponly" => true, 
            "samesite" => "None"
        ]);
    }

    private function unsetUserSession(array $data): void{
        $sessionUUID = isset($_COOKIE["sessionUUID"]) ? $this->getDecryptedUUID($_COOKIE["sessionUUID"]) : NULL;
        
        $this->sessionGateway->deleteByUUIDAndUserId($sessionUUID, $data["userId"]);
        
        //if you are in localhost, you might want to consider to unset cookies in a similar you set them. If you did not add for example an httpOnly => true, omit it
        setcookie("sessionUUID", "", [
            "expires" => time() - 3600,
            "path" => "/",
            "secure" => true,
            "httponly" => true,
            "samesite" => "None"
        ]);

        setcookie("sessionKey", "", [
            "expires" => time() - 3600,
            "path" => "/",
            "secure" => true,
            "httponly" => true, 
            "samesite" => "None"
        ]);
    }
    
    public function validateSessionMiddleware():bool {
        $sessionKey = $_COOKIE["sessionKey"] ?? NULL;
        $sessionUUID = isset($_COOKIE["sessionUUID"]) ? $this->getDecryptedUUID($_COOKIE["sessionUUID"]) : NULL;
        
        if($sessionKey === NULL || $sessionUUID === NULL) {
            return false;
        }

        if(!$this->validateSession($sessionKey, $sessionUUID)) {
            return false;
        }
        
        return true;
    }

    public function getUserByUUID(): array | false{
        $sessionUUID = isset($_COOKIE["sessionUUID"]) ? $this->getDecryptedUUID($_COOKIE["sessionUUID"]) : NULL;

        $email = $this->getEmailByUUID($sessionUUID);

        $user = $this->gateway->getByEmail($email);

        if(!$user){
            return false;
        }

        return $user;
    }
    
}