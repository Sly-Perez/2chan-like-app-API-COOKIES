<?php

class CommentController{

    private CommentGateway $gateway;
    private UserController $userController;
    private ?CommentImageGateway $commentImageGateway;
    private ?CommentReactionGateway $commentReactionGateway;

    public function __construct(CommentGateway $gateway, UserController $userController, ?CommentImageGateway $commentImageGateway, ?CommentReactionGateway $commentReactionGateway){
        $this->gateway = $gateway;
        $this->userController = $userController;
        $this->commentImageGateway = $commentImageGateway;
        $this->commentReactionGateway = $commentReactionGateway;
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
        
        //when a delete request is made, we will disable comments. Therefore, it does not matter if it is a reply or a main comment
        if($method === "DELETE" || ($url === "my/reactions" && ($method === "POST" || $method === "GET")) || ($url !== NULL && preg_match("#^pictures/[1-3]/?$#", $url) && $method === "GET")){
            $comment = $this->gateway->getById($id);
            
            if(!$comment){
                http_response_code(404);
                echo json_encode([
                    "errors"=>["Comment with id $id was not found"]
                ]);
                return;
            }
        }
        //in any other case, we will just take into account a main comment with the sent id
        else{
            $mainComment = $this->gateway->getMainById($id);
    
            if(!$mainComment){
                http_response_code(404);
                echo json_encode([
                    "errors"=>["Main Comment with id $id was not found"]
                ]);
                return;
            }
        }

        switch ($method) {
            case "GET":
                
                if($url !== null && preg_match("#^pictures/[1-3]/?$#", $url)){
                    $number = substr($url, 9, 1);
                    $index = $number - 1;
                    $commentImage = $this->commentImageGateway->getByCommentIdAndIndex($id, $index);
                    
                    if(!$commentImage){
                        http_response_code(404);
                        echo json_encode([
                            "errors"=>["image number $number attached to comment with id $id was not found"]
                        ]);
                        return;
                    }

                    $fileName = $commentImage["name"];
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
                    
                    $filePath = ROOT_PATH . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'images' . DIRECTORY_SEPARATOR . 'users' . DIRECTORY_SEPARATOR . 'comments' . DIRECTORY_SEPARATOR . $fileName;
                    
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

                if($url !== "replies" && $url !== "my/reactions"){
                    http_response_code(404);
                    echo json_encode([
                        "errors"=>["Path Not found"]
                    ]);
                    return;
                }

                if($url === "my/reactions"){
                    $userDB = $this->userController->getUserByUUID();
                    $userId = $userDB["userId"];

                    $commentReaction = $this->commentReactionGateway->getByCommentIdAndUserId($id, $userId);

                    if(!$commentReaction){
                        http_response_code(404);
                        echo json_encode([
                            "errors"=>["Comment reaction with user Id $userId and comment Id $id was not found"]
                        ]);
                        return;
                    }

                    echo json_encode($commentReaction);
                    return;
                }

                $replies = $this->gateway->getAllRepliesByCommentId($id);

                echo json_encode($replies);
                break;
            case "POST":
                if($url !== "replies" && $url !== "my/reactions"){
                    http_response_code(404);
                    echo json_encode([
                        "errors"=>["Path Not found"]
                    ]);
                    return;
                }

                if($url === "my/reactions"){
                    $data = isset($_POST['jsonBody']) ? json_decode($_POST['jsonBody'], true) : json_decode(file_get_contents("php://input"), true);
                    $reactionName = "";

                    //validate user did not send double comment Reaction
                    if(isset($data['isLike']) && isset($data['isDislike'])){
                        http_response_code(400);
                        echo json_encode([
                            "errors"=>["Cannot send isLike and isDislike in the same request; Choose just one"]
                        ]);
                        return;
                    }

                    //validate user sent at least one reaction
                    if(!isset($data['isLike']) && !isset($data['isDislike'])){
                        http_response_code(400);
                        echo json_encode([
                            "errors"=>["Comment Reaction's reaction is mandatory; Send isLike or isDislike"]
                        ]);
                        return;
                    }

                    //validate value is valid
                    if(isset($data['isLike'])){
                        if($data['isLike'] != 1 && $data['isLike'] != 0){
                            http_response_code(400);
                            echo json_encode([
                                "errors"=>["Valid values for isLike: 0 or 1"]
                            ]);
                            return;
                        }

                        //define reaction in case there is no problem with the sent data
                        $reactionName = "isLike";
                    }

                    if(isset($data['isDislike'])){
                        if($data['isDislike'] != 1 && $data['isDislike'] != 0){
                            http_response_code(400);
                            echo json_encode([
                                "errors"=>["Valid values for isDislike: 0 or 1"]
                            ]);
                            return;
                        }

                        //define reaction in case there is no problem with the sent data
                        $reactionName = "isDislike";
                    }

                    //set the required data
                    $completeData = [];
                    $completeData["commentId"] = $comment["commentId"];
                    $userDB = $this->userController->getUserByUUID();
                    $completeData["userId"] = $userDB["userId"];
                    $completeData["reactionName"] = $reactionName;
                    $completeData["reactionValue"] = $data[$reactionName];

                    $commentReaction = $this->commentReactionGateway->addOrUpdateCommentReaction($completeData);
                    echo json_encode($commentReaction);
                    return;
                }

                $data = isset($_POST['jsonBody']) ? json_decode($_POST['jsonBody'], true) : json_decode(file_get_contents("php://input"), true);
                
                $data["postId"] = $mainComment["postId"];
                $data["responseTo"] = $mainComment["commentId"];

                $sanitizedData = $this->getSanitizedInputData($data ?? NULL, $_FILES['pictures'] ?? NULL, true);
                $pictureNames = [];
                
                $errors = $this->getValidationInputErrors($sanitizedData);

                if(count($errors) !== 0){
                    http_response_code(400);
                    echo json_encode([
                        "errors"=>$errors
                    ]);
                    return;
                }
                
                if($sanitizedData['numberOfImages'] > 0 && $sanitizedData['pictures'] !== NULL){
                    
                    for ($i = 0; $i < $sanitizedData["numberOfImages"]; $i++) { 
                        //name
                        $name = $this->uploadPicture($sanitizedData["pictures"], $i, true);
                        array_push($pictureNames, $name);
                    }
                }
                
                
                $returnedId = $this->gateway->add($sanitizedData, $pictureNames);
                http_response_code(201);
                $reply = $this->gateway->getReplyById($returnedId);
                echo json_encode($reply);
                break;
            case "DELETE":
                $userDB = $this->userController->getUserByUUID();

                if($userDB["userId"] !== $comment["userId"]){
                    
                    if($userDB["hierarchyLevelId"] !== 1){
                        http_response_code(403);
                        return;
                    }

                    $this->gateway->deleteById($id, $comment["responseTo"]);
                    echo json_encode([
                        "message"=>["Comment with id $id deleted successfully"]
                    ]);
                    return;
                }

                $this->gateway->deleteById($id, $comment["responseTo"]);
                echo json_encode([
                    "message"=>["Comment with id $id deleted successfully"]
                ]);
                break;
            
            default:
                http_response_code(405);
                header("Allow: GET, POST, DELETE");
                break;
        }

    }

    private function processRequestWithoutId(string $method, ?string $url): void{
        
        http_response_code(404);
        echo json_encode([
            "errors"=>["Path Not Found"]
        ]);
        return;
    }

    public function uploadPicture(array $file, int $index): string{

        $extension = pathinfo($file['name'][$index], PATHINFO_EXTENSION);

        $currentPath = $file['tmp_name'][$index];

        $newFileName = uniqid('img-') . '.' . $extension;

        $path = ROOT_PATH . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'images' . DIRECTORY_SEPARATOR . 'users' . DIRECTORY_SEPARATOR . 'comments' . DIRECTORY_SEPARATOR;        
        
        $newPath = $path . $newFileName;

        move_uploaded_file($currentPath, $newPath);

        return $newFileName;
    }

    public function getSanitizedInputData(?array $data, ?array $images, bool $is_for_reply = false): array{

        $description = filter_var(trim($data['description'] ?? ""), FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        $numberOfImages = empty($images['name'][0]) ? 0 : count($images['name']);

        if($numberOfImages > 0){
            
            $pictures = $images;
            
        }

        $sanitizedData = [];

        $sanitizedData['description'] = $description;
        $sanitizedData['pictures'] = $pictures ?? NULL;
        $sanitizedData['numberOfImages'] = $numberOfImages;
        //we define the userId based on the corresponding COOKIES sent with the request
        $userDB = $this->userController->getUserByUUID();
        $sanitizedData['userId'] = $userDB['userId'];
        $sanitizedData['postId'] = $data['postId'];

        if($is_for_reply){
            $sanitizedData["responseTo"] = $data["responseTo"];
        }

        return $sanitizedData;
    }

    public function getValidationInputErrors(array $data): array{
        $errors = [];

        $description = $data['description'];
        $numberOfImages = $data['numberOfImages'];
        $pictures = $data['pictures'];

        //description
        if(empty($description)){
            array_push($errors, "The Comment's description is required");
        }
        else if(strlen($description) > 300){
            array_push($errors, "The Comment's description: cannot have length greater than 300 characters");
        }

        //pictures
        if(($numberOfImages > 0) && ($pictures !== NULL)){
            if($numberOfImages > 3){
                array_push($errors, "The Comment's image(s): cannot be more than 3");
            }
            else{
                //max size of image will be 2MB
                $max_file_size = 2 * 1024 * 1024; //2MB in bytes
        
                $allowedTypes = ['image/gif', 'image/jpeg', 'image/png', 'image/webp'];
                $allowedExtensions = ['gif', 'jpeg', 'jpg', 'png', 'webp'];

                for ($i = 0; $i < $numberOfImages; $i++) { 
                    
                    $fileName = basename($pictures['name'][$i]);
                    $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
                    $fileType = mime_content_type($pictures['tmp_name'][$i]);
                    
                    //validate file MIME type is allowed
                    if(!in_array($fileType, $allowedTypes)){
                        array_push($errors, "The Comment's image(s) Must be in format: jpeg, jpg, png, gif, webp; Please correct pictures. Error found in picture number " . $i+1);
                    }
                    //validate file extension is allowed (optional)
                    else if(!in_array($fileExtension, $allowedExtensions)) {
                        array_push($errors, "The Comment's image(s) Must be in format: jpeg, jpg, png, gif, webp; Please correct pictures. Error found in picture number " . $i+1);
                    }
                    //validate a max file size
                    else if($pictures['size'][$i] > $max_file_size){
                        array_push($errors, "The Comment's image(s) size cannot be more than 2MB; Please correct pictures. Error found in picture number " . $i+1);
                    }
                }
            }
        }
        
        return $errors;
    }

}