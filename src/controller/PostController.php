<?php

class PostController{

    private PostGateway $gateway;
    private PostImageGateway $postImageGateway;
    private CommentGateway $commentGateway;
    private CommentController $commentController;
    private UserController $userController;

    public function __construct(PostGateway $gateway, PostImageGateway $postImageGateway, CommentGateway $commentGateway, CommentController $commentController, UserController $userController){
        $this->gateway = $gateway;
        $this->postImageGateway = $postImageGateway;
        $this->commentGateway = $commentGateway;
        $this->commentController = $commentController;
        $this->userController = $userController;
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
        $post = $this->gateway->getById($id);

        if(!$post){
            http_response_code(404);
            echo json_encode([
                "errors"=>["Post with id $id was not found"]
            ]);
            return;
        }

        switch ($method) {
            case "GET":

                if($url === NULL){
                    echo json_encode($post);
                    return;
                }

                if(preg_match("#^pictures/[1-3]/?$#", $url)){
                    $number = substr($url, 9, 1);
                    $index = $number - 1;
                    $postImage = $this->postImageGateway->getByPostIdAndIndex($id, $index);
                    
                    if(!$postImage){
                        http_response_code(404);
                        echo json_encode([
                            "errors"=>["image number $number attached to post with id $id was not found"]
                        ]);
                        return;
                    }

                    $fileName = $postImage["name"];
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
                    
                    $filePath = ROOT_PATH . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'images' . DIRECTORY_SEPARATOR . 'users' . DIRECTORY_SEPARATOR . 'posts' . DIRECTORY_SEPARATOR . $fileName;
                    
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

                switch ($url) {
                    case "comments":
                        $comments = $this->commentGateway->getAllMainByPostId($id);

                        echo json_encode($comments);
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
                
                if($url !== "comments"){
                    http_response_code(404);
                    echo json_encode([
                        "errors"=>["Path Not found"]
                    ]);
                    return;
                }

                $data = isset($_POST['jsonBody']) ? json_decode($_POST['jsonBody'], true) : json_decode(file_get_contents("php://input"), true);
                
                $data["postId"] = $id;

                $sanitizedData = $this->commentController->getSanitizedInputData($data ?? NULL, $_FILES['pictures'] ?? NULL);
                $pictureNames = [];
                
                $errors = $this->commentController->getValidationInputErrors($sanitizedData);

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
                        $name = $this->commentController->uploadPicture($sanitizedData["pictures"], $i);
                        array_push($pictureNames, $name);
                    }
                }
                
                
                $returnedId = $this->commentGateway->add($sanitizedData, $pictureNames);
                http_response_code(201);
                $comment = $this->commentGateway->getMainById($returnedId);
                echo json_encode($comment);

                break;
            case "DELETE":
                
                $userDB = $this->userController->getUserByUUID();

                if($userDB["userId"] !== $post["userId"]){
                    
                    if($userDB["hierarchyLevelId"] !== 1){
                        http_response_code(403);
                        return;
                    }

                    $this->gateway->deleteById($id);
                    echo json_encode([
                        "message"=>["Post with id $id deleted successfully"]
                    ]);
                    return;
                }

                $this->gateway->deleteById($id);
                echo json_encode([
                    "message"=>["Post with id $id deleted successfully"]
                ]);
                break;
            
            default:
                http_response_code(405);
                header("Allow: GET, POST, DELETE");
                break;
        }

    }

    private function processRequestWithoutId(string $method, ?string $url): void{
        
        switch ($method) {
            case "GET":

                switch ($url) {
                    case NULL:
                        $posts = $this->gateway->getAll();
        
                        echo json_encode($posts);
                        break;
                    case "newest":
                        $posts = $this->gateway->getAllNewest();

                        echo json_encode($posts);
                        break;
                    case "popular":
                        $posts = $this->gateway->getAllPopular();

                        echo json_encode($posts);
                        break;
                    case "my/interacted":
                        $userDB = $this->userController->getUserByUUID();

                        $posts = $this->gateway->getAllInteractedByUserId($userDB["userId"]);
                        
                        echo json_encode($posts);
                        break;
                    case "my/list":
                        $userDB = $this->userController->getUserByUUID();

                        $posts = $this->gateway->getAllByUserId($userDB["userId"]);

                        echo json_encode($posts);
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
                $data = isset($_POST['jsonBody']) ? json_decode($_POST['jsonBody'], true) : json_decode(file_get_contents("php://input"), true);
                $sanitizedData = $this->getSanitizedInputData($data ?? NULL, $_FILES['pictures'] ?? NULL);
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
                        $name = $this->uploadPicture($sanitizedData["pictures"], $i);
                        array_push($pictureNames, $name);
                    }
                }
                
                $returnedId = $this->gateway->add($sanitizedData, $pictureNames);

                http_response_code(201);
                $post = $this->gateway->getById($returnedId);
                echo json_encode($post);
                break;
            
            default:
                http_response_code(405);
                header("Allow: GET, POST");
                break;
        }
        
    }

    private function uploadPicture(array $file, int $index): string{

        $extension = pathinfo($file['name'][$index], PATHINFO_EXTENSION);

        $currentPath = $file['tmp_name'][$index];

        $newFileName = uniqid('img-') . '.' . $extension;

        $path = ROOT_PATH . DIRECTORY_SEPARATOR . 'public' . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'images' . DIRECTORY_SEPARATOR . 'users' . DIRECTORY_SEPARATOR . 'posts' . DIRECTORY_SEPARATOR;        
        
        $newPath = $path . $newFileName;

        move_uploaded_file($currentPath, $newPath);

        return $newFileName;
    }

    private function getSanitizedInputData(?array $data, ?array $images): array{

        $header = htmlspecialchars(trim($data['header'] ?? ""), ENT_NOQUOTES, 'UTF-8');
        $description = htmlspecialchars(trim($data['description'] ?? ""), ENT_NOQUOTES, 'UTF-8');
        $numberOfImages = empty($images['name'][0]) ? 0 : count($images['name']);

        if($numberOfImages > 0){
            
            $pictures = $images;
            
        }

        $sanitizedData = [];

        $sanitizedData['header'] = $header;
        $sanitizedData['description'] = $description;
        $sanitizedData['pictures'] = $pictures ?? NULL;
        $sanitizedData['numberOfImages'] = $numberOfImages;
        //we define the userId based on the corresponding COOKIES sent with the request
        $userDB = $this->userController->getUserByUUID();
        $sanitizedData['userId'] = $userDB['userId'];

        return $sanitizedData;
    }

    private function getValidationInputErrors(array $data): array{
        $errors = [];

        $header = $data['header'];
        $description = $data['description'];
        $numberOfImages = $data['numberOfImages'];
        $pictures = $data['pictures'];

        //header
        if(empty($header)){
            array_push($errors, "The Post's header is required");
        }
        else if(strlen($header) > 100){
            array_push($errors, "The Post's header: cannot have length greater than 100 characters");
        }

        //description
        if(empty($description)){
            array_push($errors, "The Post's description is required");
        }
        else if(strlen($description) > 1000){
            array_push($errors, "The Post's description: cannot have length greater than 1000 characters");
        }

        //pictures
        if(($numberOfImages > 0) && ($pictures !== NULL)){
            if($numberOfImages > 3){
                array_push($errors, "The Post's image(s): cannot be more than 3");
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
                        array_push($errors, "The Post's image(s) Must be in format: jpeg, jpg, png, gif, webp; Please correct pictures. Error found in picture number " . $i+1);
                    }
                    //validate file extension is allowed (optional)
                    else if(!in_array($fileExtension, $allowedExtensions)) {
                        array_push($errors, "The Post's image(s) Must be in format: jpeg, jpg, png, gif, webp; Please correct pictures. Error found in picture number " . $i+1);
                    }
                    //validate a max file size
                    else if($pictures['size'][$i] > $max_file_size){
                        array_push($errors, "The Post's image(s) size cannot be more than 2MB; Please correct pictures. Error found in picture number " . $i+1);
                    }
                }
            }
        }
        
        return $errors;
    }
}