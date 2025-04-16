<?php

class PostGateway{

    private PDO $dbCon;

    public function __construct(DbConnection $dbConnection){
        $this->dbCon = $dbConnection->connectDB();
    }

    public function getAll(): array{
        $sql = "CALL usp_getAllPosts()";
        
        $stmt = $this->dbCon->prepare($sql);

        $stmt->execute();

        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return $data;
    }

    public function getAllNewest(): array{
        $sql = "CALL usp_getNewestPosts()";
        
        $stmt = $this->dbCon->prepare($sql);

        $stmt->execute();

        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return $data;
    }

    public function getAllPopular(): array{
        $sql = "CALL usp_getPopularPosts()";
        
        $stmt = $this->dbCon->prepare($sql);

        $stmt->execute();

        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return $data;
    }

    public function getAllInteractedByUserId(string $userId): array{
        $sql = "CALL usp_getAllInteractedPostsByUserId(:userId)";
        
        $stmt = $this->dbCon->prepare($sql);

        $stmt->bindValue(":userId", $userId, PDO::PARAM_INT);

        $stmt->execute();

        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return $data;
    }

    public function getAllByUserId(string $userId): array{
        $sql = "CALL usp_getAllPostsByUserId(:userId)";
        
        $stmt = $this->dbCon->prepare($sql);

        $stmt->bindValue(":userId", $userId, PDO::PARAM_INT);

        $stmt->execute();

        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return $data;
    }

    public function getById(string $id): array | false{
        $sql = "SELECT
                    postId, header,
                    description, publishDatetime,
                    commentsQuantity, numberOfImages,
                    userId 
                FROM posts 
                WHERE (postId=:postId) AND (state=:state)";

        $stmt = $this->dbCon->prepare($sql);

        $stmt->bindValue(":postId", $id, PDO::PARAM_INT);
        $stmt->bindValue(":state", 1, PDO::PARAM_INT);

        $stmt->execute();

        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        return $data;
    }

    public function add(array $data, array $pictureNames): int{
        try {

            //if a picture or more were uploaded, we will convert them into a string with a comma separator for the stored procedure
            if($data["numberOfImages"] > 0){
                $pictureNames = implode(',', $pictureNames);
            }
            //otherwise, we will pass in an empty string; This is handled in the stored procedure database
            else{
                $pictureNames = "";
            }

            $sql = "CALL 
                    usp_addPost(:header, :description, :numberOfImages, :userId, :pictureNames)";

            $stmt = $this->dbCon->prepare($sql);
            
            $stmt->bindValue(":header", $data["header"], PDO::PARAM_STR);
            $stmt->bindValue(":description", $data["description"], PDO::PARAM_STR);
            $stmt->bindValue(":numberOfImages", $data["numberOfImages"], PDO::PARAM_INT);
            $stmt->bindValue(":userId", $data["userId"], PDO::PARAM_INT);
            $stmt->bindValue(":pictureNames", $pictureNames, PDO::PARAM_STR);
            
            $stmt->execute();
            
            $result = $stmt->fetch(PDO::FETCH_ASSOC);

            $returnedId = $result["newPostId"];

            return $returnedId;

        } catch (PDOException $e) {
            throw $e;
        }
        
    }

    public function deleteById(string $id): void{
        
        try {
            
            $sql = "CALL usp_deletePostById(:postId)";

            $stmt = $this->dbCon->prepare($sql);

            $stmt->bindValue(":postId", $id, PDO::PARAM_INT);

            $stmt->execute();

        } catch (PDOException $e) {
            throw $e;
        }
    }
}