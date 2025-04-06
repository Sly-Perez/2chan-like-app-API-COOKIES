<?php

class CommentGateway{

    private PDO $dbCon;

    public function __construct(DbConnection $dbConnection){
        $this->dbCon = $dbConnection->connectDB();
    }

    public function getAllMainByPostId(string $id): array{
        $sql = "SELECT 
                    commentId, description, publishDatetime,
                    likesQuantity, dislikesQuantity, 
                    repliesQuantity, numberOfImages,
                    userId, postId, responseTo
                FROM comments
                WHERE (state=:state) AND (postId=:postId)
                        AND (responseTo IS NULL)";
        
        $stmt = $this->dbCon->prepare($sql);

        $stmt->bindValue(":state", 1, PDO::PARAM_INT);
        $stmt->bindValue(":postId", $id, PDO::PARAM_INT);

        $stmt->execute();

        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return $data;
    }

    public function getAllRepliesByCommentId(string $id): array{
        $sql = "SELECT 
                    commentId, description, publishDatetime,
                    likesQuantity, dislikesQuantity, 
                    repliesQuantity, numberOfImages,
                    userId, postId, responseTo
                FROM comments
                WHERE (state=:state) AND (responseTo=:responseTo)";
        
        $stmt = $this->dbCon->prepare($sql);

        $stmt->bindValue(":state", 1, PDO::PARAM_INT);
        $stmt->bindValue(":responseTo", $id, PDO::PARAM_INT);

        $stmt->execute();

        $data = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return $data;
    }

    public function getById(string $id): array | false{
        $sql = "SELECT 
                    commentId, description, publishDatetime,
                    likesQuantity, dislikesQuantity, 
                    repliesQuantity, numberOfImages,
                    userId, postId, responseTo
                FROM comments
                WHERE (state=:state) AND (commentId=:commentId)";
        
        $stmt = $this->dbCon->prepare($sql);

        $stmt->bindValue(":state", 1, PDO::PARAM_INT);
        $stmt->bindValue(":commentId", $id, PDO::PARAM_INT);

        $stmt->execute();

        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        return $data;
    }

    public function getMainById(string $id): array | false{
        $sql = "SELECT 
                    commentId, description, publishDatetime,
                    likesQuantity, dislikesQuantity, 
                    repliesQuantity, numberOfImages,
                    userId, postId, responseTo
                FROM comments
                WHERE (state=:state) AND (commentId=:commentId)
                        AND (responseTo IS NULL)";
        
        $stmt = $this->dbCon->prepare($sql);

        $stmt->bindValue(":state", 1, PDO::PARAM_INT);
        $stmt->bindValue(":commentId", $id, PDO::PARAM_INT);

        $stmt->execute();

        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        return $data;
    }

    public function getReplyById(string $id): array | false{
        $sql = "SELECT 
                    commentId, description, publishDatetime,
                    likesQuantity, dislikesQuantity, 
                    repliesQuantity, numberOfImages,
                    userId, postId, responseTo
                FROM comments
                WHERE (state=:state) AND (commentId=:commentId)
                        AND (responseTo IS NOT NULL)";
        
        $stmt = $this->dbCon->prepare($sql);

        $stmt->bindValue(":state", 1, PDO::PARAM_INT);
        $stmt->bindValue(":commentId", $id, PDO::PARAM_INT);

        $stmt->execute();

        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        return $data;
    }

    public function add(array $data, array $pictureNames): int | string{
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
                    usp_addComment(:description, :numberOfImages, :userId, :postId, :responseTo, :pictureNames)";

            $stmt = $this->dbCon->prepare($sql);
            
            $stmt->bindValue(":description", $data["description"], PDO::PARAM_STR);
            $stmt->bindValue(":numberOfImages", $data["numberOfImages"], PDO::PARAM_INT);
            $stmt->bindValue(":userId", $data["userId"], PDO::PARAM_INT);
            $stmt->bindValue(":postId", $data["postId"], PDO::PARAM_INT);
            if(isset($data["responseTo"])){
                $stmt->bindValue(":responseTo", $data["responseTo"], PDO::PARAM_INT);
            }
            else{
                $stmt->bindValue(":responseTo", NULL, PDO::PARAM_NULL);
            }
            $stmt->bindValue(":pictureNames", $pictureNames, PDO::PARAM_STR);

            $stmt->execute();
            
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            $returnedId = $result["newCommentId"];

            return $returnedId;

        } catch (PDOException $e) {
            throw $e;
        }
        
    }

    public function deleteById(string $id, ?string $responseTo): void{
        try {

            $sql = "CALL 
                    usp_deleteCommentById(:commentId, :responseTo)";

            $stmt = $this->dbCon->prepare($sql);
            
            $stmt->bindValue(":commentId", $id, PDO::PARAM_INT);
            $stmt->bindValue(":responseTo", $responseTo, PDO::PARAM_INT);

            $stmt->execute();

        } catch (PDOException $e) {
            throw $e;
        }
    }
}