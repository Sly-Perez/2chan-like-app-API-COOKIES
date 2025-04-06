<?php

class PostImageGateway{

    private PDO $dbCon;

    public function __construct(DbConnection $dbConnection){
        $this->dbCon = $dbConnection->connectDB();
    }

    public function getByPostIdAndIndex(string $id, string $index): array | false{
        try {
            $sql = "SELECT
                postImageId, name,
                publishDatetime, userId,
                postId
            FROM postImages
            WHERE (postId=:postId) AND (state=:state)
            LIMIT :offset, :rows_count";
    
            $stmt = $this->dbCon->prepare($sql);
    
            $stmt->bindValue(":postId", $id, PDO::PARAM_INT);
            $stmt->bindValue(":state", 1, PDO::PARAM_INT);
            $stmt->bindValue(":offset", $index, PDO::PARAM_INT);
            $stmt->bindValue(":rows_count", 1, PDO::PARAM_INT);
    
            $stmt->execute();
    
            $data = $stmt->fetch(PDO::FETCH_ASSOC);
    
            return $data;
        } catch (PDOException $e) {
            throw $e;
        }
    }

    
}