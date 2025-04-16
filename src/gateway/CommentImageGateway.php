<?php

class CommentImageGateway{

    private PDO $dbCon;

    public function __construct(DbConnection $dbConnection){
        $this->dbCon = $dbConnection->connectDB();
    }

    public function getByCommentIdAndIndex(string $commentId, string $index): array | false{
        $sql = "SELECT
            commentImageId, name,
            publishDatetime, userId,
            commentId
        FROM commentImages
        WHERE (commentId=:commentId) AND (state=:state)
        LIMIT :offset, :rows_count";

        $stmt = $this->dbCon->prepare($sql);

        $stmt->bindValue(":commentId", $commentId, PDO::PARAM_INT);
        $stmt->bindValue(":state", 1, PDO::PARAM_INT);
        $stmt->bindValue(":offset", $index, PDO::PARAM_INT);
        $stmt->bindValue(":rows_count", 1, PDO::PARAM_INT);

        $stmt->execute();

        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        return $data;
    }

    
}