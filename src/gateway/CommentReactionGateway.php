<?php

class CommentReactionGateway{

    private PDO $dbCon;

    public function __construct(DbConnection $dbConnection){
        $this->dbCon = $dbConnection->connectDB();
    }

    // this called stored procedure will take care of checking whether a reaction exists already
    // and, based on that, do the corresponding insertion or update
    public function addOrUpdateCommentReaction(array $data): array{
        try {
            $sql = "CALL usp_addOrUpdateCommentReaction(:commentId, :userId, :reactionName, :reactionValue)";
    
            $stmt = $this->dbCon->prepare($sql);
    
            $stmt->bindValue(":commentId", $data["commentId"], PDO::PARAM_INT);
            $stmt->bindValue(":userId", $data["userId"], PDO::PARAM_INT);
            $stmt->bindValue(":reactionName", $data["reactionName"], PDO::PARAM_STR);
            $stmt->bindValue(":reactionValue", $data["reactionValue"], PDO::PARAM_INT);
    
            $stmt->execute();
    
            $data = $stmt->fetch(PDO::FETCH_ASSOC);
    
            return $data;
        } catch (PDOException $e) {
            throw $e;
        }
    }

    public function getByCommentIdAndUserId(string $commentId, string $userId): array | false{
        try {
            $sql = "SELECT 
                        commentId, userId,
                        isLike, isDislike
                    FROM commentReactions
                    WHERE (commentId=:commentId AND userId=:userId) AND (state=:state)";
    
            $stmt = $this->dbCon->prepare($sql);
    
            $stmt->bindValue(":commentId", $commentId, PDO::PARAM_INT);
            $stmt->bindValue(":userId", $userId, PDO::PARAM_INT);
            $stmt->bindValue(":state", 1, PDO::PARAM_INT);
    
            $stmt->execute();
    
            $data = $stmt->fetch(PDO::FETCH_ASSOC);
    
            return $data;
        } catch (PDOException $e) {
            throw $e;
        }
    }

}