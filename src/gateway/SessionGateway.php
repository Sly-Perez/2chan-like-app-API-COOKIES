<?php

class SessionGateway{

    private PDO $dbCon;

    public function __construct(DbConnection $dbConnection){
        $this->dbCon = $dbConnection->connectDB();
    }
    
    //it can return an array (if it exists) or false (if it does not)
    public function getByUUID(string $uuid): array | false{
        $sql =  "SELECT
                    userId, uuid,
                    expiresAt
                FROM sessions
                WHERE (uuid=:uuid) AND (state=:state) AND (expiresAt > NOW())";

        $stmt = $this->dbCon->prepare($sql);

        $stmt->bindValue(":uuid", $uuid, PDO::PARAM_INT);
        $stmt->bindValue(":state", 1, PDO::PARAM_INT);

        $stmt->execute();

        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        return $data;
    }

    public function add(string $userId, string $uuid): void{
        try {
            $this->dbCon->beginTransaction();
            
            $sql = "INSERT INTO
                    sessions(userId, uuid, expiresAt)
                    VALUES(:userId, :uuid, NOW() + INTERVAL 2 HOUR)";

            $stmt = $this->dbCon->prepare($sql);
            
            $stmt->bindValue(":userId", $userId, PDO::PARAM_STR);
            $stmt->bindValue(":uuid", $uuid, PDO::PARAM_STR);

            $stmt->execute();
        
            $this->dbCon->commit();

        } catch (PDOException $e) {
            $this->dbCon->rollBack();
            throw $e;
        }
        
    }

    public function deleteByUUIDAndUserId(string $uuid, string $userId){
        try{
            $this->dbCon->beginTransaction();

            $sql = "UPDATE sessions
                    SET state=:state
                    WHERE uuid=:uuid AND userId=:userId";

            $stmt = $this->dbCon->prepare($sql);

            $stmt->bindValue(":state", 0, PDO::PARAM_INT);
            $stmt->bindValue(":uuid", $uuid, PDO::PARAM_STR);
            $stmt->bindValue(":userId", $userId, PDO::PARAM_STR);

            $stmt->execute();

            $this->dbCon->commit();
        } catch (PDOException $e){
            $this->dbCon->rollBack();
            throw $e;
        }
        
    }
    
}