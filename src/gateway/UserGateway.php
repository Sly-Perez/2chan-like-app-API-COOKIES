<?php

class UserGateway{

    private PDO $dbCon;

    public function __construct(DbConnection $dbConnection){
        $this->dbCon = $dbConnection->connectDB();
    }

    public function getByEmail(string $email): array | false{
        $sql = "SELECT
                    * 
                FROM users 
                WHERE (email=:email) AND (state=:state)";

        $stmt = $this->dbCon->prepare($sql);

        $stmt->bindValue(":email", $email, PDO::PARAM_STR);
        $stmt->bindValue(":state", 1, PDO::PARAM_INT);

        $stmt->execute();

        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        return $data;
    }
    
    //it can return an array (if it exists) or false (if it does not)
    public function getById(string $id, bool $email_will_display = false): array | false{
        $sql =  $email_will_display 
                ? "SELECT
                    userId, username, email,
                    picture, joinedAt,
                    amountOfPosts, hierarchyLevelId 
                FROM users 
                WHERE (userId=:userId) AND (state=:state)"
                : "SELECT
                    userId, username,
                    picture, joinedAt,
                    amountOfPosts, hierarchyLevelId 
                FROM users 
                WHERE (userId=:userId) AND (state=:state)";

        $stmt = $this->dbCon->prepare($sql);

        $stmt->bindValue(":userId", $id, PDO::PARAM_INT);
        $stmt->bindValue(":state", 1, PDO::PARAM_INT);

        $stmt->execute();

        $data = $stmt->fetch(PDO::FETCH_ASSOC);

        return $data;
    }

    public function add(array $data, bool $pictureIsUploaded): int{
        try {
            $this->dbCon->beginTransaction();
            //if the user uploaded a picture, the System will store the picture name in the "picture" field in the users table in the database
            //otherwise, the System will not store any name, leaving the name by default
            $sql = $pictureIsUploaded 
                    ? "INSERT INTO 
                    users(username, email, password, picture)
                    VALUES(:username, :email, :password, :picture)"
                    : "INSERT INTO
                    users(username, email, password)
                    VALUES(:username, :email, :password)";

            $stmt = $this->dbCon->prepare($sql);
            
            $stmt->bindValue(":username", $data["username"], PDO::PARAM_STR);
            $stmt->bindValue(":email", $data["email"], PDO::PARAM_STR);
            $stmt->bindValue(":password", password_hash($data["password"], PASSWORD_DEFAULT), PDO::PARAM_STR);
            
            if($pictureIsUploaded){
                $stmt->bindValue(":picture", $data['picture'], PDO::PARAM_STR);
            }

            $stmt->execute();

            $returnedId = $this->dbCon->lastInsertId(); 
        
            $this->dbCon->commit();

            return $returnedId;

        } catch (PDOException $e) {
            $this->dbCon->rollBack();
            throw $e;
        }
        
    }

    
    public function update(array $old, array $new): void{
        
        try {
            $this->dbCon->beginTransaction();
            
            $sql = "UPDATE users
                    SET username=:username, 
                        email=:email, 
                        password=:password, 
                        picture=:picture
                    WHERE userId=:userId";

            $stmt = $this->dbCon->prepare($sql);

            $stmt->bindValue(":username", $new["username"] ?? $old["username"], PDO::PARAM_STR);
            $stmt->bindValue(":email", $new["email"] ?? $old["email"], PDO::PARAM_STR);
            //we don't want to re-hash an already hashed password
            $stmt->bindValue(":password", ($new["password"] !== NULL) ? password_hash($new["password"], PASSWORD_DEFAULT) : $old["password"], PDO::PARAM_STR);
            $stmt->bindValue(":picture", $new["picture"] ?? $old["picture"], PDO::PARAM_STR);
            $stmt->bindValue(":userId", $old["userId"], PDO::PARAM_INT);

            $stmt->execute();

            $this->dbCon->commit();
        } catch (PDOException $e) {
            $this->dbCon->rollBack();
            throw $e;
        }
    }
    

    public function deleteById(string $id): void{
        
        try {
            $sql =  "CALL usp_deleteUserById(:userId)";

            $stmt = $this->dbCon->prepare($sql);

            $stmt->bindValue(":userId", $id, PDO::PARAM_INT);

            $stmt->execute();

        } catch (PDOException $e) {
            throw $e;
        }
    }
    
}