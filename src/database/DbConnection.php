<?php

class DbConnection{
    private $db_server = 'localhost';
    private $db_name = 'weekieMochi_ws_cookies';
    private $user = 'root';
    private $password = 'root';

    
    public function connectDB(): PDO{
        $dbCon = new PDO("mysql:host=$this->db_server;dbname=$this->db_name", $this->user, $this->password);
        return $dbCon;
    } 
}