<?php

class ErrorHandler{

    public static function handleException(Throwable $e): void{
        http_response_code(500);
        
        echo json_encode([
            "errors" => ["Internal Server Error"],
            "file" => $e->getFile(),
            "line" => $e->getLine(),
            "message" => $e->getMessage()
        ]);
    }

    public static function handleError(int $errno, string $errstr, string $errfile, int $errline): bool{
        throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
    }

}